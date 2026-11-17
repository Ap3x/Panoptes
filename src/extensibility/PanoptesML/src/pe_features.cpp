#include "PanoptesML.h"
#include <algorithm>
#include <array>
#include <cmath>
#include <cstdio>
#include <cstring>
#include <stdexcept>

// The README and every trained model depend on this; changing it means a new feature version
static_assert(FEATURE_COUNT == 278, "update README.md and PANO_ML_FEATURE_VERSION");

// Names of the features after the byte histogram, in PanoMlFeature order
static constexpr std::array kNamedFeatures = {
	"entropy", "log_size", "is_pe", "is_64bit", "is_dll", "subsystem_gui", "section_count",
	"section_entropy_max", "section_entropy_min", "section_entropy_mean",
	"writable_executable_sections", "entry_outside_executable", "imported_dlls",
	"imported_functions", "has_signature", "has_tls", "has_debug", "has_relocations",
	"has_resources", "overlay_ratio", "image_to_file_ratio", "zero_timestamp",
};
static_assert(kNamedFeatures.size() == FEATURE_COUNT - FEATURE_ENTROPY, "name every feature in PanoMlFeature");

const char* FeatureName(size_t Index)
{
	// byte_00 .. byte_ff for the histogram, built once
	static const std::vector<std::string> names = [] {
		std::vector<std::string> all;
		all.reserve(FEATURE_COUNT);
		char name[16];
		for (int value = 0; value < 256; value++) {
			snprintf(name, sizeof(name), "byte_%02x", value);
			all.emplace_back(name);
		}
		all.insert(all.end(), kNamedFeatures.begin(), kNamedFeatures.end());
		return all;
	}();
	return Index < names.size() ? names[Index].c_str() : nullptr;
}

// The file is untrusted: every header field is checked against the file's size before it is
// used, and nothing in it is followed outside the file. The PE is never loaded or run.

#pragma region Helpers

/// @brief Shannon entropy in bits per byte (0..8)
static float Entropy(const uint8_t* Data, size_t Size)
{
	if (Size == 0) {
		return 0;
	}
	size_t counts[256] = {};
	for (size_t i = 0; i < Size; i++) {
		counts[Data[i]]++;
	}
	double entropy = 0;
	for (size_t count : counts) {
		if (count != 0) {
			double p = (double)count / (double)Size;
			entropy -= p * std::log2(p);
		}
	}
	return (float)entropy;
}

/// @brief A read-only view of the file that refuses reads outside it
class FileView {
public:
	FileView(const uint8_t* Data, size_t Size) : m_data(Data), m_size(Size) {}

	size_t Size() const { return m_size; }
	const uint8_t* Data() const { return m_data; }

	bool Contains(uint64_t Offset, uint64_t Length) const
	{
		return Offset <= m_size && Length <= m_size - Offset;
	}

	/// @brief Copies a T from Offset. False when it doesn't fit in the file
	template <typename T>
	bool Read(uint64_t Offset, T* Out) const
	{
		if (!Contains(Offset, sizeof(T))) {
			return false;
		}
		memcpy(Out, m_data + Offset, sizeof(T)); // the file has no alignment guarantees
		return true;
	}

private:
	const uint8_t* m_data;
	size_t m_size;
};

/// @brief The parts of a PE the features need
struct PeLayout {
	bool Is64Bit = false;
	IMAGE_FILE_HEADER FileHeader{};
	DWORD AddressOfEntryPoint = 0;
	DWORD SizeOfImage = 0;
	WORD Subsystem = 0;
	DWORD DataDirectoryCount = 0;
	IMAGE_DATA_DIRECTORY DataDirectories[IMAGE_NUMBEROF_DIRECTORY_ENTRIES]{};
	std::vector<IMAGE_SECTION_HEADER> Sections;
};

/// @brief Parses the DOS, NT and section headers. False if the file is not a PE
static bool ParsePe(const FileView& File, PeLayout* Pe)
{
	IMAGE_DOS_HEADER dos;
	if (!File.Read(0, &dos) || dos.e_magic != IMAGE_DOS_SIGNATURE || dos.e_lfanew < 0) {
		return false;
	}
	uint64_t ntOffset = (uint64_t)dos.e_lfanew;
	DWORD signature;
	if (!File.Read(ntOffset, &signature) || signature != IMAGE_NT_SIGNATURE ||
		!File.Read(ntOffset + sizeof(DWORD), &Pe->FileHeader)) {
		return false;
	}

	uint64_t optionalOffset = ntOffset + sizeof(DWORD) + sizeof(IMAGE_FILE_HEADER);
	WORD magic;
	if (!File.Read(optionalOffset, &magic)) {
		return false;
	}
	const IMAGE_DATA_DIRECTORY* directories = nullptr;
	DWORD directoryCount = 0;
	IMAGE_OPTIONAL_HEADER64 optional64;
	IMAGE_OPTIONAL_HEADER32 optional32;
	if (magic == IMAGE_NT_OPTIONAL_HDR64_MAGIC && File.Read(optionalOffset, &optional64)) {
		Pe->Is64Bit = true;
		Pe->AddressOfEntryPoint = optional64.AddressOfEntryPoint;
		Pe->SizeOfImage = optional64.SizeOfImage;
		Pe->Subsystem = optional64.Subsystem;
		directories = optional64.DataDirectory;
		directoryCount = optional64.NumberOfRvaAndSizes;
	}
	else if (magic == IMAGE_NT_OPTIONAL_HDR32_MAGIC && File.Read(optionalOffset, &optional32)) {
		Pe->AddressOfEntryPoint = optional32.AddressOfEntryPoint;
		Pe->SizeOfImage = optional32.SizeOfImage;
		Pe->Subsystem = optional32.Subsystem;
		directories = optional32.DataDirectory;
		directoryCount = optional32.NumberOfRvaAndSizes;
	}
	else {
		return false;
	}
	Pe->DataDirectoryCount = std::min<DWORD>(directoryCount, IMAGE_NUMBEROF_DIRECTORY_ENTRIES);
	memcpy(Pe->DataDirectories, directories, Pe->DataDirectoryCount * sizeof(IMAGE_DATA_DIRECTORY));

	// The section table follows the optional header at the size the file header gives, which
	// a crafted file can set to anything
	uint64_t sectionOffset = optionalOffset + Pe->FileHeader.SizeOfOptionalHeader;
	for (WORD i = 0; i < Pe->FileHeader.NumberOfSections; i++) {
		IMAGE_SECTION_HEADER section;
		if (!File.Read(sectionOffset + (uint64_t)i * sizeof(section), &section)) {
			break; // a truncated table: keep the sections that are there
		}
		Pe->Sections.push_back(section);
	}
	return true;
}

static const IMAGE_DATA_DIRECTORY* Directory(const PeLayout& Pe, DWORD Index)
{
	if (Index >= Pe.DataDirectoryCount || Pe.DataDirectories[Index].VirtualAddress == 0 ||
		Pe.DataDirectories[Index].Size == 0) {
		return nullptr;
	}
	return &Pe.DataDirectories[Index];
}

/// @brief The file offset of an RVA, through the section that maps it. False if no section does
static bool RvaToOffset(const PeLayout& Pe, const FileView& File, DWORD Rva, uint64_t* Offset)
{
	for (const auto& section : Pe.Sections) {
		DWORD size = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
		if (Rva >= section.VirtualAddress && Rva - section.VirtualAddress < size) {
			uint64_t delta = Rva - section.VirtualAddress;
			if (delta >= section.SizeOfRawData) {
				return false; // in the section's zero-filled tail, not in the file
			}
			*Offset = (uint64_t)section.PointerToRawData + delta;
			return File.Contains(*Offset, 1);
		}
	}
	return false;
}

/// @brief Counts the imported DLLs and functions. Stops at the first entry outside the file and
/// at fixed limits, so a crafted import table can't make it loop for long
static void CountImports(const PeLayout& Pe, const FileView& File, uint32_t* Dlls, uint32_t* Functions)
{
	const uint32_t maxDlls = 4096;
	const uint32_t maxFunctionsPerDll = 65536;
	*Dlls = 0;
	*Functions = 0;

	const IMAGE_DATA_DIRECTORY* imports = Directory(Pe, IMAGE_DIRECTORY_ENTRY_IMPORT);
	uint64_t descriptorOffset;
	if (imports == nullptr || !RvaToOffset(Pe, File, imports->VirtualAddress, &descriptorOffset)) {
		return;
	}

	for (uint32_t i = 0; i < maxDlls; i++) {
		IMAGE_IMPORT_DESCRIPTOR descriptor;
		if (!File.Read(descriptorOffset + (uint64_t)i * sizeof(descriptor), &descriptor) ||
			descriptor.Name == 0) {
			break;
		}
		(*Dlls)++;

		// The lookup table, or the address table when a linker left the lookup table out
		DWORD thunkRva = descriptor.OriginalFirstThunk != 0 ? descriptor.OriginalFirstThunk : descriptor.FirstThunk;
		uint64_t thunkOffset;
		if (!RvaToOffset(Pe, File, thunkRva, &thunkOffset)) {
			continue;
		}
		size_t thunkSize = Pe.Is64Bit ? sizeof(uint64_t) : sizeof(uint32_t);
		for (uint32_t j = 0; j < maxFunctionsPerDll; j++) {
			uint64_t thunk = 0;
			bool read = Pe.Is64Bit
				? File.Read(thunkOffset + (uint64_t)j * thunkSize, &thunk)
				: File.Read(thunkOffset + (uint64_t)j * thunkSize, (uint32_t*)&thunk);
			if (!read || thunk == 0) {
				break;
			}
			(*Functions)++;
		}
	}
}

#pragma endregion

PeFeatures ExtractPeFeatures(const uint8_t* Data, size_t Size)
{
	PeFeatures features;
	std::vector<float>& f = features.Values;
	f.assign(FEATURE_COUNT, 0.0f);
	FileView file(Data, Size);

	// Byte statistics: computed for every file, PE or not
	if (Size > 0) {
		size_t counts[256] = {};
		for (size_t i = 0; i < Size; i++) {
			counts[Data[i]]++;
		}
		for (size_t b = 0; b < 256; b++) {
			f[FEATURE_BYTE_HISTOGRAM + b] = (float)((double)counts[b] / (double)Size);
		}
	}
	f[FEATURE_ENTROPY] = Entropy(Data, Size) / 8.0f;
	f[FEATURE_LOG_SIZE] = (float)(std::log2((double)Size + 1) / 32.0);

	PeLayout pe;
	if (!ParsePe(file, &pe)) {
		return features;
	}
	features.IsPe = true;
	f[FEATURE_IS_PE] = 1;
	f[FEATURE_IS_64BIT] = pe.Is64Bit ? 1.0f : 0.0f;
	f[FEATURE_IS_DLL] = (pe.FileHeader.Characteristics & IMAGE_FILE_DLL) ? 1.0f : 0.0f;
	f[FEATURE_SUBSYSTEM_GUI] = pe.Subsystem == IMAGE_SUBSYSTEM_WINDOWS_GUI ? 1.0f : 0.0f;
	f[FEATURE_ZERO_TIMESTAMP] = pe.FileHeader.TimeDateStamp == 0 ? 1.0f : 0.0f;
	f[FEATURE_SECTION_COUNT] = std::min((float)pe.Sections.size() / 16.0f, 4.0f);

	// Sections: entropy of each one's raw data, W+X sections, where the entry point is, and
	// how much of the file lies past the last section (the overlay)
	float entropyMax = 0, entropyMin = 8, entropySum = 0;
	size_t withData = 0, writableExecutable = 0;
	bool entryInExecutable = false;
	uint64_t endOfSections = 0;
	for (const auto& section : pe.Sections) {
		DWORD flags = section.Characteristics;
		bool executable = (flags & IMAGE_SCN_MEM_EXECUTE) != 0;
		if (executable && (flags & IMAGE_SCN_MEM_WRITE)) {
			writableExecutable++;
		}
		DWORD virtualSize = std::max(section.Misc.VirtualSize, section.SizeOfRawData);
		if (executable && pe.AddressOfEntryPoint >= section.VirtualAddress &&
			pe.AddressOfEntryPoint - section.VirtualAddress < virtualSize) {
			entryInExecutable = true;
		}

		uint64_t start = section.PointerToRawData;
		uint64_t length = section.SizeOfRawData;
		if (length == 0 || !file.Contains(start, 1)) {
			continue;
		}
		length = std::min<uint64_t>(length, Size - start);
		endOfSections = std::max(endOfSections, start + length);
		float entropy = Entropy(Data + start, (size_t)length);
		entropyMax = std::max(entropyMax, entropy);
		entropyMin = std::min(entropyMin, entropy);
		entropySum += entropy;
		withData++;
	}
	if (withData > 0) {
		f[FEATURE_SECTION_ENTROPY_MAX] = entropyMax / 8.0f;
		f[FEATURE_SECTION_ENTROPY_MIN] = entropyMin / 8.0f;
		f[FEATURE_SECTION_ENTROPY_MEAN] = entropySum / (float)withData / 8.0f;
	}
	if (!pe.Sections.empty()) {
		f[FEATURE_WRITABLE_EXECUTABLE_SECTIONS] = (float)writableExecutable / (float)pe.Sections.size();
	}
	// A DLL without an entry point has AddressOfEntryPoint 0, which is not suspicious
	f[FEATURE_ENTRY_OUTSIDE_EXECUTABLE] = (pe.AddressOfEntryPoint != 0 && !entryInExecutable) ? 1.0f : 0.0f;
	if (Size > 0 && endOfSections < Size) {
		f[FEATURE_OVERLAY_RATIO] = (float)((double)(Size - endOfSections) / (double)Size);
	}
	if (Size > 0) {
		f[FEATURE_IMAGE_TO_FILE_RATIO] = (float)(std::min((double)pe.SizeOfImage / (double)Size, 16.0) / 16.0);
	}

	uint32_t dlls = 0, functions = 0;
	CountImports(pe, file, &dlls, &functions);
	f[FEATURE_IMPORTED_DLLS] = (float)(std::log2((double)dlls + 1) / 8.0);
	f[FEATURE_IMPORTED_FUNCTIONS] = (float)(std::log2((double)functions + 1) / 12.0);

	f[FEATURE_HAS_SIGNATURE] = Directory(pe, IMAGE_DIRECTORY_ENTRY_SECURITY) ? 1.0f : 0.0f;
	f[FEATURE_HAS_TLS] = Directory(pe, IMAGE_DIRECTORY_ENTRY_TLS) ? 1.0f : 0.0f;
	f[FEATURE_HAS_DEBUG] = Directory(pe, IMAGE_DIRECTORY_ENTRY_DEBUG) ? 1.0f : 0.0f;
	f[FEATURE_HAS_RELOCATIONS] = Directory(pe, IMAGE_DIRECTORY_ENTRY_BASERELOC) ? 1.0f : 0.0f;
	f[FEATURE_HAS_RESOURCES] = Directory(pe, IMAGE_DIRECTORY_ENTRY_RESOURCE) ? 1.0f : 0.0f;
	return features;
}

PeFeatures ExtractPeFeatures(const std::wstring& Path)
{
	// Shared for read and write, so a file still open in the program that wrote it can be read
	HANDLE file = CreateFileW(Path.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, FILE_ATTRIBUTE_NORMAL | FILE_FLAG_SEQUENTIAL_SCAN, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		throw std::runtime_error("cannot open the file (error " + std::to_string(GetLastError()) + ")");
	}

	LARGE_INTEGER size{};
	if (!GetFileSizeEx(file, &size)) {
		CloseHandle(file);
		throw std::runtime_error("cannot get the file's size");
	}
	if ((ULONGLONG)size.QuadPart > PANO_ML_MAX_FILE_SIZE) {
		CloseHandle(file);
		throw std::runtime_error("the file is larger than " + std::to_string(PANO_ML_MAX_FILE_SIZE) + " bytes");
	}

	std::vector<uint8_t> data((size_t)size.QuadPart);
	size_t read = 0;
	while (read < data.size()) {
		DWORD chunk = (DWORD)std::min<size_t>(data.size() - read, 1 << 24);
		DWORD got = 0;
		if (!ReadFile(file, data.data() + read, chunk, &got, NULL) || got == 0) {
			break; // the file shrank; score what was read
		}
		read += got;
	}
	CloseHandle(file);
	data.resize(read);
	return ExtractPeFeatures(data.data(), data.size());
}
