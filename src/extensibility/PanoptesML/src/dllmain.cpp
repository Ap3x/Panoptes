#include "PanoptesML.h"
#include <algorithm>
#include <cstring>
#include <iostream>
#include <mutex>
#include <stdexcept>

// The model is loaded on the first scan and kept for the container's lifetime: loading it is
// far slower than scoring a file. A model that fails to load is not retried until the container
// restarts
static std::once_flag g_ModelLoad;
static std::string g_ModelError; // why the model didn't load; set once, with g_Model

// Deliberately a plain pointer, not a static unique_ptr: a static's destructor runs during
// DLL_PROCESS_DETACH, and at process exit Windows has already ended ONNX Runtime's threads by
// then, so tearing down its session and thread pool there reads freed memory and crashes or
// hangs (ORT documents not destroying sessions during DLL unload). PanoUnbind frees it while the
// threads are alive; at process exit the memory is reclaimed with the process
static MlModel* g_Model = nullptr;

static MlModel* GetModel()
{
	std::call_once(g_ModelLoad, [] {
		// The model built into the DLL when there is one (encrypted, see model_seal.cpp), and
		// otherwise model.onnx from the DLL's folder
		std::wstring path = L"the embedded model"; // what failed, for the message below
		std::vector<uint8_t> embedded;
		try {
			bool isEmbedded = LoadEmbeddedModel(embedded);
			if (!isEmbedded) {
				path = ModuleDirectory() + PANO_ML_MODEL_FILE;
			}
			if (isEmbedded) {
				g_Model = new MlModel(embedded.data(), embedded.size(), "embedded model.onnx");
			}
			else {
				g_Model = new MlModel(path);
			}
		}
		catch (const std::exception& e) {
			g_ModelError = e.what();
			std::wcerr << L"PanoptesML: cannot load " << path << L": ";
			std::cerr << e.what() << std::endl;
		}
		if (!embedded.empty()) {
			SecureZeroMemory(embedded.data(), embedded.size());
		}
	});
	return g_Model;
}

static std::wstring Widen(const std::string& Text)
{
	int length = MultiByteToWideChar(CP_UTF8, 0, Text.c_str(), (int)Text.size(), NULL, 0);
	std::wstring out(length, L'\0');
	MultiByteToWideChar(CP_UTF8, 0, Text.c_str(), (int)Text.size(), out.data(), length);
	return out;
}

BOOL APIENTRY DllMain(HMODULE module, DWORD reason, LPVOID reserved)
{
	UNREFERENCED_PARAMETER(reserved);
	if (reason == DLL_PROCESS_ATTACH) {
		DisableThreadLibraryCalls(module);
	}
	return TRUE;
}

/// @brief Registers with the Panoptes Service: the extensibility type and the port of the
/// container this module runs in
/// @return The container port, or 0 if the service didn't accept it
extern "C" PANO_API int PanoBind(int ContainerPort)
{
	PanoptesServiceClient client;
	if (!client.Hello(ExtensibilityType::EXTENSIBILITY_TYPE_ML, ContainerPort)) {
		return 0;
	}
	return ContainerPort;
}

/// @brief Scores one file with the model and reports the result to the service. The file is
/// only read: its static features are computed from its bytes and headers.
///
/// A result is reported for every file, including one that couldn't be scored (Error says why),
/// so the service and a scanner waiting on it know the ML scan has finished.
/// @return True if the file was scored and the result reported
extern "C" PANO_API bool PanoEntry(PeScan* data)
{
	MlScanResult result;
	bool scored = false;
	// No exception may leave this extern "C" export: it would end the container
	try {
		MlModel* model = GetModel();
		if (model == nullptr) {
			result.Error = "cannot load the model: " + g_ModelError;
		}
		else {
			result.Model = model->Name();
			PeFeatures features = ExtractPeFeatures(Widen(data->PePath));
			result.IsPe = features.IsPe;
			if (!features.IsPe) {
				// The model is trained on PE files only (EMBER2024's Win32, Win64 and .NET
				// records); its score for anything else means nothing
				result.Error = "not a PE file; the model only scores PE files";
			}
			else {
				result.Score = model->Score(features.Values);
				result.Malicious = result.Score >= PANO_ML_THRESHOLD;
				scored = true;
			}
		}
	}
	catch (const std::exception& e) {
		// Ort::Exception derives from std::exception. A file deleted or locked before its scan,
		// or one over the size limit, is common
		result.Error = e.what();
		std::cerr << "PanoptesML scan of " << data->PePath << " failed: " << e.what() << std::endl;
	}

	try {
		PanoptesServiceClient client;
		return client.SendResults_ML(data->PePath, data->FileHash, result) && scored;
	}
	catch (const std::exception& e) {
		std::cerr << "PanoptesML: reporting " << data->PePath << " failed: " << e.what() << std::endl;
		return false;
	}
}

#pragma region Test interface

// tools/mlquery declares the same layout; no padding, so the size is the sum of the fields
static_assert(sizeof(PanoMlTestResult) == 7 * 4 + FEATURE_COUNT * 4 + 128 + 512,
	"PanoMlTestResult changed: update tools/mlquery/main.go");

static void CopyText(char* Destination, size_t Size, const std::string& Text)
{
	strncpy_s(Destination, Size, Text.c_str(), _TRUNCATE);
}

extern "C" PANO_API int PanoMlScoreFile(const wchar_t* Path, PanoMlTestResult* Result)
{
	// A caller built against another layout gets nothing written, rather than a struct overrun
	if (Result == nullptr || Result->StructSize != sizeof(PanoMlTestResult)) {
		return PANO_ML_TEST_FAILED;
	}
	ZeroMemory(Result, sizeof(*Result));
	Result->StructSize = sizeof(PanoMlTestResult);
	Result->FeatureVersion = PANO_ML_FEATURE_VERSION;
	Result->FeatureCount = FEATURE_COUNT;
	Result->Threshold = PANO_ML_THRESHOLD;
	if (Path == nullptr) {
		CopyText(Result->Error, sizeof(Result->Error), "no path");
		return PANO_ML_TEST_FAILED;
	}

	// No exception may leave an extern "C" export
	try {
		PeFeatures features = ExtractPeFeatures(std::wstring(Path));
		std::copy(features.Values.begin(), features.Values.end(), Result->Features);
		Result->IsPe = features.IsPe ? 1 : 0;

		MlModel* model = GetModel();
		if (model == nullptr) {
			CopyText(Result->Error, sizeof(Result->Error), "cannot load the model: " + g_ModelError);
			return PANO_ML_TEST_NO_MODEL;
		}
		// The raw score is kept for testing, but as in PanoEntry a file that isn't a PE gets no
		// verdict: the model is trained on PE files only
		Result->Score = model->Score(features.Values);
		Result->Malicious = features.IsPe && Result->Score >= PANO_ML_THRESHOLD ? 1 : 0;
		CopyText(Result->Model, sizeof(Result->Model), model->Name());
		return PANO_ML_TEST_OK;
	}
	catch (const std::exception& e) {
		CopyText(Result->Error, sizeof(Result->Error), e.what());
		return PANO_ML_TEST_FAILED;
	}
}

extern "C" PANO_API int PanoMlFeatureName(int Index, char* Buffer, int BufferSize)
{
	const char* name = Index >= 0 ? FeatureName((size_t)Index) : nullptr;
	if (name == nullptr || Buffer == nullptr) {
		return -1;
	}
	size_t length = strlen(name);
	if (BufferSize <= 0 || length >= (size_t)BufferSize) {
		return -1;
	}
	memcpy(Buffer, name, length + 1);
	return (int)length;
}

#pragma endregion

/// @brief Called once when the container shuts down
extern "C" PANO_API bool PanoUnbind()
{
	// No scan runs after this: the container calls it once, when it shuts down
	delete g_Model;
	g_Model = nullptr;
	return true;
}
