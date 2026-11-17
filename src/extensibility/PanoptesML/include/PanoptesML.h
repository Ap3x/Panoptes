#pragma once
#include "ExtensibilityCore.h"
#include <cstdint>
#include <memory>
#include <string>
#include <vector>

#define PANO_ML_VERSION "1.0.0"

/// @brief The model file, loaded from the folder PanoptesML.dll is in (ext\)
#define PANO_ML_MODEL_FILE L"model.onnx"

/// @brief Score at or above which a file is reported as malicious
#define PANO_ML_THRESHOLD 0.5f

/// @brief Files larger than this are not scored (the features are computed over the whole file)
#define PANO_ML_MAX_FILE_SIZE (256ULL * 1024 * 1024)

#pragma region Features

/// @brief Version of the feature layout below. A model is trained for one layout; change this
/// whenever a feature is added, removed or reordered, and retrain
#define PANO_ML_FEATURE_VERSION 1

/// @brief The static features of one file, in the order the model takes them. See README.md for
/// what each index means. Every value is a float, most scaled to about 0..1
enum PanoMlFeature : size_t {
	FEATURE_BYTE_HISTOGRAM = 0,          // 256 values: how often each byte value occurs, / file size
	FEATURE_ENTROPY = 256,               // Shannon entropy of the whole file, / 8
	FEATURE_LOG_SIZE,                    // log2(file size + 1) / 32
	FEATURE_IS_PE,                       // 1 if the file parsed as a PE
	FEATURE_IS_64BIT,                    // PE32+
	FEATURE_IS_DLL,                      // IMAGE_FILE_DLL
	FEATURE_SUBSYSTEM_GUI,               // IMAGE_SUBSYSTEM_WINDOWS_GUI
	FEATURE_SECTION_COUNT,               // number of sections / 16
	FEATURE_SECTION_ENTROPY_MAX,         // highest section entropy / 8
	FEATURE_SECTION_ENTROPY_MIN,         // lowest section entropy / 8
	FEATURE_SECTION_ENTROPY_MEAN,        // mean section entropy / 8
	FEATURE_WRITABLE_EXECUTABLE_SECTIONS,// sections both writable and executable / section count
	FEATURE_ENTRY_OUTSIDE_EXECUTABLE,    // 1 if the entry point is not in an executable section
	FEATURE_IMPORTED_DLLS,               // log2(imported DLLs + 1) / 8
	FEATURE_IMPORTED_FUNCTIONS,          // log2(imported functions + 1) / 12
	FEATURE_HAS_SIGNATURE,               // security directory present (Authenticode, not verified)
	FEATURE_HAS_TLS,                     // TLS directory present (TLS callbacks run before the entry point)
	FEATURE_HAS_DEBUG,                   // debug directory present
	FEATURE_HAS_RELOCATIONS,             // base relocations present
	FEATURE_HAS_RESOURCES,               // resource directory present
	FEATURE_OVERLAY_RATIO,               // bytes after the last section / file size
	FEATURE_IMAGE_TO_FILE_RATIO,         // SizeOfImage / file size, capped at 16, / 16
	FEATURE_ZERO_TIMESTAMP,              // TimeDateStamp is 0
	FEATURE_COUNT
};

struct PeFeatures {
	std::vector<float> Values; // FEATURE_COUNT values
	bool IsPe = false;
};

/// @brief Reads a file and computes its static features. The file is only read, never run or
/// loaded. Throws std::runtime_error when the file can't be read or is too large
PeFeatures ExtractPeFeatures(const std::wstring& Path);

/// @brief The same, from a file's bytes (used by ExtractPeFeatures and the tests)
PeFeatures ExtractPeFeatures(const uint8_t* Data, size_t Size);

#pragma endregion

#pragma region Model

/// @brief An ONNX model that scores a feature vector. The model must take one float tensor of
/// shape [1, FEATURE_COUNT] (or [N, FEATURE_COUNT]) and output a float tensor whose last value
/// is the malicious probability: [1, 1] or [1, 2] (benign, malicious). See README.md
class MlModel {
public:
	/// @brief Loads the model. Throws Ort::Exception or std::runtime_error when it can't be
	/// loaded or doesn't take FEATURE_COUNT features
	explicit MlModel(const std::wstring& ModelPath);
	/// @brief The same, from the model's bytes in memory. Name is what results report as the model
	MlModel(const void* Data, size_t Size, const std::string& Name);
	~MlModel();
	MlModel(const MlModel&) = delete;
	MlModel& operator=(const MlModel&) = delete;

	/// @brief Runs the model on one file's features. Returns the malicious probability
	float Score(const std::vector<float>& Features);

	const std::string& Name() const { return m_name; }

private:
	struct Impl; // keeps onnxruntime_cxx_api.h out of this header
	void Inspect(); // checks the loaded session's input and finds its score output
	std::unique_ptr<Impl> m_impl;
	std::string m_name;
};

/// @brief The model built into the DLL (an encrypted RCDATA resource, see tools/sealmodel),
/// decrypted into Model. Returns false when the DLL was built without one, so model.onnx is
/// loaded from its folder instead. Throws std::runtime_error when the embedded model can't be
/// decrypted (modified or corrupted)
bool LoadEmbeddedModel(std::vector<uint8_t>& Model);

/// @brief Name of the embedded model's resource (type RCDATA)
#define PANO_ML_MODEL_RESOURCE L"PANOML_MODEL"

#pragma endregion

/// @brief The folder this DLL was loaded from, with a trailing backslash
std::wstring ModuleDirectory();

/// @brief One file's result, as sent to the service
struct MlScanResult {
	float Score = 0;
	bool Malicious = false;
	bool IsPe = false;
	std::string Model;
	std::string Error; // why the file wasn't scored; empty when it was
};

#pragma region Test interface

// A plain C interface for test tools (tools/mlquery), separate from the container's PanoEntry:
// PeScan holds std::string, which only code built with the same compiler settings can pass, and
// PanoEntry sends its result to the service instead of returning it. These run the same feature
// extraction and model, but return the result and talk to nothing.

/// @brief One file's result for a test tool. Every field has a fixed size, so a caller in any
/// language can declare the same layout
struct PanoMlTestResult {
	uint32_t StructSize;     // set by the caller to sizeof(PanoMlTestResult); any other value is refused
	int32_t FeatureVersion;  // PANO_ML_FEATURE_VERSION
	int32_t FeatureCount;    // FEATURE_COUNT
	int32_t IsPe;            // 1 if the file parsed as a PE
	int32_t Malicious;       // 1 if Score >= Threshold
	float Score;             // the model's malicious probability, 0..1
	float Threshold;         // PANO_ML_THRESHOLD
	float Features[FEATURE_COUNT]; // the model's input, in PanoMlFeature order
	char Model[128];         // the model's name (UTF-8, null-terminated)
	char Error[512];         // why the call failed (UTF-8, null-terminated); empty on success
};

/// @brief PanoMlScoreFile results
#define PANO_ML_TEST_OK 0
#define PANO_ML_TEST_FAILED -1     // nothing usable: see Error (or StructSize was wrong)
#define PANO_ML_TEST_NO_MODEL -2   // the features were computed but the model couldn't be loaded: see Error

extern "C" {
	/// @brief Computes a file's features and scores them with the model (embedded, or model.onnx from the DLL's folder).
	/// The file is only read. Thread-safe
	/// @return PANO_ML_TEST_OK, PANO_ML_TEST_FAILED or PANO_ML_TEST_NO_MODEL
	PANO_API int PanoMlScoreFile(const wchar_t* Path, PanoMlTestResult* Result);

	/// @brief Copies the name of feature Index (e.g. "byte_4d", "section_entropy_max") into Buffer
	/// @return The name's length, or -1 if Index is out of range or Buffer too small
	PANO_API int PanoMlFeatureName(int Index, char* Buffer, int BufferSize);
}

/// @brief The name of feature Index, or nullptr when it is out of range
const char* FeatureName(size_t Index);

#pragma endregion

/// @brief The Panoptes Service client used to talk to the service over gRPC
class PanoptesServiceClient {
public:
	PanoptesServiceClient();
	bool Hello(ExtensibilityType ExtensibilityType, int ContainerPort);
	bool SendResults_ML(const std::string& PePath, const std::string& FileHash, const MlScanResult& Result);
};
