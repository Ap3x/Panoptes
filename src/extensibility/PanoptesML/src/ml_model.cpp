#include "PanoptesML.h"
#include <onnxruntime/onnxruntime_cxx_api.h> // vcpkg installs the headers under include/onnxruntime
#include <stdexcept>

struct MlModel::Impl {
	Ort::Env Env{ ORT_LOGGING_LEVEL_WARNING, "PanoptesML" };
	Ort::Session Session{ nullptr };
	std::string InputName;
	std::vector<std::string> OutputNames;
	size_t ScoreOutput = 0; // index of the float tensor output the score is read from
};

static std::string Narrow(const std::wstring& Text)
{
	int length = WideCharToMultiByte(CP_UTF8, 0, Text.c_str(), (int)Text.size(), NULL, 0, NULL, NULL);
	std::string out(length, '\0');
	WideCharToMultiByte(CP_UTF8, 0, Text.c_str(), (int)Text.size(), out.data(), length, NULL, NULL);
	return out;
}

/// @brief The vcpkg onnxruntime port builds with onnxruntime_DEBUG_NODE_INPUTS_OUTPUTS, in every
/// configuration, which prints each node's shapes and placement on every run unless these are 0.
/// Set them before the first session is created; a value already in the environment is kept, so
/// the dumps can still be turned on to debug a model
static void QuietNodeDumps()
{
	for (const char* name : { "ORT_DEBUG_NODE_IO_DUMP_SHAPE_DATA", "ORT_DEBUG_NODE_IO_DUMP_NODE_PLACEMENT" }) {
		if (GetEnvironmentVariableA(name, NULL, 0) == 0) {
			SetEnvironmentVariableA(name, "0");
		}
	}
}

static Ort::SessionOptions MakeSessionOptions()
{
	Ort::SessionOptions options;
	// One file is scored at a time and the container runs next to everything else on the
	// machine, so keep the model from spreading across every core
	options.SetIntraOpNumThreads(1);
	options.SetGraphOptimizationLevel(GraphOptimizationLevel::ORT_ENABLE_ALL);
	return options;
}

MlModel::MlModel(const std::wstring& ModelPath)
	: m_impl((QuietNodeDumps(), std::make_unique<Impl>()))
{
	m_name = Narrow(ModelPath.substr(ModelPath.find_last_of(L"\\/") + 1));
	m_impl->Session = Ort::Session(m_impl->Env, ModelPath.c_str(), MakeSessionOptions());
	Inspect();
}

MlModel::MlModel(const void* Data, size_t Size, const std::string& Name)
	: m_impl((QuietNodeDumps(), std::make_unique<Impl>())), m_name(Name)
{
	// ONNX Runtime copies what it needs; the caller may wipe Data afterwards
	m_impl->Session = Ort::Session(m_impl->Env, Data, Size, MakeSessionOptions());
	Inspect();
}

void MlModel::Inspect()
{
	Ort::AllocatorWithDefaultOptions allocator;
	if (m_impl->Session.GetInputCount() != 1) {
		throw std::runtime_error(m_name + " must have one input, the feature vector");
	}
	m_impl->InputName = m_impl->Session.GetInputNameAllocated(0, allocator).get();

	// The input must be [N, FEATURE_COUNT] floats; N may be dynamic (-1). The shape info is a
	// view into the TypeInfo, so the TypeInfo must outlive it: not a temporary
	Ort::TypeInfo inputType = m_impl->Session.GetInputTypeInfo(0);
	auto input = inputType.GetTensorTypeAndShapeInfo();
	std::vector<int64_t> shape = input.GetShape();
	if (input.GetElementType() != ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT || shape.size() != 2 ||
		(shape[1] != -1 && shape[1] != (int64_t)FEATURE_COUNT)) {
		throw std::runtime_error(m_name + " must take a float tensor of shape [N, " +
			std::to_string(FEATURE_COUNT) + "] (feature version " + std::to_string(PANO_ML_FEATURE_VERSION) + ")");
	}

	// Classifiers exported from scikit-learn output a label and then the probabilities; the
	// score is the last value of the first float tensor output
	bool found = false;
	for (size_t i = 0; i < m_impl->Session.GetOutputCount(); i++) {
		m_impl->OutputNames.push_back(m_impl->Session.GetOutputNameAllocated(i, allocator).get());
		Ort::TypeInfo type = m_impl->Session.GetOutputTypeInfo(i);
		if (!found && type.GetONNXType() == ONNX_TYPE_TENSOR &&
			type.GetTensorTypeAndShapeInfo().GetElementType() == ONNX_TENSOR_ELEMENT_DATA_TYPE_FLOAT) {
			m_impl->ScoreOutput = i;
			found = true;
		}
	}
	if (!found) {
		throw std::runtime_error(m_name + " has no float tensor output to read the score from "
			"(export scikit-learn classifiers with zipmap disabled)");
	}
}

MlModel::~MlModel() = default;

float MlModel::Score(const std::vector<float>& Features)
{
	if (Features.size() != FEATURE_COUNT) {
		throw std::runtime_error("expected " + std::to_string(FEATURE_COUNT) + " features, got " + std::to_string(Features.size()));
	}

	Ort::MemoryInfo memory = Ort::MemoryInfo::CreateCpu(OrtArenaAllocator, OrtMemTypeDefault);
	const int64_t shape[2] = { 1, (int64_t)FEATURE_COUNT };
	Ort::Value input = Ort::Value::CreateTensor<float>(memory, const_cast<float*>(Features.data()),
		Features.size(), shape, 2);

	const char* inputName = m_impl->InputName.c_str();
	const char* outputName = m_impl->OutputNames[m_impl->ScoreOutput].c_str();
	std::vector<Ort::Value> outputs = m_impl->Session.Run(Ort::RunOptions{ nullptr }, &inputName, &input, 1, &outputName, 1);

	auto info = outputs[0].GetTensorTypeAndShapeInfo();
	size_t count = info.GetElementCount();
	if (count == 0) {
		throw std::runtime_error(m_name + " returned an empty score");
	}
	return outputs[0].GetTensorData<float>()[count - 1];
}

std::wstring ModuleDirectory()
{
	HMODULE module = NULL;
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)&ModuleDirectory, &module);
	WCHAR path[MAX_PATH];
	DWORD length = GetModuleFileNameW(module, path, MAX_PATH);
	std::wstring directory(path, length);
	return directory.substr(0, directory.find_last_of(L'\\') + 1);
}
