// The model embedded in the DLL: an RCDATA resource holding model.onnx encrypted with AES-256-GCM
// by tools/sealmodel at build time. This keeps the model from being copied off a machine or read
// as a file, and a modified model fails GCM authentication instead of loading. It doesn't make
// the model secret from someone who reverse-engineers the DLL: the key is compiled in (masked,
// from the generated model_key.h), and the plain model is in memory while ONNX Runtime loads it.
#include "PanoptesML.h"
#include <bcrypt.h>
#include <cstdio>
#include <cstring>
#include <stdexcept>

#pragma comment(lib, "bcrypt.lib")

#ifdef PANO_ML_EMBEDDED_MODEL
#include "model_key.h" // generated with the sealed model, in the build folder

namespace {
	constexpr char kMagic[4] = { 'P', 'M', 'L', 'E' };
	constexpr uint32_t kVersion = 1;
	constexpr size_t kHeaderSize = 8, kNonceSize = 12, kTagSize = 16, kKeySize = 32;
	static_assert(sizeof(g_ModelKeyMasked) == kKeySize && sizeof(g_ModelKeyMask) == kKeySize);

	struct Algorithm {
		BCRYPT_ALG_HANDLE Handle = NULL;
		~Algorithm() { if (Handle) BCryptCloseAlgorithmProvider(Handle, 0); }
	};
	struct Key {
		BCRYPT_KEY_HANDLE Handle = NULL;
		~Key() { if (Handle) BCryptDestroyKey(Handle); }
	};

	void Check(NTSTATUS Status, const char* What)
	{
		if (Status < 0) {
			char text[96];
			snprintf(text, sizeof(text), "embedded model: %s failed (NTSTATUS 0x%08lx)", What, (unsigned long)Status);
			throw std::runtime_error(text);
		}
	}
}

bool LoadEmbeddedModel(std::vector<uint8_t>& Model)
{
	HMODULE module = NULL;
	GetModuleHandleExW(GET_MODULE_HANDLE_EX_FLAG_FROM_ADDRESS | GET_MODULE_HANDLE_EX_FLAG_UNCHANGED_REFCOUNT,
		(LPCWSTR)&LoadEmbeddedModel, &module);
	HRSRC resource = FindResourceW(module, PANO_ML_MODEL_RESOURCE, RT_RCDATA);
	if (resource == NULL) {
		return false;
	}
	HGLOBAL loaded = LoadResource(module, resource);
	const uint8_t* sealed = loaded ? (const uint8_t*)LockResource(loaded) : nullptr;
	size_t size = SizeofResource(module, resource);
	uint32_t version = 0;
	if (sealed && size >= kHeaderSize) {
		memcpy(&version, sealed + 4, sizeof(version));
	}
	if (!sealed || size < kHeaderSize + kNonceSize + kTagSize || memcmp(sealed, kMagic, 4) != 0 || version != kVersion) {
		throw std::runtime_error("embedded model: not a sealed model (version 1)");
	}
	const uint8_t* nonce = sealed + kHeaderSize;
	const uint8_t* cipherText = nonce + kNonceSize;
	size_t cipherSize = size - kHeaderSize - kNonceSize - kTagSize;
	const uint8_t* tag = cipherText + cipherSize;

	// The key only exists in this buffer, briefly
	uint8_t keyBytes[kKeySize];
	for (size_t i = 0; i < kKeySize; i++) {
		keyBytes[i] = ((volatile unsigned char*)g_ModelKeyMasked)[i] ^ ((volatile unsigned char*)g_ModelKeyMask)[i];
	}
	Algorithm algorithm;
	Key key;
	NTSTATUS status = BCryptOpenAlgorithmProvider(&algorithm.Handle, BCRYPT_AES_ALGORITHM, NULL, 0);
	if (status >= 0) {
		status = BCryptSetProperty(algorithm.Handle, BCRYPT_CHAINING_MODE, (PUCHAR)BCRYPT_CHAIN_MODE_GCM,
			sizeof(BCRYPT_CHAIN_MODE_GCM), 0);
	}
	if (status >= 0) {
		status = BCryptGenerateSymmetricKey(algorithm.Handle, &key.Handle, NULL, 0, keyBytes, kKeySize, 0);
	}
	SecureZeroMemory(keyBytes, sizeof(keyBytes));
	Check(status, "AES-GCM setup");

	BCRYPT_AUTHENTICATED_CIPHER_MODE_INFO info;
	BCRYPT_INIT_AUTH_MODE_INFO(info);
	info.pbNonce = (PUCHAR)nonce;
	info.cbNonce = (ULONG)kNonceSize;
	info.pbTag = (PUCHAR)tag;
	info.cbTag = (ULONG)kTagSize;
	info.pbAuthData = (PUCHAR)sealed; // the magic and version
	info.cbAuthData = (ULONG)kHeaderSize;

	Model.resize(cipherSize);
	ULONG written = 0;
	status = BCryptDecrypt(key.Handle, (PUCHAR)cipherText, (ULONG)cipherSize, &info, NULL, 0,
		Model.data(), (ULONG)Model.size(), &written, 0);
	if (status < 0) {
		SecureZeroMemory(Model.data(), Model.size());
		Model.clear();
		if (status == (NTSTATUS)0xC000A002L) { // STATUS_AUTH_TAG_MISMATCH
			throw std::runtime_error("embedded model: authentication failed; the DLL's model was modified or corrupted");
		}
		Check(status, "decryption");
	}
	Model.resize(written);
	return true;
}

#else

bool LoadEmbeddedModel(std::vector<uint8_t>&)
{
	return false; // built without assets/ml/model.onnx, or with PANOPTES_ML_EMBED_MODEL off
}

#endif
