#include "PanoptesYara.h"
#include <Softpub.h>
#include <wintrust.h>
#include <mscat.h>
#include <bcrypt.h>

/// @brief Convert an ANSI path to a wide string
/// @param str The ANSI string
/// @return The wide string
static std::wstring ToWide(const std::string& str)
{
	int size = MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, NULL, 0);
	if (size <= 0) {
		return std::wstring();
	}

	std::wstring result(size, L'\0');
	MultiByteToWideChar(CP_ACP, 0, str.c_str(), -1, &result[0], size);
	result.resize(size - 1);
	return result;
}

/// @brief Convert a wide string to UTF-8
/// @param str The wide string
/// @return The UTF-8 string
static std::string ToUtf8(const std::wstring& str)
{
	int size = WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, NULL, 0, NULL, NULL);
	if (size <= 0) {
		return std::string();
	}

	std::string result(size, '\0');
	WideCharToMultiByte(CP_UTF8, 0, str.c_str(), -1, &result[0], size, NULL, NULL);
	result.resize(size - 1);
	return result;
}

/// @brief Get the display name of the signing certificate from WinVerifyTrust state data
/// @param stateData The state data returned by WinVerifyTrust
/// @return The signer's display name, empty if it could not be retrieved
static std::string GetSignerName(HANDLE stateData)
{
	CRYPT_PROVIDER_DATA* providerData = WTHelperProvDataFromStateData(stateData);
	if (providerData == NULL) {
		return std::string();
	}

	CRYPT_PROVIDER_SGNR* signer = WTHelperGetProvSignerFromChain(providerData, 0, FALSE, 0);
	if (signer == NULL || signer->csCertChain == 0) {
		return std::string();
	}

	CRYPT_PROVIDER_CERT* cert = WTHelperGetProvCertFromChain(signer, 0);
	if (cert == NULL || cert->pCert == NULL) {
		return std::string();
	}

	DWORD size = CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, NULL, 0);
	if (size <= 1) {
		return std::string();
	}

	std::wstring name(size, L'\0');
	CertGetNameStringW(cert->pCert, CERT_NAME_SIMPLE_DISPLAY_TYPE, 0, NULL, &name[0], size);
	name.resize(size - 1);
	return ToUtf8(name);
}

/// @brief Run WinVerifyTrust on the prepared trust data and collect the signer name
/// @param trustData The WINTRUST_DATA with the union choice and subject already set
/// @param signer Receives the signer's display name
/// @return The WinVerifyTrust result
static LONG RunWinVerifyTrust(WINTRUST_DATA& trustData, std::string& signer)
{
	GUID policyGuid = WINTRUST_ACTION_GENERIC_VERIFY_V2;

	trustData.cbStruct = sizeof(trustData);
	trustData.dwUIChoice = WTD_UI_NONE;
	trustData.fdwRevocationChecks = WTD_REVOKE_NONE;
	trustData.dwProvFlags = WTD_SAFER_FLAG;
	trustData.dwStateAction = WTD_STATEACTION_VERIFY;

	LONG status = WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGuid, &trustData);
	if (trustData.hWVTStateData != NULL) {
		signer = GetSignerName(trustData.hWVTStateData);
	}

	// Release the state data
	trustData.dwStateAction = WTD_STATEACTION_CLOSE;
	WinVerifyTrust(static_cast<HWND>(INVALID_HANDLE_VALUE), &policyGuid, &trustData);

	return status;
}

/// @brief Verify the file against the system catalogs
/// @param filePath The path to the file
/// @param info Updated with the catalog verification result if the file is in a catalog
/// @return True if the file was found in a catalog, false otherwise
static bool VerifyCatalogSignature(const std::wstring& filePath, SignatureInfo& info)
{
	HANDLE file = CreateFileW(filePath.c_str(), GENERIC_READ, FILE_SHARE_READ | FILE_SHARE_WRITE | FILE_SHARE_DELETE,
		NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		return false;
	}

	bool found = false;

	// Newer catalogs use SHA256 hashes, older ones use SHA1
	for (LPCWSTR algorithm : { BCRYPT_SHA256_ALGORITHM, BCRYPT_SHA1_ALGORITHM }) {
		HCATADMIN catAdmin = NULL;
		if (!CryptCATAdminAcquireContext2(&catAdmin, NULL, algorithm, NULL, 0)) {
			continue;
		}

		DWORD hashSize = 0;
		CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, &hashSize, NULL, 0);
		std::vector<BYTE> hash(hashSize);
		if (hashSize == 0 || !CryptCATAdminCalcHashFromFileHandle2(catAdmin, file, &hashSize, hash.data(), 0)) {
			CryptCATAdminReleaseContext(catAdmin, 0);
			continue;
		}

		HCATINFO catInfo = CryptCATAdminEnumCatalogFromHash(catAdmin, hash.data(), hashSize, 0, NULL);
		if (catInfo != NULL) {
			CATALOG_INFO catalog = {};
			catalog.cbStruct = sizeof(catalog);
			if (CryptCATCatalogInfoFromContext(catInfo, &catalog, 0)) {
				// The catalog member tag is the file hash as an uppercase hex string
				std::wstring memberTag;
				wchar_t hex[3];
				for (BYTE b : hash) {
					swprintf_s(hex, L"%02X", b);
					memberTag += hex;
				}

				WINTRUST_CATALOG_INFO catalogInfo = {};
				catalogInfo.cbStruct = sizeof(catalogInfo);
				catalogInfo.pcwszCatalogFilePath = catalog.wszCatalogFile;
				catalogInfo.pcwszMemberFilePath = filePath.c_str();
				catalogInfo.pcwszMemberTag = memberTag.c_str();
				catalogInfo.hMemberFile = file;
				catalogInfo.pbCalculatedFileHash = hash.data();
				catalogInfo.cbCalculatedFileHash = hashSize;
				catalogInfo.hCatAdmin = catAdmin;

				WINTRUST_DATA trustData = {};
				trustData.dwUnionChoice = WTD_CHOICE_CATALOG;
				trustData.pCatalog = &catalogInfo;

				info.trustStatus = RunWinVerifyTrust(trustData, info.signer);
				info.isSigned = true;
				info.catalogSigned = true;
				info.trusted = info.trustStatus == ERROR_SUCCESS;
				found = true;
			}
			CryptCATAdminReleaseCatalogContext(catAdmin, catInfo, 0);
		}

		CryptCATAdminReleaseContext(catAdmin, 0);
		if (found) {
			break;
		}
	}

	CloseHandle(file);
	return found;
}

/// @brief Verify the Authenticode signature of a file using WinVerifyTrust. The embedded
/// signature is checked first, falling back to the system catalogs if the file has none
/// @param PathToFile The path to the file
/// @return The signature information
SignatureInfo VerifyFileSignature(const std::string& PathToFile)
{
	SignatureInfo info;
	std::wstring filePath = ToWide(PathToFile);
	if (filePath.empty()) {
		return info;
	}

	WINTRUST_FILE_INFO fileInfo = {};
	fileInfo.cbStruct = sizeof(fileInfo);
	fileInfo.pcwszFilePath = filePath.c_str();

	WINTRUST_DATA trustData = {};
	trustData.dwUnionChoice = WTD_CHOICE_FILE;
	trustData.pFile = &fileInfo;

	LONG status = RunWinVerifyTrust(trustData, info.signer);
	switch (status) {
	case TRUST_E_NOSIGNATURE:
	case TRUST_E_SUBJECT_FORM_UNKNOWN:
	case TRUST_E_PROVIDER_UNKNOWN:
		// No embedded signature, check if the file is signed through a catalog
		info.signer.clear();
		if (!VerifyCatalogSignature(filePath, info)) {
			info.trustStatus = status;
		}
		break;
	default:
		info.isSigned = true;
		info.trustStatus = status;
		info.trusted = status == ERROR_SUCCESS;
		break;
	}

	return info;
}
