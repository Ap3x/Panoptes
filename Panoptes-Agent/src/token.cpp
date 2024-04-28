#include "token.hpp"


BOOL token::GetProcessTokenInfo(DWORD processId) {
	bool maliciousPerms = false;
	// Open a handle to the process
	HANDLE processHandle = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, processId);
	if (processHandle == NULL) {
		printf("Failed to open process. Error code: %lu\n", GetLastError());
		return maliciousPerms;
	}

	// Open the process token
	HANDLE tokenHandle;
	if (!OpenProcessToken(processHandle, TOKEN_QUERY, &tokenHandle)) {
		printf("Failed to open process token. Error code: %lu", GetLastError());
		CloseHandle(processHandle);
		return maliciousPerms;
	}

	//// Get the token user information
	//DWORD tokenInfoSize = 0;
	//GetTokenInformation(tokenHandle, TokenUser, NULL, 0, &tokenInfoSize);

	//PTOKEN_USER tokenInfo = (PTOKEN_USER)malloc(tokenInfoSize);
	//if (!GetTokenInformation(tokenHandle, TokenUser, tokenInfo, tokenInfoSize, &tokenInfoSize)) {
	//	printf("Failed to get token information. Error code: %lu", GetLastError());
	//	free(tokenInfo);
	//	CloseHandle(tokenHandle);
	//	CloseHandle(processHandle);
	//	return maliciousPerms;
	//}

	//// Print the token information
	//LPWSTR userName;
	//LPWSTR domain;
	//DWORD userNameSize = 0;
	//SID_NAME_USE sidNameUse;
	//DWORD domainNameSize = 0;
	//LookupAccountSidW(NULL, tokenInfo->User.Sid, NULL, &userNameSize, NULL, &domainNameSize, &sidNameUse);
	//userName = (LPWSTR)malloc(userNameSize * sizeof(WCHAR));
	//domain = (LPWSTR)malloc(domainNameSize * sizeof(WCHAR));
	//LookupAccountSidW(NULL, tokenInfo->User.Sid, userName, &userNameSize, domain, &domainNameSize, &sidNameUse);

	//wprintf(TEXT("User name: %ws\n"), userName);
	//wprintf(TEXT("ComputerName: %ws\n"), domain);

	//// Clean up
	//free(domain);
	//free(userName);
	//free(tokenInfo);

	// Get the token privileges
	DWORD tokenPrivilegesSize = 0;
	GetTokenInformation(tokenHandle, TokenPrivileges, NULL, 0, &tokenPrivilegesSize);

	PTOKEN_PRIVILEGES tokenPrivileges = (PTOKEN_PRIVILEGES)malloc(tokenPrivilegesSize);
	if (!GetTokenInformation(tokenHandle, TokenPrivileges, tokenPrivileges, tokenPrivilegesSize, &tokenPrivilegesSize)) {
		printf("Failed to get token privileges. Error code: %lu\n", GetLastError());
		free(tokenPrivileges);
		CloseHandle(tokenHandle);
		CloseHandle(processHandle);
		return maliciousPerms;
	}

	// Print the token privileges
	printf("Token Privileges:\n");
	for (DWORD i = 0; i < tokenPrivileges->PrivilegeCount; i++) {
		LUID_AND_ATTRIBUTES privilege = tokenPrivileges->Privileges[i];

		// Convert the privilege LUID to a string
		LPWSTR privilegeName;
		DWORD privilegeNameSize = 0;
		LookupPrivilegeNameW(NULL, &privilege.Luid, NULL, &privilegeNameSize);
		privilegeName = (LPWSTR)malloc(privilegeNameSize * sizeof(WCHAR));
		LookupPrivilegeNameW(NULL, &privilege.Luid, privilegeName, &privilegeNameSize);
		if (wcscmp(privilegeName, L"SeDebugPrivilege") == 0) {
			maliciousPerms = true;
		}
		//printf("- %ls (Attributes: %lu)\n", privilegeName, privilege.Attributes);
		free(privilegeName);
	}

	// Clean up
	free(tokenPrivileges);
	CloseHandle(tokenHandle);
	CloseHandle(processHandle);

	return maliciousPerms;
}