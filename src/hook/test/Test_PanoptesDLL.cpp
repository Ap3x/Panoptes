#include <Windows.h>
#include <cstdio>
#include <cstring>

#ifdef _WIN64
#define HOOK_ARCH "x64"
#else
#define HOOK_ARCH "x86"
#endif

#define HOOK_DLL_NAME "PanoptesDLL" HOOK_ARCH ".dll"

/// @brief The ntdll functions the hook DLL places trampolines on.
static const char* g_hookedFunctions[] = {
	"NtWriteVirtualMemory",
	"NtMapViewOfSection",
	"NtMapViewOfSectionEx",
	"NtUnmapViewOfSection",
	"NtUnmapViewOfSectionEx",
	"NtProtectVirtualMemory",
	"NtAllocateVirtualMemory",
	"NtAllocateVirtualMemoryEx",
	"NtReadVirtualMemory",
	"NtCreateThreadEx",
	"NtQueueApcThread",
	"NtQueueApcThreadEx2",
	"NtSetInformationProcess",
};

/// @brief Checks whether an address falls inside a loaded module's image.
/// @param hModule The module to check against, or NULL.
/// @param address The address to check.
/// @return TRUE if the address is inside the module's image.
static BOOL IsInModule(HMODULE hModule, BYTE* address) {
	if (hModule == NULL) {
		return FALSE;
	}

	BYTE* base = (BYTE*)hModule;
	PIMAGE_NT_HEADERS ntHeaders = (PIMAGE_NT_HEADERS)(base + ((PIMAGE_DOS_HEADER)base)->e_lfanew);
	return address >= base && address < base + ntHeaders->OptionalHeader.SizeOfImage;
}

/// @brief Follows the chain of jmp rel32 / jmp [mem] instructions a Detours trampoline
/// is made of, starting at a function's entry point.
/// @param address The function entry point.
/// @param hops Receives the number of jumps followed.
/// @return The final destination of the jump chain.
static BYTE* FollowJumps(BYTE* address, int* hops) {
	*hops = 0;
	for (int i = 0; i < 8; i++) {
		if (address[0] == 0xE9) {
			// jmp rel32
			address = address + 5 + *(INT32*)(address + 1);
		}
		else if (address[0] == 0xFF && address[1] == 0x25) {
#ifdef _WIN64
			// jmp [rip+disp32]
			address = *(BYTE**)(address + 6 + *(INT32*)(address + 2));
#else
			// jmp [disp32]
			address = **(BYTE***)(address + 2);
#endif
		}
		else {
			break;
		}
		(*hops)++;
	}
	return address;
}

/// @brief Prints the entry bytes of each hooked ntdll function and whether it starts
/// with a trampoline into the hook DLL.
/// @param phase A label for when the check is being made.
/// @param hHook The loaded hook DLL, or NULL if it is not loaded.
/// @param expectHooked Whether every function should be hooked at this point.
/// @return The number of functions whose state does not match expectHooked.
static int CheckHooks(const char* phase, HMODULE hHook, BOOL expectHooked) {
	HMODULE hNtdll = GetModuleHandleA("ntdll.dll");
	int mismatches = 0;

	printf("\n[%s] expecting %s\n", phase, expectHooked ? "trampolines" : "clean functions");

	for (const char* name : g_hookedFunctions) {
		BYTE* function = (BYTE*)GetProcAddress(hNtdll, name);
		if (function == NULL) {
			printf("  %-26s not exported by this ntdll, skipping\n", name);
			continue;
		}

		printf("  %-26s %p:", name, (void*)function);
		for (int i = 0; i < 8; i++) {
			printf(" %02x", function[i]);
		}

		int hops = 0;
		BYTE* destination = FollowJumps(function, &hops);
		BOOL hooked = hops > 0 && IsInModule(hHook, destination);

		if (hops == 0) {
			printf("  clean");
		}
		else if (hooked) {
			printf("  trampoline -> %p in %s (%d jumps)", (void*)destination, HOOK_DLL_NAME, hops);
		}
		else {
			printf("  trampoline -> %p outside %s (%d jumps)", (void*)destination, HOOK_DLL_NAME, hops);
		}

		if (hooked != expectHooked) {
			printf("  <-- UNEXPECTED");
			mismatches++;
		}
		printf("\n");
	}

	return mismatches;
}

/// @brief Loads the hook DLL for this architecture from bin/<config>, one directory
/// above the tests folder this executable is placed in, and checks that its
/// trampolines are placed on load and removed on unload.
int main() {
	printf("Hello World from the %s hook loader\n", HOOK_ARCH);

	char dllPath[MAX_PATH];
	DWORD length = GetModuleFileNameA(NULL, dllPath, MAX_PATH);
	if (length == 0 || length == MAX_PATH) {
		printf("Failed to get the executable path (error %lu)\n", GetLastError());
		return 1;
	}

	// Replace the executable name with ..\<dll name>
	char* lastSlash = strrchr(dllPath, '\\');
	if (lastSlash == NULL) {
		printf("Unexpected executable path: %s\n", dllPath);
		return 1;
	}
	*(lastSlash + 1) = '\0';
	strcat_s(dllPath, MAX_PATH, "..\\" HOOK_DLL_NAME);

	int failures = CheckHooks("before load", NULL, FALSE);

	HMODULE hModule = LoadLibraryA(dllPath);
	if (hModule == NULL) {
		printf("Failed to load %s (error %lu)\n", dllPath, GetLastError());
		return 1;
	}

	printf("\nLoaded %s at %p\n", dllPath, (void*)hModule);

	failures += CheckHooks("after load", hModule, TRUE);

	FreeLibrary(hModule);
	printf("\nUnloaded %s\n", HOOK_DLL_NAME);

	failures += CheckHooks("after unload", NULL, FALSE);

	printf("\n%s\n", failures == 0 ? "PASS" : "FAIL");
	return failures == 0 ? 0 : 1;
}
