#pragma once
// Section helpers for the map and unmap hook tests. The views are mapped and unmapped by calling
// the ntdll exports directly, which go through the hooks, so each test controls exactly which
// export (plain or Ex) is exercised.
#include "hook_test_harness.hpp"

#define TEST_NT_SUCCESS(status) ((NTSTATUS)(status) >= 0)

/// SECTION_INHERIT::ViewUnmap: the view is not mapped into child processes
#define TEST_VIEW_UNMAP 2

typedef NTSTATUS(NTAPI* NtMapViewOfSection_t)(HANDLE SectionHandle, HANDLE ProcessHandle,
	PVOID* BaseAddress, ULONG_PTR ZeroBits, SIZE_T CommitSize, PLARGE_INTEGER SectionOffset,
	PSIZE_T ViewSize, DWORD InheritDisposition, ULONG AllocationType, ULONG Win32Protect);
typedef NTSTATUS(NTAPI* NtMapViewOfSectionEx_t)(HANDLE SectionHandle, HANDLE ProcessHandle,
	PVOID* BaseAddress, PLARGE_INTEGER SectionOffset, PSIZE_T ViewSize, ULONG AllocationType,
	ULONG PageProtection, PMEM_EXTENDED_PARAMETER ExtendedParameters, ULONG ExtendedParameterCount);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSection_t)(HANDLE ProcessHandle, PVOID BaseAddress);
typedef NTSTATUS(NTAPI* NtUnmapViewOfSectionEx_t)(HANDLE ProcessHandle, PVOID BaseAddress, ULONG Flags);

/// @brief Creates a one-page, pagefile-backed section with the given maximum protection.
inline HANDLE CreatePageSection(DWORD protection) {
	return CreateFileMappingA(INVALID_HANDLE_VALUE, NULL, protection | SEC_COMMIT, 0, 0x1000, NULL);
}

/// @brief Creates an image section from System32\version.dll, which the tests do not otherwise
/// load. A 32-bit test gets the 32-bit DLL through WOW64 file system redirection. The view's
/// first page is the read-only PE header; its code section is executable.
inline HANDLE CreateImageSection() {
	char path[MAX_PATH];
	GetSystemDirectoryA(path, MAX_PATH);
	strcat_s(path, "\\version.dll");
	HANDLE file = CreateFileA(path, GENERIC_READ, FILE_SHARE_READ, NULL, OPEN_EXISTING, 0, NULL);
	if (file == INVALID_HANDLE_VALUE) {
		fprintf(stderr, "    failed to open %s (error %lu)\n", path, GetLastError());
		return NULL;
	}
	HANDLE section = CreateFileMappingA(file, NULL, PAGE_READONLY | SEC_IMAGE, 0, 0, NULL);
	CloseHandle(file);
	return section;
}

/// @brief Maps a view of a section through NtMapViewOfSection. Returns NULL if the call fails.
inline PVOID MapView(HANDLE section, HANDLE process, ULONG protection) {
	auto map = NtdllFunction<NtMapViewOfSection_t>("NtMapViewOfSection");
	PVOID base = NULL;
	SIZE_T size = 0;
	NTSTATUS status = map(section, process, &base, 0, 0, NULL, &size, TEST_VIEW_UNMAP, 0, protection);
	return TEST_NT_SUCCESS(status) ? base : NULL;
}

/// @brief Maps a view of a section through NtMapViewOfSectionEx. Returns NULL if the call fails.
inline PVOID MapViewEx(HANDLE section, HANDLE process, ULONG protection) {
	auto map = NtdllFunction<NtMapViewOfSectionEx_t>("NtMapViewOfSectionEx");
	if (map == NULL) {
		fprintf(stderr, "    NtMapViewOfSectionEx is not exported by this ntdll\n");
		return NULL;
	}
	PVOID base = NULL;
	SIZE_T size = 0;
	NTSTATUS status = map(section, process, &base, NULL, &size, 0, protection, NULL, 0);
	return TEST_NT_SUCCESS(status) ? base : NULL;
}

inline NTSTATUS UnmapView(HANDLE process, PVOID address) {
	return NtdllFunction<NtUnmapViewOfSection_t>("NtUnmapViewOfSection")(process, address);
}

inline NTSTATUS UnmapViewEx(HANDLE process, PVOID address) {
	auto unmap = NtdllFunction<NtUnmapViewOfSectionEx_t>("NtUnmapViewOfSectionEx");
	if (unmap == NULL) {
		fprintf(stderr, "    NtUnmapViewOfSectionEx is not exported by this ntdll\n");
		return (NTSTATUS)0xC0000002; // STATUS_NOT_IMPLEMENTED
	}
	return unmap(process, address, 0);
}
