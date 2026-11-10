#include "inject_exclusions.h"
#include "pano_events.h"

#define INJECT_EXCLUSIONS_TAG 'xEnP'

// One allocation holding the header, the Names array and the characters the names point at,
// so a list is replaced by swapping a single pointer
typedef struct _INJECT_EXCLUSION_LIST {
	ULONG Count;
	UNICODE_STRING Names[1];
} INJECT_EXCLUSION_LIST, * PINJECT_EXCLUSION_LIST;

static EX_PUSH_LOCK g_ListLock;
static PINJECT_EXCLUSION_LIST g_List; // NULL when the list is empty

void InjectExclusionsInit()
{
	ExInitializePushLock(&g_ListLock);
	g_List = NULL;
}

void InjectExclusionsCleanup()
{
	if (g_List != NULL) {
		ExFreePoolWithTag(g_List, INJECT_EXCLUSIONS_TAG);
		g_List = NULL;
	}
}

NTSTATUS InjectExclusionsSet(PVOID Buffer, ULONG Length)
{
	PAGED_CODE();

	const ULONG headerSize = FIELD_OFFSET(PANO_INJECTION_EXCLUSIONS, Names);
	if (Buffer == NULL || Length < headerSize || (Length - headerSize) % sizeof(WCHAR) != 0) {
		return STATUS_INVALID_PARAMETER;
	}

	PPANO_INJECTION_EXCLUSIONS request = (PPANO_INJECTION_EXCLUSIONS)Buffer;
	ULONG count = request->Count;
	if (count > PANO_MAX_INJECTION_EXCLUSIONS) {
		return STATUS_INVALID_PARAMETER;
	}

	// Check every name lies inside the buffer and is terminated before anything is allocated.
	// The whole buffer must be used, so a wrong Count is caught
	const WCHAR* names = request->Names;
	ULONG remaining = (Length - headerSize) / sizeof(WCHAR);
	ULONG position = 0;
	for (ULONG i = 0; i < count; i++) {
		ULONG nameLength = 0;
		while (position + nameLength < remaining && names[position + nameLength] != L'\0') {
			nameLength++;
		}
		if (position + nameLength >= remaining || nameLength == 0 ||
			nameLength > PANO_MAX_INJECTION_EXCLUSION_LENGTH) {
			return STATUS_INVALID_PARAMETER;
		}
		position += nameLength + 1;
	}
	if (position != remaining) {
		return STATUS_INVALID_PARAMETER;
	}

	PINJECT_EXCLUSION_LIST newList = NULL;
	if (count > 0) {
		// The characters, terminators included, follow the Names array. position counts them
		SIZE_T namesOffset = FIELD_OFFSET(INJECT_EXCLUSION_LIST, Names) + (SIZE_T)count * sizeof(UNICODE_STRING);
		newList = (PINJECT_EXCLUSION_LIST)ExAllocatePool2(POOL_FLAG_PAGED, namesOffset + (SIZE_T)position * sizeof(WCHAR), INJECT_EXCLUSIONS_TAG);
		if (newList == NULL) {
			return STATUS_INSUFFICIENT_RESOURCES;
		}

		PWCHAR characters = (PWCHAR)((PUCHAR)newList + namesOffset);
		RtlCopyMemory(characters, names, (SIZE_T)position * sizeof(WCHAR));

		newList->Count = count;
		PWCHAR name = characters;
		for (ULONG i = 0; i < count; i++) {
			// Validated above: non-empty, terminated, at most PANO_MAX_INJECTION_EXCLUSION_LENGTH
			USHORT nameLength = (USHORT)wcslen(name);
			newList->Names[i].Buffer = name;
			newList->Names[i].Length = nameLength * sizeof(WCHAR);
			newList->Names[i].MaximumLength = newList->Names[i].Length + sizeof(WCHAR);
			name += nameLength + 1;
			DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_INFO_LEVEL, "[+] Panoptes:   Do not inject: %wZ\n", &newList->Names[i]);
		}
	}

	KeEnterCriticalRegion();
	ExAcquirePushLockExclusive(&g_ListLock);
	PINJECT_EXCLUSION_LIST oldList = g_List;
	g_List = newList;
	ExReleasePushLockExclusive(&g_ListLock);
	KeLeaveCriticalRegion();

	if (oldList != NULL) {
		ExFreePoolWithTag(oldList, INJECT_EXCLUSIONS_TAG);
	}

	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: Injection exclusion list set (%lu names)\n", count);
	return STATUS_SUCCESS;
}

BOOLEAN IsInjectionExcluded(PCUNICODE_STRING ProcessImagePath)
{
	PAGED_CODE();

	if (ProcessImagePath == NULL || ProcessImagePath->Buffer == NULL || ProcessImagePath->Length == 0) {
		return FALSE;
	}

	// The file name is everything after the last separator
	USHORT totalChars = ProcessImagePath->Length / sizeof(WCHAR);
	USHORT start = totalChars;
	while (start > 0 && ProcessImagePath->Buffer[start - 1] != L'\\') {
		start--;
	}

	UNICODE_STRING fileName;
	fileName.Buffer = ProcessImagePath->Buffer + start;
	fileName.Length = (totalChars - start) * sizeof(WCHAR);
	fileName.MaximumLength = fileName.Length;
	if (fileName.Length == 0) {
		return FALSE;
	}

	BOOLEAN excluded = FALSE;
	KeEnterCriticalRegion();
	ExAcquirePushLockShared(&g_ListLock);
	if (g_List != NULL) {
		for (ULONG i = 0; i < g_List->Count; i++) {
			// A name starting with \ is a full NT path and must match the whole image path.
			// Any other name is a file name and matches the image in any folder
			PCUNICODE_STRING entry = &g_List->Names[i];
			PCUNICODE_STRING candidate = (entry->Buffer[0] == L'\\') ? ProcessImagePath : &fileName;
			if (RtlEqualUnicodeString(candidate, entry, TRUE)) {
				excluded = TRUE;
				break;
			}
		}
	}
	ExReleasePushLockShared(&g_ListLock);
	KeLeaveCriticalRegion();
	return excluded;
}
