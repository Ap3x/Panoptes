#include "framework.h"
#include "detours.h"
#include "vt_yara.hpp"
#include <vector>

class hook
{
public:
#pragma region API Definitions
    typedef DWORD(NTAPI* pNtWriteVirtualMemory)(
        HANDLE ProcessHandle,
        PVOID BaseAddress,
        PVOID Buffer,
        SIZE_T NumberOfBytesToWrite,
        PSIZE_T NumberOfBytesWritten
        );
#pragma endregion


    static DWORD HookedNtWriteVirtualMemory(
        HANDLE ProcessHandle, 
        PVOID BaseAddress, 
        PVOID Buffer, 
        SIZE_T NumberOfBytesToWrite, 
        PSIZE_T NumberOfBytesWritten);

    static VOID PlaceHooks(vt_yara obj);
    static VOID UnHook();

};

