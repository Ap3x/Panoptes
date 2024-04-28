#pragma once
#include "framework.h"
#include "utils.hpp"
#include "pe.hpp"
#include <string>
#include <wchar.h>

class inject
{
public:
	static BOOL InjectDLL(DWORD pid);
	static VOID GetFileHash();
};

