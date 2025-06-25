#pragma once
#include <Windows.h>
#include "service_constants.h"

ERRORCODE StartWindowsDriver();
ERRORCODE StopWindowsDriver();
ERRORCODE GetKernelServiceStatus();