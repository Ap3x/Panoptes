#pragma once
#include <Windows.h>
#include "error_message.h"

ERRORCODE SetEnvironmentMutex();
ERRORCODE MutexExist();
ERRORCODE DestroyMutex();
