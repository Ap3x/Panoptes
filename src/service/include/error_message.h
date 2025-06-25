#pragma once
#include <Windows.h>
#include <string>
#include "service_constants.h"
#include "ResourceCore.h"

void DisplayErrorMessage(std::string errorMessage);
std::string GetErrorMessage(UINT resourceID);
