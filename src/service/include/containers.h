#pragma once
#include <vector>
#include <panoptes.pb.h>
#include "service_constants.h"
#include "Configuration.hpp"

ERRORCODE StartContainers();

/// @brief Ends every container started by StartContainers. Safe to call if none were started
void StopContainers();
