#pragma once
#include <vector>
#include <panoptes.pb.h>
#include "service_constants.h"
#include "Configuration.hpp"

ERRORCODE StartContainers(std::vector<Configuration::ContainerType> selectedExtensibility);