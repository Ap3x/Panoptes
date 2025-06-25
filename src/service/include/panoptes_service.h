#pragma once
#include "Configuration.hpp"
#include <atomic>
#include "database.hpp"

struct PanoptesContext {
	std::atomic<bool> threadError;
	Configuration* config;
	std::atomic<PanoptesDatabase> database = PanoptesDatabase();
};