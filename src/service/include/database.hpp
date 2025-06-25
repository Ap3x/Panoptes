#pragma once
#include <Windows.h>
#include <nlohmann/json.hpp>
#include "ResourceCore.h"
#include "error_message.h"

class PanoptesDatabase {
public:
	//BOOL DeleteDatabase(string databasePath);
	std::string UpdateEntry(std::string key, std::string entry);
	BOOL AddEntry(std::string key, std::string entry);
	std::string GetEntry(std::string hash);
	ERRORCODE InitializeDatabase();
	PanoptesDatabase();
};