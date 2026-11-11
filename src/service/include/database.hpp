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
	/// @brief Flushes and closes the database. Safe to call if it was never opened
	static void CloseDatabase();
	PanoptesDatabase();
};