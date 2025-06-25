#pragma once
#include <Windows.h>
#include <iostream>
#include <string>
#include <fstream>
#include <vector>

/// @brief Check if a file exists
/// @param filePath The path to the file
/// @return True if the file exists, false otherwise
bool FileExists(const std::string& filePath);

/// @brief Remove a string from a vector    
/// @param vec The vector to remove the string from
/// @param str The string to remove
void RemoveStringFromVector(std::vector<std::string>& vec, const std::string& str);

/// @brief Check if a string is in a vector
/// @param vec The vector to check
/// @param str The string to check
/// @return True if the string is in the vector, false otherwise
bool IsStringInVector(const std::vector<std::string>& vec, const std::string& str);