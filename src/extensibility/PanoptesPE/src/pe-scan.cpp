#include <LIEF/PE.hpp>
#include <LIEF/errors.hpp>
#include <LIEF/PE/signature/Signature.hpp>
#include "PanoptesPE.h"


using namespace LIEF::PE;
std::unique_ptr<const Binary> binary;

/// @brief Constructor for the PortableExecutable class
/// @param PortableExecutablePath The path to the portable executable to scan
PortableExecutable::PortableExecutable(std::string PortableExecutablePath)
{
	binary = Parser::parse(PortableExecutablePath);
	return;
}

/// @brief Get the imports from the portable executable
/// @return A vector of strings containing the imports
std::vector<std::string> PortableExecutable::GetImports()
{
	std::vector<std::string> results;
	if (binary == NULL) {
		throw std::runtime_error("Not a PE");
	}

	if (binary->imports().size() > 0) {
		auto it_imports = binary->imports();
		for (LIEF::PE::Import import : it_imports)
		{
			std::string moduleName = import.name();
			for (auto entry : import.entries())
			{
				std::string entryName = entry.name();
				std::string entryJoined = moduleName + "!" + entryName;
				results.push_back(entryJoined);
			}
		}
	}
	return results;
}

/// @brief Get the sections from the portable executable
/// @return A vector of pairs containing the section name and entropy
std::vector<std::pair<std::string, double>> PortableExecutable::GetSections()
{
	std::vector<std::pair<std::string, double>> results;
	if (binary == NULL) {
		throw std::runtime_error("Not a PE");
	}

	if (binary->sections().size() > 0) {
		for (LIEF::PE::Section section : binary->sections())
		{
			std::string sectionName = section.name();
			double sectionEntropy = section.entropy();
			results.push_back(std::make_pair(sectionName, sectionEntropy));
		}
	}
	return results;
}

/// @brief Check if the portable executable is signed
/// @return True if the portable executable is signed, false otherwise
bool PortableExecutable::CheckIfSigned()
{
	if (binary == NULL) {
		throw std::runtime_error("Not a PE");
	}

	if (!binary->has_signatures())
		return false;

	Signature::VERIFICATION_FLAGS sigCheck = binary->verify_signature();
	if (sigCheck == Signature::VERIFICATION_FLAGS::OK)
		return true;

	return false;
}