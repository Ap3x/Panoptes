#include "gtest/gtest.h"
#include "PanoptesPE.h"

namespace PE {

	TEST(PEScan, GetImports) {
		PortableExecutable* pe = new PortableExecutable("C:\\Windows\\System32\\notepad.exe");
		std::vector<std::string> result = pe->GetImports();
		EXPECT_GT(result.size(), 0);
	}

	TEST(PEScan, GetSections) {
		PortableExecutable* pe = new PortableExecutable("C:\\Windows\\System32\\notepad.exe");
		std::vector<std::pair<std::string, double>> result = pe->GetSections();
		EXPECT_GT(result.size(), 0);
	}

	TEST(PEScan, CheckIfSigned) {
		PortableExecutable* pe = new PortableExecutable("C:\\Windows\\System32\\notepad.exe");
		bool result = pe->CheckIfSigned();
		EXPECT_EQ(result, false);
	}
}