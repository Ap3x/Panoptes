#include "gtest/gtest.h"
#include "PanoptesYara.h"

#define YARA_RULES "rules.pkg"
#define EICAR_PATH "eicarcom2.zip"

namespace Yara {
	class YaraScanTest : public ::testing::Test {
	protected:
		YaraScanner* yaraScan;

		void SetUp() override {
			yaraScan = new YaraScanner(YARA_RULES);
		}

		void TearDown() override {
			delete yaraScan;
			yaraScan = nullptr;
		}
	};

	TEST_F(YaraScanTest, ScanNotePad) {
		std::vector<string> result = yaraScan->YaraScanFile("C:\\Windows\\System32\\notepad.exe");
		EXPECT_EQ(result.size(), 0);
	}

	TEST_F(YaraScanTest, ScanEicar) {
		std::vector<string> result = yaraScan->YaraScanFile(EICAR_PATH);
		EXPECT_GT(result.size(), 0);
	}
}