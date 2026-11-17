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

	// A file deleted before its scan used to free the scanner twice (heap corruption that
	// ended the container). It must throw cleanly, and the scanner must still work afterwards
	TEST_F(YaraScanTest, MissingFileThrowsAndScannerStillWorks) {
		for (int i = 0; i < 3; i++) {
			EXPECT_THROW(yaraScan->YaraScanFile("C:\\does\\not\\exist.exe"), std::runtime_error);
		}
		EXPECT_EQ(yaraScan->YaraScanFile("C:\\Windows\\System32\\notepad.exe").size(), 0);
	}

	TEST(SignatureTest, NotePadIsTrusted) {
		SignatureInfo info = VerifyFileSignature("C:\\Windows\\System32\\notepad.exe");
		EXPECT_TRUE(info.isSigned);
		EXPECT_TRUE(info.trusted);
		EXPECT_TRUE(info.catalogSigned);
		EXPECT_EQ(info.trustStatus, ERROR_SUCCESS);
		EXPECT_FALSE(info.signer.empty());
	}

	TEST(SignatureTest, EmbeddedSignatureIsTrusted) {
		// MpSigStub.exe ships with Defender and has an embedded signature
		const char* path = "C:\\Windows\\System32\\MpSigStub.exe";
		if (GetFileAttributesA(path) == INVALID_FILE_ATTRIBUTES) {
			GTEST_SKIP() << "MpSigStub.exe is not present";
		}

		SignatureInfo info = VerifyFileSignature(path);
		EXPECT_TRUE(info.isSigned);
		EXPECT_TRUE(info.trusted);
		EXPECT_FALSE(info.catalogSigned);
		EXPECT_FALSE(info.signer.empty());
	}

	TEST(SignatureTest, EicarIsUnsigned) {
		SignatureInfo info = VerifyFileSignature(EICAR_PATH);
		EXPECT_FALSE(info.isSigned);
		EXPECT_FALSE(info.trusted);
		EXPECT_FALSE(info.catalogSigned);
		EXPECT_TRUE(info.signer.empty());
	}
}