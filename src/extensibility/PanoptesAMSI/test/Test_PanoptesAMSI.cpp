#include "gtest/gtest.h"
#include "PanoptesAMSI.h"

namespace AMSI {
	TEST(AMSIScan, ScanFileCopy) {
		int result = -1;
		AmsiScanner::AmsiScanFile("C:\\Windows\\System32\\notepad.exe", "C:\\Windows\\Temp\\notepad2.exe", &result);
		EXPECT_EQ(result, 1);
	}

	TEST(AMSIScan, ScanFileNoCopy) {
		int result = -1;
		AmsiScanner::AmsiScanFile("C:\\Windows\\System32\\notepad.exe", "", &result);
		EXPECT_EQ(result, 1);
	}
}