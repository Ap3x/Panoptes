#include "pipe.hpp"

void pipe::ParseRequest(IN LPCWSTR Request, PREQUEST req) {

	LPWSTR context = nullptr;
	LPWSTR strPID = wcstok_s((WCHAR*)Request, L":", &context);
	req->PID = static_cast<DWORD>(_wtoi(strPID));

	LPCWSTR PEPath = wcstok_s(nullptr, L"\0", &context) + 1;
	if (wcscmp(PEPath, L"") == 0) {
		req->Path = utils::GetBinaryPathFromPID(req->PID);
	} 
	else {
		req->Path = PEPath;
	}
	req->BaseName = utils::GetBaseName(req->Path);

}


// VOID pipe::SendDetection()
// {
// 	LPCTSTR lpszPipename = PIPE_NAME;
// 	HANDLE hPipe = CreateNamedPipe(
// 		lpszPipename,             // pipe name 
// 		PIPE_ACCESS_DUPLEX,       // read/write access 
// 		PIPE_TYPE_MESSAGE |       // message type pipe 
// 		PIPE_READMODE_MESSAGE |   // message-read mode 
// 		PIPE_WAIT,                // blocking mode 
// 		PIPE_UNLIMITED_INSTANCES, // max. instances  
// 		BUFFER_SIZE,              // output buffer size 
// 		BUFFER_SIZE,              // input buffer size 
// 		0,                        // client time-out 
// 		NULL);                    // default security attribute 

// 	if (hPipe != NULL) {
// 		BOOL fConnected = ConnectNamedPipe(hPipe, NULL) ?
// 			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

// 		if (fConnected)
// 		{
// 			HANDLE hHeap = GetProcessHeap();
// 			TCHAR* pchReply = (TCHAR*)HeapAlloc(hHeap, 0, BUFFER_SIZE * sizeof(TCHAR));

// 			DWORD pid = GetCurrentProcessId();
// 			// Convert DWORD to LPCTSTR (wide string)
// 			wchar_t wideBuffer[BUFFER_SIZE];
// 			utils::DwordToLpctstr(pid, wideBuffer, sizeof(wideBuffer) / sizeof(wchar_t));

// 			// Check the outgoing message to make sure it's not too long for the buffer.
// 			if (FAILED(StringCchCopy(pchReply, BUFFER_SIZE, wideBuffer)))
// 			{
// 				return;
// 			}
// 			else {
// 				DWORD cbReplyBytes = 0, cbWritten = 0;

// 				StringCchCat(pchReply, BUFFER_SIZE, TEXT(":"));
// 				BOOL fSuccess = WriteFile(
// 					hPipe,						// handle to pipe 
// 					pchReply,				// buffer to write from 
// 					cbReplyBytes, // number of bytes to write 
// 					&cbWritten,  // number of bytes written 
// 					NULL);			   // not overlapped I/O 

// 				if (fSuccess != 0 && cbReplyBytes != cbWritten)
// 				{
// 					wprintf(TEXT("InstanceThread WriteFile failed, GLE=%d.\n"), GetLastError());
// 				}
// 			}
// 		}
// 	}
// }