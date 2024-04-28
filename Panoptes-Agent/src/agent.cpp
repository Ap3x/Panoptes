#include "framework.h"
#include "pe.hpp"
#include "utils.hpp"
#include "pipe.hpp"
#include <wchar.h>
#include <shellapi.h>
#include "inject.hpp"
#include <strsafe.h>
#include "vt_yara.hpp"


vt_yara obj;

typedef struct _THREAD_DATA {
	YR_COMPILER* compiler;
	YR_RULES* rules;
	HANDLE kernelNamedPipe;
} THREAD_DATA, * PTHREAD_DATA;

BOOL IsExclusion(LPCWSTR FullPath) {
	LPCWSTR exclusionList[] =
	{
		L"C:\\Windows",
		L"C:\\Program Files",
		L"C:\\Program Files (x86)"
	};

	//No Exclusions Set
	//LPCTSTR exclusionList[] = { 0 };

	if (exclusionList[0] == NULL)
	{
		return false;
	}

	for (int i = 0; i < sizeof(exclusionList) / sizeof(LPCWSTR); i++)
	{
		if (wcsstr(FullPath, exclusionList[i]) != 0) {
			//If in Exclusion list then ignore
			return true;
		}
	}
	//If not in exclusion list then continue with checks
	return false;
}

void ShowTrayNotification(const std::string& title, const std::string& message)
{
	// Register the window class
	WNDCLASSEXW wcex = { sizeof(WNDCLASSEXW) };
	wcex.lpfnWndProc = DefWindowProc;
	wcex.hInstance = GetModuleHandleW(nullptr);
	wcex.lpszClassName = L"TrayNotificationClass";
	RegisterClassExW(&wcex);

	HWND hwnd = CreateWindowExW(0, L"TrayNotificationClass", L"", 0, 0, 0, 0, 0, HWND_MESSAGE, nullptr, nullptr, nullptr);

	// Set up the notification data
	NOTIFYICONDATA nid = { sizeof(NOTIFYICONDATA) };
	nid.uID = 1;      // Unique identifier for the notification icon
	nid.hWnd = hwnd;
	nid.uFlags = NIF_INFO | NIF_MESSAGE;
	nid.uCallbackMessage = WM_USER + 1;
	nid.uTimeout = 5000; // Display for 5 seconds
	nid.dwInfoFlags = NIIF_INFO;

	HICON hIcon = LoadIcon(NULL, MAKEINTRESOURCEA(101));
	nid.hIcon = hIcon;

	std::wstring wideTitle(title.begin(), title.end());
	std::wstring wideMessage(message.begin(), message.end());

	wcscpy_s(nid.szInfoTitle, sizeof(nid.szInfoTitle) / sizeof(WCHAR), wideTitle.c_str());
	wcscpy_s(nid.szInfo, sizeof(nid.szInfo) / sizeof(WCHAR), wideMessage.c_str());

	// Show the notification
	Shell_NotifyIcon(NIM_ADD, &nid);
}

//https://learn.microsoft.com/en-us/windows/win32/ipc/multithreaded-pipe-server
VOID GetAnswerToRequest(LPCWSTR pchRequest, LPCWSTR pchReply, LPDWORD pchBytes, YR_COMPILER * compilerThread, YR_RULES * rulesThread)
{
	LPCWSTR decisionStr = L"OK";
	PREQUEST req = (PREQUEST)malloc(sizeof(REQUEST));

	pipe::ParseRequest(pchRequest, req);

	if (wcscmp(req->Path, L"") != 0) {
		//If its NOT in an exclusion folder
		if (!IsExclusion(req->Path)) {
			//wprintf(L"Checking Process (%d): \"%s\"\n"), req->PID, req->Path);

			//If signed by Microsoft then its trusted
			if (pe::VerifyEmbeddedSignature(req->Path)) {
				//wprintf(L"[+] PE has a good signature\n");
				wprintf(L"[+] In Signer Exclusion (%d): \"%s\"\n", req->PID, req->Path);
				decisionStr = L"OK";
			}
			else
			{
				//wprintf(L"[!] PE is not signed and verified\n"));
				//if (token::GetProcessTokenInfo(pid)) {
				//	printf("[!] Process (%d) has \"SeDebugPrivilege\"\n", pid);
				//}
				LPCWSTR message[MAX_PATH];

				int peScore = pe::CheckForImportFunctions(req->Path);
				if (peScore > 12) {

					if (vt_yara::StaticScan(req->Path, compilerThread, rulesThread)) {
						wprintf(L"[!] VIRUS DETECTED (%s)(%d): Caught by Yara Rules\n", req->Path, req->PID);
						wsprintfW((LPWSTR)message, L"VIRUS DETECTED: (%s)(%d) Caught by Yara Rules", req->BaseName, req->PID);
						ShowTrayNotification("Panoptes", utils::LPTSTRToString((LPWSTR)message));
						decisionStr = L"NO";
					}
					else {
						wprintf(L"[-] Suspicious File: (%s)(%d) IAT Scored: %d\n", req->Path, req->PID, peScore);
						wsprintfW((LPWSTR)message, L"Suspicious File (%s)(%d):\nIAT Score: %d", req->BaseName, req->PID, peScore);
						ShowTrayNotification("Panoptes", utils::LPTSTRToString((LPWSTR)message));
						decisionStr = L"OK";
					}

				}
				else if (peScore == -1) {
					wprintf(L"[-] Suspicious File (%s)(%d): No Imports\n", req->Path, req->PID);
					wsprintfW((LPWSTR)message, L"Suspicious File (%s)(%d):\nNo Imports", req->BaseName, req->PID);
					ShowTrayNotification("Panoptes", utils::LPTSTRToString((LPWSTR)message));
					decisionStr = L"NO";
				}
				else {
					if (vt_yara::StaticScan(req->Path, compilerThread, rulesThread)) {
						wprintf(L"[!] VIRUS DETECTED (%s)(%d): Caught by Yara Rules\n", req->BaseName, req->PID);
						wsprintfW((LPWSTR)message, L"VIRUS DETECTED: (%s)(%d) Caught by Yara Rules", req->BaseName, req->PID);
						ShowTrayNotification("Panoptes", utils::LPTSTRToString((LPWSTR)message));
						decisionStr = L"NO";
					}
					else {
						wprintf(L"[+] Clean Yara Scan (%s)(%d) IAT Scored: %d\n", req->Path, req->PID, peScore);
						wprintf(L"[+] Injecting DLL\n");
						inject::InjectDLL(req->PID);
						decisionStr = L"OK";
					}
				}
			}
		}
		else {
			//If its in an exclusion folder
			wprintf(L"[+] In Exclusion Folder (%d): \"%s\"\n", req->PID, req->Path);
			decisionStr = L"OK";
		}
	}
	else
	{
		wprintf(L"[!] Failed to get PE path for PID: %lu\n", req->PID);
		decisionStr = L"NO";
	}

	// Check the outgoing message to make sure it's not too long for the buffer.
	if (StringCchCopy((LPWSTR)pchReply, BUFFER_SIZE, decisionStr) != 0)
	{
		printf("StringCchCopy failed, no outgoing message.\n");
		return;
	}

	*pchBytes = (lstrlenW(pchReply) + 1) * sizeof(WCHAR);
}

DWORD WINAPI InstanceThread(LPVOID lpvParam)
{

	THREAD_DATA* data = (THREAD_DATA*)(lpvParam);

	HANDLE hHeap = GetProcessHeap();
	LPCWSTR pchRequest = (LPCWSTR)HeapAlloc(hHeap, 0, BUFFER_SIZE * sizeof(WCHAR));
	LPCWSTR pchReply = (LPCWSTR)HeapAlloc(hHeap, 0, BUFFER_SIZE * sizeof(WCHAR));

	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
	BOOL fSuccess = FALSE;
	HANDLE hPipe = data->kernelNamedPipe;

	if (lpvParam == NULL)
	{
		printf("\nERROR - Pipe Server Failure:\n");
		printf("   InstanceThread got an unexpected NULL value in lpvParam.\n");
		printf("   InstanceThread exitting.\n");
		if (pchReply != NULL) {
			HeapFree(hHeap, 0, (LPVOID)pchReply);
		}
		if (pchRequest != NULL) {
			HeapFree(hHeap, 0, (LPVOID)pchRequest);
		}
		return (DWORD)-1;
	}

	if (pchRequest == NULL)
	{
		printf("\nERROR - Pipe Server Failure:\n");
		printf("   InstanceThread got an unexpected NULL heap allocation.\n");
		printf("   InstanceThread exitting.\n");
		if (pchReply != NULL){
			HeapFree(hHeap, 0, (LPVOID)pchReply);
		}
		return (DWORD)-1;
	}

	if (pchReply == NULL)
	{
		printf("\nERROR - Pipe Server Failure:\n");
		printf("   InstanceThread got an unexpected NULL heap allocation.\n");
		printf("   InstanceThread exitting.\n");
		if (pchRequest != NULL) {
			HeapFree(hHeap, 0, (LPVOID)pchRequest);
		}
		return (DWORD)-1;
	}

	while (1)
	{
		fSuccess = ReadFile(
			hPipe,									  // handle to pipe 
			(LPVOID)pchRequest,					  // buffer to receive data 
			BUFFER_SIZE * sizeof(WCHAR), // size of buffer 
			&cbBytesRead,				  // number of bytes read 
			NULL);							  // not overlapped I/O 

		if (!fSuccess || cbBytesRead == 0)
		{
			if (GetLastError() == ERROR_BROKEN_PIPE)
			{
				//wprintf(L"InstanceThread: client disconnected.\n"));
			}
			else
			{
				wprintf(L"InstanceThread ReadFile failed, GLE=%d.\n", GetLastError());
			}
			break;
		}

		// Process the incoming message.
		GetAnswerToRequest(pchRequest, pchReply, &cbReplyBytes, data->compiler, data->rules);

		// Write the reply to the pipe. 
		fSuccess = WriteFile(
			hPipe,						// handle to pipe 
			pchReply,				// buffer to write from 
			cbReplyBytes, // number of bytes to write 
			&cbWritten,  // number of bytes written 
			NULL);			   // not overlapped I/O 

		if (fSuccess != 0 && cbReplyBytes != cbWritten)
		{
			wprintf(L"InstanceThread WriteFile failed, GLE=%d.\n", GetLastError());
			break;
		}

		// Flush the pipe to allow the client to read the pipe's contents 
		// before disconnecting. Then disconnect the pipe, and close the 
		// handle to this pipe instance. 

		FlushFileBuffers(hPipe);

		HeapFree(hHeap, 0, (LPVOID)pchRequest);
		HeapFree(hHeap, 0, (LPVOID)pchReply);
	}

	DisconnectNamedPipe(hPipe);
	CloseHandle(hPipe);

	//printf("InstanceThread exiting.\n");
	return 1;
}

int main()
{
	BOOL   fConnected = FALSE;
	DWORD  dwThreadId = 0;
	HANDLE hPipe = INVALID_HANDLE_VALUE, hThread = NULL;
	LPCWSTR lpszPipename = PIPE_NAME;
	yr_initialize();
	yr_compiler_create(&(obj.compiler));
	obj.CompileYaraRules(RULES_FOLDER, obj.compiler);
	if (yr_compiler_get_rules(obj.compiler, &(obj.rules)) != ERROR_SUCCESS)
	{
		yr_compiler_destroy(obj.compiler);
		printf("Error compiling Yara Rules");
		yr_finalize();
		exit(1);
	}

	for (;;)
	{
		//wprintf(L"\nPipe Server: Main thread awaiting client connection on %s\n"), lpszPipename);
		hPipe = CreateNamedPipeW(
			lpszPipename,             // pipe name 
			PIPE_ACCESS_DUPLEX,       // read/write access 
			PIPE_TYPE_MESSAGE |       // message type pipe 
			PIPE_READMODE_MESSAGE |   // message-read mode 
			PIPE_WAIT,                // blocking mode 
			PIPE_UNLIMITED_INSTANCES, // max. instances  
			BUFFER_SIZE,              // output buffer size 
			BUFFER_SIZE,              // input buffer size 
			0,                        // client time-out 
			NULL);                    // default security attribute 

		if (hPipe == INVALID_HANDLE_VALUE)
		{
			wprintf(L"CreateNamedPipe failed, GLE=%d.\n", GetLastError());
			return -1;
		}

		fConnected = ConnectNamedPipe(hPipe, NULL) ?
			TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);

		if (fConnected)
		{
			// printf("Client connected, creating a processing thread.\n");
			THREAD_DATA* data = new THREAD_DATA;
			data->compiler = obj.compiler;
			data->rules = obj.rules;
			data->kernelNamedPipe = hPipe;

			hThread = CreateThread(
				NULL,		// no security attribute 
				0,				// default stack size 
				InstanceThread,	// thread proc
				data,				// thread parameter 
				0,				// not suspended 
				&dwThreadId);		// returns thread ID 

			if (hThread == NULL)
			{
				wprintf(L"CreateThread failed, GLE=%d.\n", GetLastError());
				return -1;
			}
			else CloseHandle(hThread);
			if (!FlushFileBuffers(hPipe)) {
				printf("Error flushing named pipe: 0x%lx", GetLastError());
				CloseHandle(hPipe);
				return 1;
			}
		}
		else
			// The client could not connect, so close the pipe. 
			CloseHandle(hPipe);
	}

	return 0;
}