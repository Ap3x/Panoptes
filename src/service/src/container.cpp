#include <format>
//#include "message.hpp"
//#include "score.hpp"
#include "hash.hpp"
#include "container.hpp"
#include "ResourceCore.h"

#define BUFFER_SIZE 4096
#define BUFSIZE 4096

using namespace std;

//VOID IdentifyContainerConnection(PanoptesMessage::ContainerType containerType) {
//	if (containerType == Message::CONTAINER_TYPE_AMSI) {
//		serviceContext->LogInformationMessage("Container Connected: AMSI/YARA");
//	}
//	else if (containerType == Message::CONTAINER_TYPE_PE) {
//		serviceContext->LogInformationMessage("Container Connected: PE");
//	}
//	else if (containerType == Message::CONTAINER_TYPE_ML) {
//		serviceContext->LogInformationMessage("Container Connected: ML");
//	}
//	return;
//}
//
//BOOL SendHelloToContainer(Pipe::PIPEINST* pipe)
//{
//	DWORD bytesWritten;
//	PanoptesMessage::PipeData* data;
//	data->set_sender(PanoptesMessage::SENDER_SERVICE);
//	data->set_message_type(PanoptesMessage::MSG_TYPE_HELLO);
//
//	BOOL fSuccess = WriteFile(
//		pipe->pipeInst,
//		data,
//		MESSAGE_SIZE,
//		&bytesWritten,
//		&pipe->overlap);
//
//	return fSuccess;
//}
//
//
//BOOL ConnectToNewClient(ThreadContext* threadContext, HANDLE hPipe, LPOVERLAPPED lpo)
//{
//	serviceContext = threadContext->serviceContext;
//	BOOL fConnected, pendingIO = FALSE;
//	 Start an overlapped connection for this pipe instance. 
//	fConnected = ConnectNamedPipe(hPipe, lpo);
//
//	 Overlapped ConnectNamedPipe should return zero. 
//	if (fConnected)
//	{
//		string message = format("Error creating an overlapped connection {}", GetLastError());
//		serviceContext->LogErrorMessage(message);
//		return 0;
//	}
//
//	 //Set the read mode to blocking
//	DWORD dwMode = PIPE_READMODE_MESSAGE;
//	BOOL success = SetNamedPipeHandleState(
//		hPipe,
//		&dwMode,
//		NULL,
//		NULL);
//
//	switch (GetLastError())
//	{
//		 The overlapped connection in progress. 
//	case ERROR_IO_PENDING:
//		pendingIO = TRUE;
//		break;
//
//		 Client is already connected, so signal an event. 
//
//	case ERROR_PIPE_CONNECTED:
//		if (SetEvent(lpo->hEvent))
//			break;
//
//		 //If an error occurs during the connect operation... 
//	default:
//	{
//		string message = format("Error creating an overlapped connection {}", GetLastError());
//		serviceContext->LogErrorMessage(message);
//		return 0;
//	}
//	}
//
//	return pendingIO;
//}
//DWORD StartContainerNamedPipe()
//{
//	//ThreadContext* threadContext = static_cast<ThreadContext*>(lpParams);
//	//ServiceContext* serviceContext = threadContext->serviceContext;
//	Pipe* pipe = threadContext->pipeInstance;
//
//	DWORD pipeIndex, dwWait;
//	BOOL fSuccess;
//
//	if (!StartContainerInstances(4)) {
//		string message = format("Error creating {} container named pipes: {}", INSTANCES, threadContext->namedPipe.c_str());
//		serviceContext->LogErrorMessage(message);
//		exit(1);
//	}
//
//	string message = format("Created {} container named pipes: {}", INSTANCES, threadContext->namedPipe.c_str());
//	serviceContext->LogInformationMessage(message);
//	PanoptesMessage::PipeData* responseData;
//	//Message::PipeData* responseData;
//	while (1)
//	{
//		dwWait = WaitForMultipleObjects(
//			INSTANCES,		// number of event objects 
//			pipe->hEvents,      // array of event objects 
//			FALSE,        // does not wait for all 
//			INFINITE);    // waits indefinitely 
//
//		pipeIndex = dwWait - WAIT_OBJECT_0;  // determines which pipe 
//		if (pipeIndex < 0 || pipeIndex >(INSTANCES - 1))
//		{
//			string message = format("Error out of range when creating {} container named pipes: {}", INSTANCES, threadContext->namedPipe.c_str());
//			serviceContext->LogErrorMessage(message);
//			return 0;
//		}
//
//		std::string serialized_data;
//		PanoptesMessage::PipeData data;
//		DWORD totalBytesRead = 0;
//		DWORD error = 0;
//		BOOL initCheck = false;
//		switch (pipe->PipeInst[pipeIndex].state)
//		{
//		case CONNECTING_STATE:
//			pipe->PipeInst[pipeIndex].state = READING_STATE;
//			break;
//		case READING_STATE:
//
//			uint32_t size;
//			DWORD bytesRead;
//			initCheck = ReadFile(pipe->PipeInst[pipeIndex].pipeInst, &size, sizeof(size), &bytesRead, &pipe->PipeInst[pipeIndex].overlap);
//			error = GetLastError();
//			if (!initCheck && error != ERROR_MORE_DATA) {
//				exit(1);
//			}
//			char buffer[BUFFER_SIZE];
//			while (totalBytesRead < size) {
//				DWORD bytesToRead = min(BUFFER_SIZE, size - totalBytesRead);
//				fSuccess = ReadFile(pipe->PipeInst[pipeIndex].pipeInst, buffer, bytesToRead, &bytesRead, &pipe->PipeInst[pipeIndex].overlap);
//				serialized_data.append(buffer, bytesRead);
//				totalBytesRead += bytesRead;
//			}
//			data.ParseFromString(serialized_data);
//				//person.ParseFromString(serialized_data)
//				//fSuccess = ReadFile(
//				//	pipe->PipeInst[pipeIndex].pipeInst,
//				//	responseData,
//				//	MESSAGE_SIZE,
//				//	&pipe->PipeInst[pipeIndex].bytesRead,
//				//	&pipe->PipeInst[pipeIndex].overlap);
//			
//			if (data.sender() == PanoptesMessage::SENDER_CONTAINER) {
//				if (data.message_type() == PanoptesMessage::MSG_TYPE_HELLO) {
//					pipe->PipeInst[pipeIndex].containerType = responseData->container_type();
//					IdentifyContainerConnection(responseData->container_type());
//					pipe->PipeInst[pipeIndex].state = WRITING_STATE;
//					break;
//				}
//				else if (responseData->message_type() == PanoptesMessage::MSG_TYPE_PROCESSED) {
//					string filePath = responseData->container_data().file_path();
//					if (filePath.length() > 4) {
//						string hash = Hash::Generate(filePath.c_str());
//						if (hash == "")
//						{
//							serviceContext->LogErrorMessage("Error generating file hash");
//						}
//						else {
//							Database::PPanoptesDBEntry entry = serviceContext->GetEntry(hash);
//
//							if (pipe->PipeInst[pipeIndex].containerType == Message::CONTAINER_TYPE_AMSI) {
//								//INT score = Score::GenerateAMSIScore(responseData->ContainerData.StatusCode);
//								INT score = 0;
//								if (entry == NULL) {
//									entry = serviceContext->BuildEntry(score, Message::CONTAINER_TYPE_AMSI);
//									serviceContext->AddEntry(hash, entry);
//								}
//								else {
//									serviceContext->ModifyEntryScore(entry, score, Message::CONTAINER_TYPE_AMSI);
//									serviceContext->UpdateEntry(hash, entry);
//								}
//							}
//							else if (pipe->PipeInst[pipeIndex].containerType == Message::CONTAINER_TYPE_PE)
//							{
//								//INT score = Score::GeneratePEScore(responseData->ContainerData.StatusCode);
//								INT score = 0;
//								if (entry == NULL) {
//									entry = serviceContext->BuildEntry(score, Message::CONTAINER_TYPE_PE);
//									serviceContext->AddEntry(hash, entry);
//								}
//								else {
//									serviceContext->ModifyEntryScore(entry, score, Message::CONTAINER_TYPE_PE);
//									serviceContext->UpdateEntry(hash, entry);
//								}
//							}
//
//							if (entry != NULL) {
//								bool allExtCheckDone = true;
//								int combinedScore = 0;
//								for (int i = 0; i < serviceContext->m_extensibilityListName.size(); i++) {
//									if (serviceContext->m_extensibilityListName[i] == "AMSI") {
//										if (entry->amsiScore >= 0) {
//											combinedScore += entry->amsiScore;
//										}
//										else {
//											allExtCheckDone = false;
//										}
//									}
//									else if (serviceContext->m_extensibilityListName[i] == "YARA") {
//										if (entry->yaraScore >= 0) {
//											combinedScore += entry->yaraScore;
//										}
//										else {
//											allExtCheckDone = false;
//										}
//									}
//									else if (serviceContext->m_extensibilityListName[i] == "PE") {
//										if (entry->peScore >= 0) {
//											combinedScore += entry->peScore;
//										}
//										else {
//											allExtCheckDone = false;
//										}
//									}
//									else if (serviceContext->m_extensibilityListName[i] == "ML") {
//										if (entry->mlScore >= 0) {
//											combinedScore += entry->mlScore;
//										}
//										else {
//											allExtCheckDone = false;
//										}
//									}
//								}
//
//								if (allExtCheckDone) {
//									//TODO: get base name of file path 
//									string message = format("Scan Done - {} Score: {}", filePath.c_str(), combinedScore);
//									serviceContext->LogInformationMessage(message);
//									//Tray::Notification("Panoptes EDR", message);
//
//									//inject::InjectDLL(incomingRequest->ContainerData.ProcessId, "C:\\Users\\Research\\source\\repos\\PanoptesEDR\\bin\\x64\\Debug\\PanoptesHook_x64.dll");
//								}
//							}
//						}
//					}
//
//				}
//			}
//			//else {
//			//	free(responseData);
//			//}
//			break;
//		case WRITING_STATE:
//			if (responseData->sender() == Message::SENDER_CONTAINER && responseData->message_type() == Message::MSG_TYPE_HELLO) {
//				if (!SendHelloToContainer(&pipe->PipeInst[pipeIndex])) {
//					serviceContext->LogErrorMessage("Error sending HELLO message to container.");
//				}
//			}
//			pipe->PipeInst[pipeIndex].state = CONNECTING_STATE;
//			//free(responseData);
//			break;
//		}
//
//	}
//
//	return 0;
//}


//string GenerateGUID() {
//	GUID guid;
//	CoInitialize(NULL);
//
//	HRESULT hr = CoCreateGuid(&guid);
//
//	if (SUCCEEDED(hr)) {
//		char guid_string[37]; // 32 hex digits + 4 hyphens + null terminator
//		snprintf(guid_string, sizeof(guid_string),
//			"%08lx-%04hx-%04hx-%02hhx%02hhx-%02hhx%02hhx%02hhx%02hhx%02hhx%02hhx",
//			guid.Data1, guid.Data2, guid.Data3,
//			guid.Data4[0], guid.Data4[1], guid.Data4[2], guid.Data4[3],
//			guid.Data4[4], guid.Data4[5], guid.Data4[6], guid.Data4[7]);
//		CoUninitialize();
//		return std::string(guid_string);
//	}
//
//
//	CoUninitialize();
//	return ""; // Return empty string if GUID creation failed
//}

//ERRORCODE Container::CreateEvents()
//{
//	for (int i = 0; i < m_extensibilityListName.size(); i++)
//	{
//		string ranGUID = GenerateGUID();
//		m_eventNames.push_back(ranGUID);
//		string eventName = "Global\\" + m_eventNames[i]; // Use a unique name
//		m_Events[i] = CreateEvent(
//			NULL,				// default security attribute 
//			TRUE,				// manual-reset event 
//			TRUE,				// initial state = signaled 
//			eventName.c_str()	// event name
//		);
//
//		if (m_Events[i] == NULL)
//		{
//			//string message = format("Failed to create an container event: {}", GetLastError());
//			//LogErrorMessage(message);
//			return CONTAINER_START;
//		}
//	}
//
//	return SUCCESS;
//}

//DWORD WINAPI Container::InstanceThread(LPVOID lpvParam) {
//	PanoptesMessage::ContainerMessage request;
//	DWORD cbBytesRead = 0, cbReplyBytes = 0, cbWritten = 0;
//	BOOL fSuccess = FALSE;
//
//	if (lpvParam == NULL) {
//		printf("\nERROR - Pipe Server Failure:\n");
//		printf("   InstanceThread got an unexpected NULL value in lpvParam.\n");
//		printf("   InstanceThread exiting.\n");
//		return (DWORD)-1;
//	}
//
//	ServiceContext* serviceContext = (ServiceContext*)lpvParam;
//	char buffer[1024];  // Adjust size as needed
//
//	fSuccess = ReadFile(
//		serviceContext->m_pipeInst,        // handle to pipe 
//		buffer,       // buffer to receive data 
//		sizeof(buffer), // size of buffer 
//		&cbBytesRead, // number of bytes read 
//		NULL);        // not overlapped I/O 
//
//	if (!fSuccess || cbBytesRead == 0) {
//		if (GetLastError() == ERROR_BROKEN_PIPE) {
//			printf("InstanceThread: client disconnected.\n");
//		}
//		else {
//			printf("InstanceThread ReadFile failed, GLE=%d.\n", GetLastError());
//		}
//		CloseHandle(serviceContext->m_pipeInst);
//		return (DWORD)-1;
//	}
//
//	if (!request.ParseFromArray(buffer, cbBytesRead)) {
//		printf("Failed to parse the received message.\n");
//		CloseHandle(serviceContext->m_pipeInst);
//		return (DWORD)-1;
//	}
//
//	PanoptesMessage::ContainerMessage reply;
//	std::string serialized_reply;
//
//	if (request.message_type() == PanoptesMessage::MessageType::MSG_TYPE_GET_EVENT) {
//		reply.set_message_type(request.message_type());
//		reply.set_event_name(serviceContext->m_eventNames[0]);
//		if (!reply.SerializeToString(&serialized_reply)) {
//			printf("Failed to serialize the reply message.\n");
//			CloseHandle(serviceContext->m_pipeInst);
//			return (DWORD)-1;
//		}
//	}
//	else {
//		printf("Unsupported message type received.\n");
//		CloseHandle(serviceContext->m_pipeInst);
//		return (DWORD)-1;
//	}
//
//	fSuccess = WriteFile(
//		serviceContext->m_pipeInst,        // handle to pipe 
//		serialized_reply.c_str(),     // buffer to write from 
//		serialized_reply.size(), // number of bytes to write 
//		&cbWritten,   // number of bytes written 
//		NULL);        // not overlapped I/O 
//
//	if (!fSuccess || cbWritten != serialized_reply.size()) {
//		printf("InstanceThread WriteFile failed, GLE=%d.\n", GetLastError());
//		CloseHandle(serviceContext->m_pipeInst);
//		return (DWORD)-1;
//	}
//
//	FlushFileBuffers(serviceContext->m_pipeInst);
//	DisconnectNamedPipe(serviceContext->m_pipeInst);
//	CloseHandle(serviceContext->m_pipeInst);
//	return 1;
//}

//DWORD WINAPI Container::CreateThreadRequest(LPVOID lpvParam) {
//	ServiceContext* serviceContext = (ServiceContext*)lpvParam;
//	BOOL fConnected = ConnectNamedPipe(serviceContext->m_pipeInst, NULL) ?
//		TRUE : (GetLastError() == ERROR_PIPE_CONNECTED);
//
//	if (fConnected)
//	{
//		HANDLE hPipe = NULL;
//		DWORD  dwThreadId = 0;
//		// Create a thread for this client. 
//		HANDLE hThread = CreateThread(
//			NULL,              // no security attribute 
//			0,                 // default stack size 
//			InstanceThread,    // thread proc
//			(LPVOID)serviceContext,    // thread parameter 
//			0,                 // not suspended 
//			&dwThreadId);      // returns thread ID 
//
//		if (hThread == NULL)
//		{
//			printf("CreateThread failed, GLE=%d.\n", GetLastError());
//			return NOT_SET;
//		}
//		else CloseHandle(hThread);
//	}
//
//	return SUCCESS;
//}





