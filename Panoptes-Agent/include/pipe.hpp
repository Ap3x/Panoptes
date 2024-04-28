#pragma once
#include "framework.h"
#include "utils.hpp"

#define PIPE_NAME L"\\\\.\\pipe\\Panoptes"
#define BUFFER_SIZE 1024

typedef struct _REQUEST {
	LPCWSTR Path;
	DWORD PID;
	LPCWSTR BaseName;
} REQUEST, * PREQUEST;

class pipe {
public:
	static void ParseRequest(LPCWSTR Request, PREQUEST req);
	static VOID SendDetection();

};

