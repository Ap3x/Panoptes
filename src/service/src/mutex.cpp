#include "mutex.hpp"

HANDLE g_mutex;

ERRORCODE SetEnvironmentMutex() {
	g_mutex = CreateMutexA(
		NULL,
		FALSE,
		SERVICE_MUTEX
	);
	if (g_mutex == NULL)
	{
		return INVALID_INPUT;
	}

	return PANO_SUCCESS;
}

ERRORCODE MutexExist() {
	g_mutex = OpenMutexA(
		SYNCHRONIZE,  // Request full access
		FALSE,        // Do not inherit handle
		SERVICE_MUTEX     // Name of the mutex
	);
	if (g_mutex == NULL)
	{
		return MUTEX_NOT_SET;
	}

	return PANO_SUCCESS;
}

// The mutex is created unowned and only its name marks the service as running, so it is
// closed rather than released. Safe to call more than once
ERRORCODE DestroyMutex() {
	if (g_mutex == NULL)
		return PANO_SUCCESS;

	BOOL closed = CloseHandle(g_mutex);
	g_mutex = NULL;
	if (!closed)
		return CLEAN_HANDLE;

	return PANO_SUCCESS;
}
