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

ERRORCODE DestroyMutex() {
	if (!ReleaseMutex(g_mutex))
		return CLEAN_HANDLE;

	return PANO_SUCCESS;
}
