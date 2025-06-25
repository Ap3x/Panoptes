#include "TrayNotifications.h"
#include "resource.h"
#include <shellapi.h>
#include <strsafe.h>

/// @brief Display a tray icon balloon notification
/// @param pszTitle The title of the notification
/// @param pszText The text of the notification
/// @return True if the notification was displayed successfully, false otherwise
BOOL TrayNotifications::Tray::ShowTrayIconBalloon(LPCSTR pszTitle, LPCSTR pszText)
{
	NOTIFYICONDATAA nid = {};
	nid.cbSize = sizeof(NOTIFYICONDATAA);
	nid.hWnd = GetActiveWindow(); // Or use your main window handle
	nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO;
	nid.uTimeout = 5000;
	nid.dwInfoFlags = NIIF_INFO | NIIF_USER ;
	nid.uVersion = NOTIFYICON_VERSION_4;
	nid.hIcon = (HICON)LoadImageA(
		NULL,
		"assets\\panoptes-head.ico",
		IMAGE_ICON,
		128,
		128,
		LR_LOADFROMFILE | LR_SHARED
	);

	if (nid.hIcon == NULL)
		return FALSE;

	if (StringCchCopyA(nid.szInfoTitle, 64, pszTitle) != S_OK)
		return FALSE;

	if (StringCchCopyA(nid.szTip, 128, "Panoptes EDR") != S_OK)
		return FALSE;

	if (StringCchCopyA(nid.szInfo, 256, pszText) != S_OK)
		return FALSE;

	Shell_NotifyIconA(NIM_ADD, &nid);
	Sleep(5000);
	return Shell_NotifyIconA(NIM_DELETE, &nid);
}

