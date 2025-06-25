#pragma once
#include <Windows.h>
#include <string>

namespace TrayNotifications {
	/// @brief The Tray class that is used to display tray icon balloon notifications
	class Tray {
	public:
		/// @brief Display a tray icon balloon notification
		/// @param pszTitle The title of the notification
		/// @param pszText The text of the notification
		/// @return True if the notification was displayed successfully, false otherwise
		static BOOL ShowTrayIconBalloon(LPCSTR pszTitle, LPCSTR pszText);
	};
}
