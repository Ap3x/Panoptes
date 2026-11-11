#pragma once
#include <Windows.h>
#include <string>

namespace TrayNotifications {
	/// @brief The Tray class that is used to display tray icon balloon notifications
	class Tray {
	public:
		/// @brief Queues a tray icon balloon notification and returns at once. A background
		/// thread shows queued balloons one at a time, each for five seconds; in a burst, those
		/// beyond a few are summed into one "N more detections" balloon. The icon is
		/// assets\panoptes-head.ico next to the executable; without it nothing is shown
		/// @param pszTitle The title of the notification
		/// @param pszText The text of the notification
		/// @return TRUE (the notification was queued)
		static BOOL ShowTrayIconBalloon(LPCSTR pszTitle, LPCSTR pszText);
	};
}
