#include "tray_notifications.h"
#include "utils.h"
#include <shellapi.h>
#include <strsafe.h>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <thread>

// How long each balloon stays up
#define PANO_BALLOON_MS 5000

// Notifications waiting to be shown. A burst of detections would otherwise queue minutes of
// balloons; beyond this many, the rest are summed into one "and N more" balloon
#define PANO_MAX_QUEUED_BALLOONS 4

struct Balloon {
	std::string Title;
	std::string Text;
};

static std::mutex g_Lock;
static std::condition_variable g_Wake;
static std::deque<Balloon> g_Queue;
static size_t g_Dropped = 0;
static bool g_WorkerStarted = false;

// Shows one balloon and keeps it up for PANO_BALLOON_MS
static void ShowBalloon(const Balloon& balloon)
{
	NOTIFYICONDATAA nid = {};
	nid.cbSize = sizeof(NOTIFYICONDATAA);
	nid.hWnd = GetActiveWindow(); // Or use your main window handle
	nid.uFlags = NIF_MESSAGE | NIF_ICON | NIF_TIP | NIF_INFO;
	nid.uTimeout = PANO_BALLOON_MS;
	nid.dwInfoFlags = NIIF_INFO | NIIF_USER;
	nid.uVersion = NOTIFYICON_VERSION_4;
	// Relative to the executable, not the current directory, which depends on how the service
	// was started
	std::string icon = GetExecutableDirectory() + "\\assets\\panoptes-head.ico";
	nid.hIcon = (HICON)LoadImageA(NULL, icon.c_str(), IMAGE_ICON, 128, 128, LR_LOADFROMFILE | LR_SHARED);
	if (nid.hIcon == NULL) {
		return;
	}

	// StringCchCopy truncates rather than fails the balloon when a text is too long
	StringCchCopyA(nid.szInfoTitle, ARRAYSIZE(nid.szInfoTitle), balloon.Title.c_str());
	StringCchCopyA(nid.szTip, ARRAYSIZE(nid.szTip), "Panoptes EDR");
	StringCchCopyA(nid.szInfo, ARRAYSIZE(nid.szInfo), balloon.Text.c_str());

	Shell_NotifyIconA(NIM_ADD, &nid);
	Sleep(PANO_BALLOON_MS);
	Shell_NotifyIconA(NIM_DELETE, &nid);
}

// Shows queued balloons one at a time, so callers never wait for one to finish
static void BalloonThread()
{
	for (;;) {
		Balloon next;
		{
			std::unique_lock<std::mutex> lock(g_Lock);
			g_Wake.wait(lock, [] { return !g_Queue.empty() || g_Dropped > 0; });
			if (!g_Queue.empty()) {
				next = std::move(g_Queue.front());
				g_Queue.pop_front();
			}
			else {
				next.Title = "Panoptes EDR Detection";
				next.Text = std::to_string(g_Dropped) + " more detections. See C:\\ProgramData\\Panoptes\\Logs";
				g_Dropped = 0;
			}
		}
		ShowBalloon(next);
	}
}

BOOL TrayNotifications::Tray::ShowTrayIconBalloon(LPCSTR pszTitle, LPCSTR pszText)
{
	std::lock_guard<std::mutex> guard(g_Lock);
	if (!g_WorkerStarted) {
		// Detached: it only ever waits or shows a balloon, and ends with the process
		std::thread(BalloonThread).detach();
		g_WorkerStarted = true;
	}
	if (g_Queue.size() >= PANO_MAX_QUEUED_BALLOONS) {
		g_Dropped++;
	}
	else {
		g_Queue.push_back({ pszTitle, pszText });
	}
	g_Wake.notify_one();
	return TRUE;
}
