package main

import (
	"time"

	"golang.org/x/sys/windows"
)

// runningProcessImage asks Windows for the image of a running process. matched is when the
// detection's last event happened: a process with this ID created after that is a different
// one that reused the ID, and gives "". So does a process that has exited or can't be opened.
func runningProcessImage(pid uint32, matched time.Time) string {
	h, err := windows.OpenProcess(windows.PROCESS_QUERY_LIMITED_INFORMATION, false, pid)
	if err != nil {
		return ""
	}
	defer windows.CloseHandle(h)

	var created, exited, kernel, user windows.Filetime
	if err := windows.GetProcessTimes(h, &created, &exited, &kernel, &user); err != nil {
		return ""
	}
	if time.Unix(0, created.Nanoseconds()).After(matched) {
		return ""
	}

	buf := make([]uint16, windows.MAX_LONG_PATH)
	size := uint32(len(buf))
	if err := windows.QueryFullProcessImageName(h, 0, &buf[0], &size); err != nil {
		return ""
	}
	return windows.UTF16ToString(buf[:size])
}
