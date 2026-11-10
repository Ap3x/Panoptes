#pragma once
// Event definitions shared between the Panoptes driver and the Panoptes service.
// The driver completes IOCTL_PANOPTES_GET_EVENT with one event per request: a
// PANO_EVENT_HEADER followed by the data for that event's type. Only fixed-size
// types are used so the kernel and user mode builds agree on the layout.

#ifdef _KERNEL_MODE
#include <wdm.h>
#else
#include <Windows.h>
#include <winioctl.h>
#endif

#define PANOPTES_DEVICE_NAME      L"\\Device\\Panoptes"
#define PANOPTES_SYMLINK_NAME     L"\\DosDevices\\Panoptes"
#define PANOPTES_USER_DEVICE_PATH L"\\\\.\\Panoptes"

/// @brief Waits for and returns the next event from the driver
#define IOCTL_PANOPTES_GET_EVENT CTL_CODE(FILE_DEVICE_UNKNOWN, 0x800, METHOD_BUFFERED, FILE_READ_ACCESS)

/// @brief Terminates a process. The input buffer is a PANO_TERMINATE_PROCESS
#define IOCTL_PANOPTES_TERMINATE_PROCESS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x900, METHOD_BUFFERED, FILE_ANY_ACCESS)

typedef struct _PANO_TERMINATE_PROCESS {
	UINT64 ProcessId;
} PANO_TERMINATE_PROCESS, * PPANO_TERMINATE_PROCESS;

/// @brief Replaces the driver's list of process image names that the hook DLL is not injected
/// into (the DontInject setting). The input buffer is a PANO_INJECTION_EXCLUSIONS. The list
/// applies to processes that have not been injected yet; it does not unload the DLL from
/// processes that already have it
#define IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x901, METHOD_BUFFERED, FILE_WRITE_ACCESS)

/// @brief The most names a PANO_INJECTION_EXCLUSIONS may hold
#define PANO_MAX_INJECTION_EXCLUSIONS 1024

/// @brief The longest name, in WCHARs not counting its terminator, a PANO_INJECTION_EXCLUSIONS
/// may hold. A UNICODE_STRING's limit, since full paths are compared as one
#define PANO_MAX_INJECTION_EXCLUSION_LENGTH (0xFFFE / 2)

/// @brief The input of IOCTL_PANOPTES_SET_INJECTION_EXCLUSIONS. Each name is either:
/// - an image file name with no \, such as L"msedge.exe", matching that file in any folder, or
/// - a full NT image path starting with \, such as L"\\Device\\HarddiskVolume3\\Tools\\a.exe",
///   matching only that file. The service converts DOS paths (C:\...) to this form.
/// Both are compared without regard to case. The buffer is exactly
/// FIELD_OFFSET(PANO_INJECTION_EXCLUSIONS, Names) bytes plus the names; a Count of 0 clears the list
typedef struct _PANO_INJECTION_EXCLUSIONS {
	/// @brief The number of names in Names
	UINT32 Count;
	/// @brief Count non-empty, null-terminated names, back to back
	WCHAR Names[1];
} PANO_INJECTION_EXCLUSIONS, * PPANO_INJECTION_EXCLUSIONS;

/// @brief The output buffer size the service passes with IOCTL_PANOPTES_GET_EVENT. The driver
/// never returns an event larger than this. It is sized so that every event carrying the
/// longest possible names fits whole (see the static_asserts at the end of this file), so names
/// and command lines are never truncated in practice. Events are queued at their actual size,
/// so this only sets the size of each GET_EVENT buffer
#define PANO_MAX_EVENT_SIZE (132 * 1024)

/// @brief The most WCHARs a UNICODE_STRING can hold (its Length is a USHORT byte count)
#define PANO_MAX_UNICODE_STRING_CHARS (0xFFFF / sizeof(WCHAR))

/// @brief The type of event, which determines the data that follows the header
enum PANO_EVENT_TYPE : UINT32 {
	PANO_EVENT_FILE_CREATED = 1,
	/// @brief No longer reported: opens of existing files are too frequent and filled the
	/// queue. Kept so the values that follow do not change
	PANO_EVENT_FILE_OPENED,
	PANO_EVENT_FILE_OVERWRITTEN,
	PANO_EVENT_FILE_SUPERSEDED,
	PANO_EVENT_FILE_WRITE,
	/// @brief A server created a named pipe, or another instance of one (CreateNamedPipe)
	PANO_EVENT_NAMED_PIPE_CREATE,
	/// @brief A client connected to a named pipe (CreateFile on \\.\pipe\...)
	PANO_EVENT_NAMED_PIPE_OPEN,
	/// @brief A server created a mailslot (CreateMailslot)
	PANO_EVENT_MAILSLOT_CREATE,
	/// @brief A client opened a mailslot to write to it (CreateFile on \\.\mailslot\...)
	PANO_EVENT_MAILSLOT_OPEN,
	/// @brief A file was marked for deletion (a PANO_FILE_EVENT_DATA). The delete happens when the
	/// last handle closes and can still be cancelled before then
	PANO_EVENT_FILE_DELETE,
	/// @brief A file was renamed or moved (a PANO_RENAME_EVENT_DATA)
	PANO_EVENT_FILE_RENAME,
	/// @brief A process was created (a PANO_PROCESS_EVENT_DATA)
	PANO_EVENT_PROCESS_CREATED,
	/// @brief A process exited (a PANO_PROCESS_EVENT_DATA with only ProcessId set)
	PANO_EVENT_PROCESS_TERMINATED,
	/// @brief A handle that wrote to a file was closed (a PANO_FILE_MODIFIED_EVENT_DATA). One
	/// event covers every write made through the handle. A handle still writing after
	/// PANO_FILE_MODIFIED_INTERVAL_MS is reported early with PANO_FLAG_HANDLE_STILL_OPEN, and
	/// its counts start again
	PANO_EVENT_FILE_MODIFIED,
	/// @brief A file's security descriptor was changed (a PANO_FILE_EVENT_DATA). Length holds
	/// the SECURITY_INFORMATION flags saying which parts changed (owner, DACL, ...)
	PANO_EVENT_FILE_SECURITY_CHANGED,
	/// @brief A file's extended attributes were written (a PANO_FILE_EVENT_DATA). Length holds
	/// the size of the EA buffer that was set
	PANO_EVENT_FILE_EA_CHANGED
};

/// @brief How long a handle can keep writing before its PANO_EVENT_FILE_MODIFIED is sent
/// without waiting for it to close
#define PANO_FILE_MODIFIED_INTERVAL_MS 30000

/// @brief Bits of IOCTL_PANOPTES_SET_FILE_EVENTS: the groups of file system events the driver
/// reports. A group that is off is dropped at the start of its callbacks
enum PANO_FILE_EVENT_GROUP : UINT32 {
	/// @brief PANO_EVENT_FILE_CREATED / _OVERWRITTEN / _SUPERSEDED, and deletes through
	/// FILE_DELETE_ON_CLOSE
	PANO_FILE_EVENTS_CREATE = 0x1,
	/// @brief PANO_EVENT_FILE_MODIFIED
	PANO_FILE_EVENTS_WRITE = 0x2,
	/// @brief PANO_EVENT_FILE_DELETE and PANO_EVENT_FILE_RENAME
	PANO_FILE_EVENTS_DELETE_RENAME = 0x4,
	/// @brief Named pipes and mailslots being created by a server or connected to by a client
	PANO_FILE_EVENTS_PIPE_MAILSLOT = 0x8,
	/// @brief PANO_EVENT_FILE_SECURITY_CHANGED
	PANO_FILE_EVENTS_SECURITY = 0x10,
	/// @brief PANO_EVENT_FILE_EA_CHANGED
	PANO_FILE_EVENTS_EA = 0x20,
};

#define PANO_FILE_EVENTS_ALL 0x3F

/// @brief Sets which PANO_FILE_EVENT_GROUP bits are reported. The input buffer is a
/// PANO_FILE_EVENTS. Every group is on until the service sends this
#define IOCTL_PANOPTES_SET_FILE_EVENTS CTL_CODE(FILE_DEVICE_UNKNOWN, 0x902, METHOD_BUFFERED, FILE_WRITE_ACCESS)

typedef struct _PANO_FILE_EVENTS {
	/// @brief PANO_FILE_EVENT_GROUP bits. Bits outside PANO_FILE_EVENTS_ALL are rejected
	UINT32 Enabled;
} PANO_FILE_EVENTS, * PPANO_FILE_EVENTS;

/// @brief The header at the start of every IOCTL_PANOPTES_GET_EVENT response
typedef struct _PANO_EVENT_HEADER {
	/// @brief Total size in bytes of the response, header plus event data
	UINT32 Size;
	/// @brief A PANO_EVENT_TYPE describing the data that follows the header
	UINT32 Type;
	/// @brief When the event occurred, in FILETIME units (UTC)
	INT64 Timestamp;
	/// @brief Number of events dropped since the previous response because they could not be
	/// queued: the queue was full, the event was too large, or it could not be allocated
	UINT32 Dropped;
	/// @brief Number of events dropped since the previous response because no service was
	/// reading events, e.g. while it was stopped or restarting. The driver does not buffer
	/// events for a service that is not connected
	UINT32 DroppedNoConsumer;
} PANO_EVENT_HEADER, * PPANO_EVENT_HEADER;

#define PANO_FLAG_OPLOCKED         0x1
#define PANO_FLAG_COMPRESSED       0x2
#define PANO_FLAG_NAME_TRUNCATED   0x4
/// @brief PANO_EVENT_FILE_DELETE: the file was opened with FILE_DELETE_ON_CLOSE rather than
/// having its delete disposition set
#define PANO_FLAG_DELETE_ON_CLOSE  0x8
/// @brief PANO_EVENT_FILE_RENAME: the rename replaced an existing file at the destination
#define PANO_FLAG_REPLACE_EXISTING 0x10
/// @brief PANO_EVENT_PROCESS_CREATED: the command line was truncated to fit the event
#define PANO_FLAG_COMMAND_LINE_TRUNCATED 0x20
/// @brief PANO_EVENT_FILE_MODIFIED: sent while the handle is still open and writing, so the
/// file may not be complete yet
#define PANO_FLAG_HANDLE_STILL_OPEN 0x40

/// @brief The data for file, named pipe and mailslot events
typedef struct _PANO_FILE_EVENT_DATA {
	UINT64 ProcessId;
	UINT64 ThreadId;
	/// @brief Offset of the write, PANO_EVENT_FILE_WRITE only
	INT64 FileOffset;
	/// @brief Length of the write, PANO_EVENT_FILE_WRITE only
	UINT32 Length;
	/// @brief PANO_FLAG_* values
	UINT32 Flags;
	/// @brief Length of FileName in WCHARs. FileName is not null terminated
	UINT32 NameLength;
	WCHAR FileName[1];
} PANO_FILE_EVENT_DATA, * PPANO_FILE_EVENT_DATA;

/// @brief The maximum number of WCHARs in PANO_FILE_EVENT_DATA::FileName so that the whole
/// response fits in PANO_MAX_EVENT_SIZE
#define PANO_MAX_FILE_NAME_LENGTH \
	((PANO_MAX_EVENT_SIZE - sizeof(PANO_EVENT_HEADER) - FIELD_OFFSET(PANO_FILE_EVENT_DATA, FileName)) / sizeof(WCHAR))

/// @brief The data for PANO_EVENT_FILE_MODIFIED
typedef struct _PANO_FILE_MODIFIED_EVENT_DATA {
	/// @brief The process and thread of the most recent write
	UINT64 ProcessId;
	UINT64 ThreadId;
	/// @brief Number of writes through the handle covered by this event
	UINT64 Writes;
	/// @brief Bytes written by those writes
	UINT64 Bytes;
	/// @brief When the first of those writes happened, in FILETIME units (UTC)
	INT64 FirstWriteTime;
	/// @brief PANO_FLAG_* values
	UINT32 Flags;
	/// @brief Length of FileName in WCHARs. FileName is not null terminated. It is the file's
	/// name when the event was sent, so it follows a rename made through any handle
	UINT32 NameLength;
	WCHAR FileName[1];
} PANO_FILE_MODIFIED_EVENT_DATA, * PPANO_FILE_MODIFIED_EVENT_DATA;

/// @brief The maximum number of WCHARs in PANO_FILE_MODIFIED_EVENT_DATA::FileName so that the
/// whole response fits in PANO_MAX_EVENT_SIZE
#define PANO_MAX_MODIFIED_FILE_NAME_LENGTH \
	((PANO_MAX_EVENT_SIZE - sizeof(PANO_EVENT_HEADER) - FIELD_OFFSET(PANO_FILE_MODIFIED_EVENT_DATA, FileName)) / sizeof(WCHAR))

/// @brief The data for PANO_EVENT_FILE_RENAME
typedef struct _PANO_RENAME_EVENT_DATA {
	UINT64 ProcessId;
	UINT64 ThreadId;
	/// @brief PANO_FLAG_* values
	UINT32 Flags;
	/// @brief Length of the original name in WCHARs
	UINT32 SourceNameLength;
	/// @brief Length of the new name in WCHARs
	UINT32 DestinationNameLength;
	/// @brief The original name immediately followed by the new name. Neither is null terminated
	WCHAR Names[1];
} PANO_RENAME_EVENT_DATA, * PPANO_RENAME_EVENT_DATA;

/// @brief The maximum combined number of WCHARs in both PANO_RENAME_EVENT_DATA names so that
/// the whole response fits in PANO_MAX_EVENT_SIZE
#define PANO_MAX_RENAME_NAMES_LENGTH \
	((PANO_MAX_EVENT_SIZE - sizeof(PANO_EVENT_HEADER) - FIELD_OFFSET(PANO_RENAME_EVENT_DATA, Names)) / sizeof(WCHAR))

/// @brief The data for PANO_EVENT_PROCESS_CREATED and PANO_EVENT_PROCESS_TERMINATED
typedef struct _PANO_PROCESS_EVENT_DATA {
	UINT64 ProcessId;
	/// @brief PANO_EVENT_PROCESS_CREATED only
	UINT64 ParentProcessId;
	/// @brief The process that created the new process, which can differ from the parent.
	/// PANO_EVENT_PROCESS_CREATED only
	UINT64 CreatingProcessId;
	/// @brief The thread that created the new process. PANO_EVENT_PROCESS_CREATED only
	UINT64 CreatingThreadId;
	/// @brief PANO_FLAG_* values. PANO_FLAG_NAME_TRUNCATED refers to the image name and
	/// PANO_FLAG_COMMAND_LINE_TRUNCATED to the command line
	UINT32 Flags;
	/// @brief Length of the image name in WCHARs. PANO_EVENT_PROCESS_CREATED only
	UINT32 ImageNameLength;
	/// @brief Length of the command line in WCHARs. PANO_EVENT_PROCESS_CREATED only
	UINT32 CommandLineLength;
	/// @brief The image name immediately followed by the command line. Neither is null terminated
	WCHAR Strings[1];
} PANO_PROCESS_EVENT_DATA, * PPANO_PROCESS_EVENT_DATA;

/// @brief The maximum combined number of WCHARs in the PANO_PROCESS_EVENT_DATA image name and
/// command line so that the whole response fits in PANO_MAX_EVENT_SIZE
#define PANO_MAX_PROCESS_STRINGS_LENGTH \
	((PANO_MAX_EVENT_SIZE - sizeof(PANO_EVENT_HEADER) - FIELD_OFFSET(PANO_PROCESS_EVENT_DATA, Strings)) / sizeof(WCHAR))

static_assert(sizeof(PANO_EVENT_HEADER) == 24, "PANO_EVENT_HEADER layout changed");
static_assert(FIELD_OFFSET(PANO_FILE_EVENT_DATA, FileName) == 36, "PANO_FILE_EVENT_DATA layout changed");
static_assert(FIELD_OFFSET(PANO_RENAME_EVENT_DATA, Names) == 28, "PANO_RENAME_EVENT_DATA layout changed");
static_assert(FIELD_OFFSET(PANO_FILE_MODIFIED_EVENT_DATA, FileName) == 48, "PANO_FILE_MODIFIED_EVENT_DATA layout changed");
static_assert(sizeof(PANO_FILE_EVENTS) == 4, "PANO_FILE_EVENTS layout changed");
static_assert(FIELD_OFFSET(PANO_PROCESS_EVENT_DATA, Strings) == 44, "PANO_PROCESS_EVENT_DATA layout changed");
static_assert(FIELD_OFFSET(PANO_INJECTION_EXCLUSIONS, Names) == 4, "PANO_INJECTION_EXCLUSIONS layout changed");

// Every name the driver reports comes from a UNICODE_STRING, so these guarantee no event is truncated
static_assert(PANO_MAX_FILE_NAME_LENGTH >= PANO_MAX_UNICODE_STRING_CHARS,
	"PANO_MAX_EVENT_SIZE too small for a full-length file name");
static_assert(PANO_MAX_MODIFIED_FILE_NAME_LENGTH >= PANO_MAX_UNICODE_STRING_CHARS,
	"PANO_MAX_EVENT_SIZE too small for a full-length modified file name");
static_assert(PANO_MAX_RENAME_NAMES_LENGTH >= 2 * PANO_MAX_UNICODE_STRING_CHARS,
	"PANO_MAX_EVENT_SIZE too small for two full-length rename names");
static_assert(PANO_MAX_PROCESS_STRINGS_LENGTH >= 2 * PANO_MAX_UNICODE_STRING_CHARS,
	"PANO_MAX_EVENT_SIZE too small for a full-length image name and command line");
