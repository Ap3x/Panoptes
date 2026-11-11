#include "pano_filter.h"
#include "event_queue.h"

// Noise is filtered at three levels:
//   1. Subscription: only the operations in Callbacks[] reach the filter at all. Some are
//      registered only as hooks for future events and pass straight through.
//   2. Registration flags: paging I/O, which flushes data an earlier operation already
//      reported, is filtered out before READ, WRITE and SET_INFORMATION callbacks run.
//   3. In-callback gates: each pre-operation callback first checks that its event group is
//      on (IOCTL_PANOPTES_SET_FILE_EVENTS) and that the operation is not from the service
//      itself. Returning FLT_PREOP_SUCCESS_NO_CALLBACK there means the post-operation
//      callback never runs and no name is ever looked up for the operation.

#define PANO_NAMED_CONTEXT_POOL_TAG 'nFoP'  // "PoFn"
#define PANO_HANDLE_CONTEXT_POOL_TAG 'hFoP' // "PoFh"

PFLT_FILTER g_FilterHandle;

// PANO_FILE_EVENT_GROUP bits that are reported. Every group is on until the service says otherwise
static volatile LONG g_EnabledFileEvents = PANO_FILE_EVENTS_ALL;

static BOOLEAN IsGroupEnabled(UINT32 Group)
{
	return (g_EnabledFileEvents & Group) != 0;
}

NTSTATUS FilterSetFileEvents(PVOID Buffer, ULONG Length)
{
	if (Buffer == NULL || Length < sizeof(PANO_FILE_EVENTS)) {
		return STATUS_INVALID_PARAMETER;
	}

	UINT32 enabled = ((PPANO_FILE_EVENTS)Buffer)->Enabled;
	if ((enabled & ~(UINT32)PANO_FILE_EVENTS_ALL) != 0) {
		return STATUS_INVALID_PARAMETER;
	}

	InterlockedExchange(&g_EnabledFileEvents, (LONG)enabled);
	DbgPrintEx(DPFLTR_IHVDRIVER_ID, DPFLTR_ERROR_LEVEL, "[+] Panoptes: File event groups set to 0x%X\n", enabled);
	return STATUS_SUCCESS;
}

#pragma region Contexts

// The first field of every completion context, so post-write can tell the two kinds apart
enum PANO_CONTEXT_KIND : ULONG {
	PANO_CONTEXT_HANDLE = 0x4C444E48, // 'HNDL': a PANO_HANDLE_CONTEXT
	PANO_CONTEXT_NAMED = 0x454D414E,  // 'NAME': a PANO_NAMED_CONTEXT
};

// Writes made through one handle (file object) since its last PANO_EVENT_FILE_MODIFIED. A
// stream handle context, so the filter manager frees it when the file object goes away.
// Updated in post-write, which can run at DISPATCH_LEVEL, so it is nonpaged and every field is
// changed with interlocked operations
typedef struct _PANO_HANDLE_CONTEXT {
	PANO_CONTEXT_KIND Kind;
	volatile LONG Flags;           // PANO_FLAG_COMPRESSED if any write was compressed
	volatile LONG64 Writes;
	volatile LONG64 Bytes;
	volatile LONG64 FirstWriteTime; // system time of the first write counted; 0 if none
	volatile LONG64 ProcessId;      // of the most recent write
	volatile LONG64 ThreadId;
} PANO_HANDLE_CONTEXT, * PPANO_HANDLE_CONTEXT;

// A copy of the file's name, captured in a pre-operation callback for its post-operation
// callback. Post-operation callbacks can run at DISPATCH_LEVEL, where names cannot be queried
// or released, so the name is copied into nonpaged pool, which can be freed at that IRQL.
// Used for security and EA changes, and for writes on volumes without stream handle contexts
typedef struct _PANO_NAMED_CONTEXT {
	PANO_CONTEXT_KIND Kind;
	PANO_EVENT_TYPE Type;
	UINT32 Value;      // PANO_FILE_EVENT_DATA::Length for security and EA changes
	UINT32 NameLength; // in WCHARs
	_Field_size_(NameLength) WCHAR Name[ANYSIZE_ARRAY];
} PANO_NAMED_CONTEXT, * PPANO_NAMED_CONTEXT;

static const FLT_CONTEXT_REGISTRATION ContextRegistration[] = {
	{ FLT_STREAMHANDLE_CONTEXT, 0, NULL, sizeof(PANO_HANDLE_CONTEXT), PANO_HANDLE_CONTEXT_POOL_TAG },
	{ FLT_CONTEXT_END }
};

// Returns the handle's write context, creating it on the first write, with a reference the
// caller releases with FltReleaseContext. Returns NULL if the volume does not support stream
// handle contexts or none could be allocated. IRQL <= APC_LEVEL
static PPANO_HANDLE_CONTEXT GetOrCreateHandleContext(PCFLT_RELATED_OBJECTS FltObjects)
{
	PFLT_CONTEXT context = NULL;
	NTSTATUS status = FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &context);
	if (NT_SUCCESS(status)) {
		return (PPANO_HANDLE_CONTEXT)context;
	}
	if (status != STATUS_NOT_FOUND) {
		return NULL;
	}

	status = FltAllocateContext(g_FilterHandle, FLT_STREAMHANDLE_CONTEXT, sizeof(PANO_HANDLE_CONTEXT), NonPagedPoolNx, &context);
	if (!NT_SUCCESS(status)) {
		return NULL;
	}
	RtlZeroMemory(context, sizeof(PANO_HANDLE_CONTEXT));
	((PPANO_HANDLE_CONTEXT)context)->Kind = PANO_CONTEXT_HANDLE;

	// Another write on the same handle may have set one first; that one is used instead
	PFLT_CONTEXT existing = NULL;
	status = FltSetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, FLT_SET_CONTEXT_KEEP_IF_EXISTS, context, &existing);
	if (NT_SUCCESS(status)) {
		// Ours is attached; the allocation's reference is the one handed to the caller
		return (PPANO_HANDLE_CONTEXT)context;
	}

	FltReleaseContext(context); // frees ours
	if (status == STATUS_FLT_CONTEXT_ALREADY_DEFINED) {
		return (PPANO_HANDLE_CONTEXT)existing; // referenced by FltSetStreamHandleContext
	}
	return NULL;
}

static PPANO_NAMED_CONTEXT AllocateNamedContext(PANO_EVENT_TYPE Type, UINT32 Value, PFLT_FILE_NAME_INFORMATION NameInfo)
{
	UINT32 nameLength = (NameInfo != NULL) ? NameInfo->Name.Length / sizeof(WCHAR) : 0;
	PPANO_NAMED_CONTEXT context = (PPANO_NAMED_CONTEXT)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		FIELD_OFFSET(PANO_NAMED_CONTEXT, Name) + nameLength * sizeof(WCHAR),
		PANO_NAMED_CONTEXT_POOL_TAG);
	if (context == NULL) {
		return NULL;
	}

	context->Kind = PANO_CONTEXT_NAMED;
	context->Type = Type;
	context->Value = Value;
	context->NameLength = nameLength;
	if (nameLength != 0) {
		RtlCopyMemory(context->Name, NameInfo->Name.Buffer, nameLength * sizeof(WCHAR));
	}
	return context;
}

#pragma endregion

#pragma region Helpers

// The kind of volume an operation targets. The filter attaches to the named pipe (NPFS) and
// mailslot (MSFS) file systems as well as to disks (FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS)
enum PANO_TARGET_KIND {
	PANO_TARGET_FILE,
	PANO_TARGET_NAMED_PIPE,
	PANO_TARGET_MAILSLOT,
};

// Cheap enough for every callback: the file object's device is the file system's device, whose
// type says whether it is NPFS or MSFS. Valid in pre-create too, since the I/O manager sets
// DeviceObject before sending the create
static PANO_TARGET_KIND TargetKind(PCFLT_RELATED_OBJECTS FltObjects)
{
	PFILE_OBJECT fileObject = FltObjects->FileObject;
	if (fileObject == NULL || fileObject->DeviceObject == NULL) {
		return PANO_TARGET_FILE;
	}
	switch (fileObject->DeviceObject->DeviceType) {
	case FILE_DEVICE_NAMED_PIPE: return PANO_TARGET_NAMED_PIPE;
	case FILE_DEVICE_MAILSLOT:   return PANO_TARGET_MAILSLOT;
	default:                     return PANO_TARGET_FILE;
	}
}

// True for named pipes and mailslots. Only their creates and connections are reported: reads,
// writes and closes on them are constant (RPC runs over named pipes), and are not file changes
static BOOLEAN IsPipeOrMailslot(PCFLT_RELATED_OBJECTS FltObjects)
{
	return TargetKind(FltObjects) != PANO_TARGET_FILE;
}

// Maps the result of a create-type operation (Data->IoStatus.Information) to an
// event type. Returns 0 for results that are not reported.
static UINT32 CreateResultToEventType(UCHAR MajorFunction, PANO_TARGET_KIND Target, ULONG_PTR Information)
{
	switch (MajorFunction)
	{
	case IRP_MJ_CREATE:
		// An ordinary create on NPFS/MSFS is a client connecting to an existing pipe or mailslot
		if (Target == PANO_TARGET_NAMED_PIPE) {
			return PANO_EVENT_NAMED_PIPE_OPEN;
		}
		if (Target == PANO_TARGET_MAILSLOT) {
			return PANO_EVENT_MAILSLOT_OPEN;
		}
		switch (Information) {
		case FILE_CREATED:     return PANO_EVENT_FILE_CREATED;
		case FILE_OPENED:      return PANO_EVENT_FILE_OPENED;
		case FILE_OVERWRITTEN: return PANO_EVENT_FILE_OVERWRITTEN;
		case FILE_SUPERSEDED:  return PANO_EVENT_FILE_SUPERSEDED;
		}
		break;
	case IRP_MJ_CREATE_NAMED_PIPE:
		// A server creating the pipe, or another instance of an existing pipe (FILE_OPENED)
		return PANO_EVENT_NAMED_PIPE_CREATE;
	case IRP_MJ_CREATE_MAILSLOT:
		return PANO_EVENT_MAILSLOT_CREATE;
	}
	return 0;
}

// Queries the name of the file the operation targets. Must be called at
// IRQL <= APC_LEVEL. Returns NULL if no name could be obtained; otherwise the
// caller releases the result with FltReleaseFileNameInformation.
static PFLT_FILE_NAME_INFORMATION QueryFileName(PFLT_CALLBACK_DATA Data)
{
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;
	NTSTATUS status = FltGetFileNameInformation(Data, FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (!NT_SUCCESS(status)) {
		// Normalization fails on some volumes (e.g. NPFS/MSFS); fall back to the opened name.
		status = FltGetFileNameInformation(Data, FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
		if (!NT_SUCCESS(status)) {
			return NULL;
		}
	}
	return nameInfo;
}

static UINT64 CurrentThreadIdOf(PFLT_CALLBACK_DATA Data)
{
	return (Data->Thread != NULL) ? (UINT64)(ULONG_PTR)PsGetThreadId(Data->Thread) : 0;
}

static void ReportFileEvent(
	PFLT_CALLBACK_DATA Data,
	PANO_EVENT_TYPE Type,
	INT64 FileOffset,
	UINT32 Length,
	UINT32 Flags,
	const WCHAR* Name,
	UINT32 NameLength)
{
	PanoReportFileEvent(Type, FltGetRequestorProcessId(Data), CurrentThreadIdOf(Data), FileOffset, Length, Flags, Name, NameLength);
}

// True if the operation did not actually open or write anything: the instance is
// detaching, or the operation failed / is being redirected.
static BOOLEAN ShouldSkipPostOperation(PFLT_CALLBACK_DATA Data, FLT_POST_OPERATION_FLAGS Flags)
{
	return FlagOn(Flags, FLTFL_POST_OPERATION_DRAINING) ||
		!NT_SUCCESS(Data->IoStatus.Status) ||
		Data->IoStatus.Status == STATUS_REPARSE;
}

// True if the operation comes from the process reading events (the service). Its own file
// activity is not reported: the service would discard it anyway, and each line it logs would
// otherwise produce more events. Checked before the name is queried, which is the costly part
static BOOLEAN IsFromEventConsumer(PFLT_CALLBACK_DATA Data)
{
	return EventQueueIsConsumerProcess(FltGetRequestorProcessId(Data));
}

#pragma endregion

#pragma region Pass-through

// Operations subscribed to without events yet. They return at once, and since the pre-operation
// callback asks for no post-operation callback, the registered post-operation never runs
FLT_PREOP_CALLBACK_STATUS PassThroughPreCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	*CompletionContext = NULL;
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PassThroughPostCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(Data);
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);
	UNREFERENCED_PARAMETER(Flags);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

#pragma endregion

#pragma region Create

//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create
//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create-named-pipe
//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-create-mailslot
// Decides whether the create could produce an event, so post-create only runs when it might
FLT_PREOP_CALLBACK_STATUS PreCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	*CompletionContext = NULL;

	BOOLEAN wanted;
	if (Data->Iopb->MajorFunction != IRP_MJ_CREATE) {
		// A server creating a named pipe or mailslot. Anonymous pipes (CreatePipe, used for
		// every redirected stdin/stdout) are created with an empty name relative to the
		// \Device\NamedPipe\ root, so they would all be reported as just "\Device\NamedPipe".
		// No client can open one by name, so they are not reported
		wanted = IsGroupEnabled(PANO_FILE_EVENTS_PIPE_MAILSLOT) &&
			FltObjects->FileObject->FileName.Length > 0;
	}
	else if (IsPipeOrMailslot(FltObjects)) {
		// A client connecting. Opens of the file system's root (the name is empty or "\") are
		// not connections: WaitNamedPipe and pipe listings open it constantly
		wanted = IsGroupEnabled(PANO_FILE_EVENTS_PIPE_MAILSLOT) &&
			FltObjects->FileObject->FileName.Length > sizeof(WCHAR);
	}
	else {
		wanted = IsGroupEnabled(PANO_FILE_EVENTS_CREATE) ||
			(IsGroupEnabled(PANO_FILE_EVENTS_DELETE_RENAME) && FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE));
	}

	if (!wanted || IsFromEventConsumer(Data)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	return FLT_PREOP_SUCCESS_WITH_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostCreateCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);
	UNREFERENCED_PARAMETER(CompletionContext);

	if (ShouldSkipPostOperation(Data, Flags)) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	UCHAR major = Data->Iopb->MajorFunction;
	PANO_TARGET_KIND target = TargetKind(FltObjects);
	UINT32 type = CreateResultToEventType(major, target, Data->IoStatus.Information);
	if (type == 0) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	UINT32 flags = 0;
	if (major == IRP_MJ_CREATE && FlagOn(Data->Iopb->Parameters.Create.Options, FILE_COMPLETE_IF_OPLOCKED)) {
		flags |= PANO_FLAG_OPLOCKED;
	}

	// Plain opens of existing files are not reported. They are by far the most frequent
	// operation, so they filled the event queue and caused other events to be dropped, and the
	// service never used them. Pipe and mailslot creates and connections are a separate group
	BOOLEAN reportCreate;
	if (target != PANO_TARGET_FILE || major != IRP_MJ_CREATE) {
		reportCreate = IsGroupEnabled(PANO_FILE_EVENTS_PIPE_MAILSLOT);
	}
	else {
		reportCreate = (type != PANO_EVENT_FILE_OPENED) && IsGroupEnabled(PANO_FILE_EVENTS_CREATE);
	}

	// A file opened with FILE_DELETE_ON_CLOSE is deleted when its last handle closes, without
	// ever going through IRP_MJ_SET_INFORMATION, so report the delete here as well
	BOOLEAN deleteOnClose = major == IRP_MJ_CREATE && target == PANO_TARGET_FILE &&
		FlagOn(Data->Iopb->Parameters.Create.Options, FILE_DELETE_ON_CLOSE) &&
		IsGroupEnabled(PANO_FILE_EVENTS_DELETE_RENAME);

	if (!reportCreate && !deleteOnClose) {
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	// Post-create always runs at PASSIVE_LEVEL, so the name can be queried here.
	PFLT_FILE_NAME_INFORMATION nameInfo = QueryFileName(Data);
	const WCHAR* name = (nameInfo != NULL) ? nameInfo->Name.Buffer : NULL;
	UINT32 nameLength = (nameInfo != NULL) ? nameInfo->Name.Length / sizeof(WCHAR) : 0;

	if (reportCreate) {
		ReportFileEvent(Data, (PANO_EVENT_TYPE)type, 0, 0, flags, name, nameLength);
	}
	if (deleteOnClose) {
		ReportFileEvent(Data, PANO_EVENT_FILE_DELETE, 0, 0, PANO_FLAG_DELETE_ON_CLOSE, name, nameLength);
	}

	if (nameInfo != NULL) {
		FltReleaseFileNameInformation(nameInfo);
	}

	return FLT_POSTOP_FINISHED_PROCESSING;
}

#pragma endregion

#pragma region Write and Cleanup

// Takes the writes counted on the handle so far and reports them as one PANO_EVENT_FILE_MODIFIED.
// Writes that finish while this runs are counted towards the next event. IRQL <= APC_LEVEL
static void ReportHandleWrites(PFLT_CALLBACK_DATA Data, PPANO_HANDLE_CONTEXT Handle, UINT32 Flags)
{
	LONG64 writes = InterlockedExchange64(&Handle->Writes, 0);
	LONG64 bytes = InterlockedExchange64(&Handle->Bytes, 0);
	LONG64 firstWriteTime = InterlockedExchange64(&Handle->FirstWriteTime, 0);
	LONG handleFlags = InterlockedExchange(&Handle->Flags, 0);
	if (writes <= 0) {
		return;
	}

	if (firstWriteTime == 0) {
		LARGE_INTEGER now;
		KeQuerySystemTimePrecise(&now);
		firstWriteTime = now.QuadPart;
	}

	PFLT_FILE_NAME_INFORMATION nameInfo = QueryFileName(Data);
	PanoReportFileModifiedEvent(
		(UINT64)Handle->ProcessId,
		(UINT64)Handle->ThreadId,
		(UINT64)writes,
		(UINT64)bytes,
		firstWriteTime,
		Flags | (UINT32)handleFlags,
		(nameInfo != NULL) ? nameInfo->Name.Buffer : NULL,
		(nameInfo != NULL) ? nameInfo->Name.Length / sizeof(WCHAR) : 0);
	if (nameInfo != NULL) {
		FltReleaseFileNameInformation(nameInfo);
	}
}

//https://learn.microsoft.com/en-us/previous-versions/windows/drivers/ifs/irp-mj-write
// Writes are counted on the handle and reported once, when it is cleaned up (or every
// PANO_FILE_MODIFIED_INTERVAL_MS while it keeps writing), rather than one event per write
FLT_PREOP_CALLBACK_STATUS PreWriteCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	*CompletionContext = NULL;

	if (!IsGroupEnabled(PANO_FILE_EVENTS_WRITE) || IsPipeOrMailslot(FltObjects) || IsFromEventConsumer(Data)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Non-paging pre-write runs at IRQL <= APC_LEVEL; guard anyway, since neither contexts
	// nor names can be looked up above that
	if (KeGetCurrentIrql() > APC_LEVEL) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	PPANO_HANDLE_CONTEXT handle = GetOrCreateHandleContext(FltObjects);
	if (handle != NULL) {
		// A handle that keeps writing is reported periodically, so a file that is never closed
		// is still seen
		LONG64 firstWriteTime = handle->FirstWriteTime;
		if (firstWriteTime != 0) {
			LARGE_INTEGER now;
			KeQuerySystemTimePrecise(&now);
			if (now.QuadPart - firstWriteTime >= (LONG64)PANO_FILE_MODIFIED_INTERVAL_MS * 10000) {
				ReportHandleWrites(Data, handle, PANO_FLAG_HANDLE_STILL_OPEN);
			}
		}

		// The reference is released by post-write
		*CompletionContext = handle;
		return FLT_PREOP_SUCCESS_WITH_CALLBACK;
	}

	// The volume has no stream handle contexts: report each write on its own, as before
	PFLT_FILE_NAME_INFORMATION nameInfo = QueryFileName(Data);
	if (nameInfo == NULL) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	*CompletionContext = AllocateNamedContext(PANO_EVENT_FILE_WRITE, 0, nameInfo);
	FltReleaseFileNameInformation(nameInfo);
	return (*CompletionContext != NULL) ? FLT_PREOP_SUCCESS_WITH_CALLBACK : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

// Can run at DISPATCH_LEVEL: only counts, using what pre-write captured
FLT_POSTOP_CALLBACK_STATUS PostWriteCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	BOOLEAN succeeded = !ShouldSkipPostOperation(Data, Flags);
	UINT32 bytes = (UINT32)Data->IoStatus.Information; // bytes actually written
	LONG compressed = FlagOn(Data->Iopb->MinorFunction, IRP_MN_COMPRESSED) ? PANO_FLAG_COMPRESSED : 0;

	if (*(PANO_CONTEXT_KIND*)CompletionContext == PANO_CONTEXT_HANDLE) {
		PPANO_HANDLE_CONTEXT handle = (PPANO_HANDLE_CONTEXT)CompletionContext;
		if (succeeded) {
			LARGE_INTEGER now;
			KeQuerySystemTimePrecise(&now);
			InterlockedCompareExchange64(&handle->FirstWriteTime, now.QuadPart, 0);
			InterlockedExchange64(&handle->ProcessId, (LONG64)FltGetRequestorProcessId(Data));
			InterlockedExchange64(&handle->ThreadId, (LONG64)CurrentThreadIdOf(Data));
			InterlockedAdd64(&handle->Bytes, bytes);
			InterlockedOr(&handle->Flags, compressed);
			// Counted last: cleanup only reports a handle that has writes
			InterlockedIncrement64(&handle->Writes);
		}
		FltReleaseContext(handle);
		return FLT_POSTOP_FINISHED_PROCESSING;
	}

	PPANO_NAMED_CONTEXT context = (PPANO_NAMED_CONTEXT)CompletionContext;
	if (succeeded) {
		ReportFileEvent(
			Data,
			PANO_EVENT_FILE_WRITE,
			Data->Iopb->Parameters.Write.ByteOffset.QuadPart,
			bytes,
			(UINT32)compressed,
			context->Name,
			context->NameLength);
	}

	// Freed on every path, including draining and failed writes.
	ExFreePoolWithTag(context, PANO_NAMED_CONTEXT_POOL_TAG);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-cleanup
// The last handle to the file object was closed: report the writes made through it
FLT_PREOP_CALLBACK_STATUS PreCleanupCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	*CompletionContext = NULL;

	// Only handles that wrote have a context, and pipe and mailslot writes are never counted, so
	// their cleanups (which are constant) stop here without a context lookup. Not checked against
	// the service's process: the writes counted were already filtered when they were made
	if (IsPipeOrMailslot(FltObjects)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	PFLT_CONTEXT context = NULL;
	if (!NT_SUCCESS(FltGetStreamHandleContext(FltObjects->Instance, FltObjects->FileObject, &context))) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Cleanup runs at PASSIVE_LEVEL, so the name can be queried
	if (IsGroupEnabled(PANO_FILE_EVENTS_WRITE)) {
		ReportHandleWrites(Data, (PPANO_HANDLE_CONTEXT)context, 0);
	}
	FltReleaseContext(context);
	return FLT_PREOP_SUCCESS_NO_CALLBACK;
}

#pragma endregion

#pragma region Security and EA changes

// Captures the name for post-operation, which reports the change only if it succeeded
static FLT_PREOP_CALLBACK_STATUS CaptureNamedOperation(PFLT_CALLBACK_DATA Data, PVOID* CompletionContext, PANO_EVENT_TYPE Type, UINT32 Value)
{
	// Both operations are dispatched at PASSIVE_LEVEL; guard anyway, since names need <= APC_LEVEL
	if (KeGetCurrentIrql() > APC_LEVEL) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	PFLT_FILE_NAME_INFORMATION nameInfo = QueryFileName(Data);
	*CompletionContext = AllocateNamedContext(Type, Value, nameInfo);
	if (nameInfo != NULL) {
		FltReleaseFileNameInformation(nameInfo);
	}
	return (*CompletionContext != NULL) ? FLT_PREOP_SUCCESS_WITH_CALLBACK : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-security
FLT_PREOP_CALLBACK_STATUS PreSetSecurityCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	*CompletionContext = NULL;

	if (!IsGroupEnabled(PANO_FILE_EVENTS_SECURITY) || IsPipeOrMailslot(FltObjects) || IsFromEventConsumer(Data)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	return CaptureNamedOperation(Data, CompletionContext, PANO_EVENT_FILE_SECURITY_CHANGED,
		(UINT32)Data->Iopb->Parameters.SetSecurity.SecurityInformation);
}

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-ea
FLT_PREOP_CALLBACK_STATUS PreSetEaCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	*CompletionContext = NULL;

	if (!IsGroupEnabled(PANO_FILE_EVENTS_EA) || IsPipeOrMailslot(FltObjects) || IsFromEventConsumer(Data)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}
	return CaptureNamedOperation(Data, CompletionContext, PANO_EVENT_FILE_EA_CHANGED,
		(UINT32)Data->Iopb->Parameters.SetEa.Length);
}

// Shared by SET_SECURITY and SET_EA. Can run at DISPATCH_LEVEL
FLT_POSTOP_CALLBACK_STATUS PostNamedOperationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	PPANO_NAMED_CONTEXT context = (PPANO_NAMED_CONTEXT)CompletionContext;
	if (!ShouldSkipPostOperation(Data, Flags)) {
		ReportFileEvent(Data, context->Type, 0, context->Value, 0,
			(context->NameLength != 0) ? context->Name : NULL, context->NameLength);
	}

	ExFreePoolWithTag(context, PANO_NAMED_CONTEXT_POOL_TAG);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

#pragma endregion

#pragma region Delete and Rename

// Names captured in pre-set-information for the post-operation, which can run at
// DISPATCH_LEVEL where names cannot be queried. Names holds the source name followed by the
// destination name (renames only), in nonpaged pool.
typedef struct _PANO_SETINFO_CONTEXT {
	PANO_EVENT_TYPE Type;   // PANO_EVENT_FILE_DELETE or PANO_EVENT_FILE_RENAME
	UINT32 Flags;
	UINT32 SourceNameLength;      // in WCHARs
	UINT32 DestinationNameLength; // in WCHARs
	_Field_size_(SourceNameLength + DestinationNameLength) WCHAR Names[ANYSIZE_ARRAY];
} PANO_SETINFO_CONTEXT, * PPANO_SETINFO_CONTEXT;

#define PANO_SETINFO_CONTEXT_POOL_TAG 'iFoP' // "PoFi"

// Queries the name a rename will give the file. Must be called at IRQL <= APC_LEVEL. Returns
// NULL if it could not be determined; otherwise release with FltReleaseFileNameInformation.
static PFLT_FILE_NAME_INFORMATION QueryRenameDestination(PFLT_CALLBACK_DATA Data, PCFLT_RELATED_OBJECTS FltObjects)
{
	PFILE_RENAME_INFORMATION renameInfo = (PFILE_RENAME_INFORMATION)Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	PFLT_FILE_NAME_INFORMATION nameInfo = NULL;

	NTSTATUS status = FltGetDestinationFileNameInformation(
		FltObjects->Instance, FltObjects->FileObject, renameInfo->RootDirectory,
		renameInfo->FileName, renameInfo->FileNameLength,
		FLT_FILE_NAME_NORMALIZED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
	if (!NT_SUCCESS(status)) {
		status = FltGetDestinationFileNameInformation(
			FltObjects->Instance, FltObjects->FileObject, renameInfo->RootDirectory,
			renameInfo->FileName, renameInfo->FileNameLength,
			FLT_FILE_NAME_OPENED | FLT_FILE_NAME_QUERY_DEFAULT, &nameInfo);
		if (!NT_SUCCESS(status)) {
			return NULL;
		}
	}
	return nameInfo;
}

//https://learn.microsoft.com/en-us/windows-hardware/drivers/ifs/irp-mj-set-information
// Deletes are a delete disposition being set (DeleteFile); renames and moves are a rename.
FLT_PREOP_CALLBACK_STATUS PreSetInformationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID* CompletionContext
)
{
	*CompletionContext = NULL;

	if (!IsGroupEnabled(PANO_FILE_EVENTS_DELETE_RENAME) || IsPipeOrMailslot(FltObjects) || IsFromEventConsumer(Data)) {
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	PVOID buffer = Data->Iopb->Parameters.SetFileInformation.InfoBuffer;
	ULONG length = Data->Iopb->Parameters.SetFileInformation.Length;
	PANO_EVENT_TYPE type;
	UINT32 flags = 0;

	switch (Data->Iopb->Parameters.SetFileInformation.FileInformationClass) {
	case FileDispositionInformation:
		// DeleteFile = FALSE cancels a pending delete; only setting it is reported
		if (length < sizeof(FILE_DISPOSITION_INFORMATION) ||
			!((PFILE_DISPOSITION_INFORMATION)buffer)->DeleteFile) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		type = PANO_EVENT_FILE_DELETE;
		break;
	case FileDispositionInformationEx:
		if (length < sizeof(FILE_DISPOSITION_INFORMATION_EX) ||
			!FlagOn(((PFILE_DISPOSITION_INFORMATION_EX)buffer)->Flags, FILE_DISPOSITION_DELETE)) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		type = PANO_EVENT_FILE_DELETE;
		break;
	case FileRenameInformation:
		if (length < sizeof(FILE_RENAME_INFORMATION)) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		if (((PFILE_RENAME_INFORMATION)buffer)->ReplaceIfExists) {
			flags |= PANO_FLAG_REPLACE_EXISTING;
		}
		type = PANO_EVENT_FILE_RENAME;
		break;
	case FileRenameInformationEx:
		if (length < sizeof(FILE_RENAME_INFORMATION)) {
			return FLT_PREOP_SUCCESS_NO_CALLBACK;
		}
		if (FlagOn(((PFILE_RENAME_INFORMATION)buffer)->Flags, FILE_RENAME_REPLACE_IF_EXISTS)) {
			flags |= PANO_FLAG_REPLACE_EXISTING;
		}
		type = PANO_EVENT_FILE_RENAME;
		break;
	default:
		return FLT_PREOP_SUCCESS_NO_CALLBACK;
	}

	// Names can only be queried at IRQL <= APC_LEVEL. Above that the event is still reported,
	// unnamed, from a context with no names.
	PFLT_FILE_NAME_INFORMATION sourceInfo = NULL;
	PFLT_FILE_NAME_INFORMATION destinationInfo = NULL;
	if (KeGetCurrentIrql() <= APC_LEVEL) {
		sourceInfo = QueryFileName(Data);
		if (type == PANO_EVENT_FILE_RENAME) {
			destinationInfo = QueryRenameDestination(Data, FltObjects);
		}
	}

	UINT32 sourceLength = (sourceInfo != NULL) ? sourceInfo->Name.Length / sizeof(WCHAR) : 0;
	UINT32 destinationLength = (destinationInfo != NULL) ? destinationInfo->Name.Length / sizeof(WCHAR) : 0;

	PPANO_SETINFO_CONTEXT context = (PPANO_SETINFO_CONTEXT)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		FIELD_OFFSET(PANO_SETINFO_CONTEXT, Names) + (sourceLength + destinationLength) * sizeof(WCHAR),
		PANO_SETINFO_CONTEXT_POOL_TAG);
	if (context != NULL) {
		context->Type = type;
		context->Flags = flags;
		context->SourceNameLength = sourceLength;
		context->DestinationNameLength = destinationLength;
		if (sourceLength != 0) {
			RtlCopyMemory(context->Names, sourceInfo->Name.Buffer, sourceLength * sizeof(WCHAR));
		}
		if (destinationLength != 0) {
			RtlCopyMemory(context->Names + sourceLength, destinationInfo->Name.Buffer, destinationLength * sizeof(WCHAR));
		}
		*CompletionContext = context;
	}

	if (sourceInfo != NULL) {
		FltReleaseFileNameInformation(sourceInfo);
	}
	if (destinationInfo != NULL) {
		FltReleaseFileNameInformation(destinationInfo);
	}

	// Without a context the post-operation has nothing to report
	return (context != NULL) ? FLT_PREOP_SUCCESS_WITH_CALLBACK : FLT_PREOP_SUCCESS_NO_CALLBACK;
}

FLT_POSTOP_CALLBACK_STATUS PostSetInformationCallback(
	PFLT_CALLBACK_DATA Data,
	PCFLT_RELATED_OBJECTS FltObjects,
	PVOID CompletionContext,
	FLT_POST_OPERATION_FLAGS Flags
)
{
	UNREFERENCED_PARAMETER(FltObjects);

	PPANO_SETINFO_CONTEXT context = (PPANO_SETINFO_CONTEXT)CompletionContext;

	// Only operations that succeeded are reported: a failed rename did not move anything, and
	// a failed disposition change did not mark the file for deletion
	if (!ShouldSkipPostOperation(Data, Flags)) {
		const WCHAR* source = (context->SourceNameLength != 0) ? context->Names : NULL;
		if (context->Type == PANO_EVENT_FILE_DELETE) {
			ReportFileEvent(Data, PANO_EVENT_FILE_DELETE, 0, 0, context->Flags, source, context->SourceNameLength);
		}
		else {
			const WCHAR* destination = (context->DestinationNameLength != 0) ? context->Names + context->SourceNameLength : NULL;
			PanoReportRenameEvent(FltGetRequestorProcessId(Data), CurrentThreadIdOf(Data), context->Flags,
				source, context->SourceNameLength,
				destination, context->DestinationNameLength);
		}
	}

	// Freed on every path, including draining and failed operations.
	ExFreePoolWithTag(context, PANO_SETINFO_CONTEXT_POOL_TAG);
	return FLT_POSTOP_FINISHED_PROCESSING;
}

#pragma endregion

NTSTATUS PanoptesFilterUnload
(
	_In_ FLT_FILTER_UNLOAD_FLAGS Flags
)
{
	PAGED_CODE();
	NTSTATUS status;
	if (FlagOn(Flags, FLTFL_FILTER_UNLOAD_MANDATORY)) {
		FilterUninit();
		status = STATUS_SUCCESS;
	}
	else {
		status = STATUS_FLT_DO_NOT_DETACH;
	}
	return status;
}

#pragma region FilterRegistration

// Level 1: the operations the filter subscribes to. Anything not listed (flush, volume
// information, locks, shutdown, power, PnP, quota, ...) never reaches the filter. Security
// changes are subscribed to but security queries are not. CLOSE, QUERY_INFORMATION,
// NETWORK_QUERY_OPEN and ACQUIRE_FOR_SECTION_SYNCHRONIZATION have no post-operation.
//
// Level 2: READ, WRITE and SET_INFORMATION skip paging I/O. Paging writes flush data already
// reported by the write that dirtied it, and querying names during paging I/O can deadlock.
const FLT_OPERATION_REGISTRATION Callbacks[] = {
	{ IRP_MJ_CREATE,                              0,                                         PreCreateCallback,         PostCreateCallback },
	{ IRP_MJ_CREATE_NAMED_PIPE,                   0,                                         PreCreateCallback,         PostCreateCallback },
	{ IRP_MJ_CLOSE,                               0,                                         PassThroughPreCallback,    NULL },
	{ IRP_MJ_READ,                                FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PassThroughPreCallback,  PassThroughPostCallback },
	{ IRP_MJ_WRITE,                               FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreWriteCallback,        PostWriteCallback },
	{ IRP_MJ_QUERY_INFORMATION,                   0,                                         PassThroughPreCallback,    NULL },
	{ IRP_MJ_SET_INFORMATION,                     FLTFL_OPERATION_REGISTRATION_SKIP_PAGING_IO, PreSetInformationCallback, PostSetInformationCallback },
	{ IRP_MJ_QUERY_EA,                            0,                                         PassThroughPreCallback,    PassThroughPostCallback },
	{ IRP_MJ_SET_EA,                              0,                                         PreSetEaCallback,          PostNamedOperationCallback },
	{ IRP_MJ_DIRECTORY_CONTROL,                   0,                                         PassThroughPreCallback,    PassThroughPostCallback },
	{ IRP_MJ_FILE_SYSTEM_CONTROL,                 0,                                         PassThroughPreCallback,    PassThroughPostCallback },
	{ IRP_MJ_DEVICE_CONTROL,                      0,                                         PassThroughPreCallback,    PassThroughPostCallback },
	{ IRP_MJ_CLEANUP,                             0,                                         PreCleanupCallback,        PassThroughPostCallback },
	{ IRP_MJ_CREATE_MAILSLOT,                     0,                                         PreCreateCallback,         PostCreateCallback },
	{ IRP_MJ_SET_SECURITY,                        0,                                         PreSetSecurityCallback,    PostNamedOperationCallback },
	{ IRP_MJ_NETWORK_QUERY_OPEN,                  0,                                         PassThroughPreCallback,    NULL },
	{ IRP_MJ_ACQUIRE_FOR_SECTION_SYNCHRONIZATION, 0,                                         PassThroughPreCallback,    NULL },
	{ IRP_MJ_OPERATION_END }
};

// SUPPORT_NPFS_MSFS: without it the filter never attaches to the named pipe and mailslot file
// systems, so none of their creates or connections reach it. Every callback above checks
// IsPipeOrMailslot so the rest of their I/O passes straight through
const FLT_REGISTRATION FilterRegistration = {
	sizeof(FLT_REGISTRATION),         //  Size
	FLT_REGISTRATION_VERSION,           //  Version
	FLTFL_REGISTRATION_SUPPORT_NPFS_MSFS, //  Flags
	ContextRegistration,                //  Context Registration
	Callbacks,                          //  Operation callbacks
	PanoptesFilterUnload,                      //  FilterUnload
	NULL,                               //  InstanceSetup
	NULL,                               //  InstanceQueryTeardown
	NULL,                               //  InstanceTeardownStart
	NULL,                               //  InstanceTeardownComplete
	NULL                                //  GenerateFileName
};

#pragma endregion

NTSTATUS FilterInit(PDRIVER_OBJECT* DriverObject)
{
	NTSTATUS status = FltRegisterFilter(
		*DriverObject,                  //Driver
		&FilterRegistration,           //Registration
		&g_FilterHandle);               //RetFilter
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed FltRegisterFilter\n");
		switch (status)
		{
		case STATUS_INSUFFICIENT_RESOURCES:
			DbgPrint("STATUS_INSUFFICIENT_RESOURCES\n");
			break;
		case STATUS_INVALID_PARAMETER:
			DbgPrint("STATUS_INVALID_PARAMETER\n");
			break;
		case STATUS_FLT_NOT_INITIALIZED:
			DbgPrint("STATUS_FLT_NOT_INITIALIZED\n");
			break;
		case STATUS_OBJECT_NAME_NOT_FOUND:
			DbgPrint("STATUS_OBJECT_NAME_NOT_FOUND\n");
			break;
		default:
			DbgPrint("UNKNOWN\n");
			break;
		}
		return status;
	}

	status = FltStartFiltering(g_FilterHandle);
	if (!NT_SUCCESS(status)) {
		DbgPrint("Failed FltStartFiltering\n");
		FltUnregisterFilter(g_FilterHandle);
		g_FilterHandle = nullptr;
		return status;
	}

	return status;
}

void FilterUninit()
{
	if (g_FilterHandle == NULL) {
		return;
	}

	FltUnregisterFilter(g_FilterHandle);
	g_FilterHandle = NULL;
}
