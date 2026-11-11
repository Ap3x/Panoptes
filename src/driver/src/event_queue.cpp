#include "event_queue.h"

#define PANO_EVENT_POOL_TAG 'vEoP' // "PoEv"

// A buffered event. Data holds a PANO_EVENT_HEADER immediately followed by the
// event body, i.e. exactly what is copied into a GET_EVENT output buffer.
typedef struct _PANO_EVENT_NODE {
	LIST_ENTRY ListEntry;
	UINT32 Size; // bytes in Data
	_Field_size_bytes_(Size) UCHAR Data[ANYSIZE_ARRAY];
} PANO_EVENT_NODE, * PPANO_EVENT_NODE;

// Pending GET_EVENT requests. The CSQ serializes access with g_IrpLock and owns
// cancellation; dispatch, producers and the I/O manager can touch it concurrently.
static IO_CSQ g_Csq;
static LIST_ENTRY g_IrpList;
static KSPIN_LOCK g_IrpLock;

// Buffered events, protected by its own lock so it can be manipulated without
// nesting inside the CSQ lock.
static LIST_ENTRY g_EventList;
static KSPIN_LOCK g_EventLock;
static ULONG g_EventCount;
static volatile LONG g_Dropped; // events dropped since the last delivery

// Handles that have sent a GET_EVENT request and not yet been cleaned up. Each
// one is marked by setting its FileObject->FsContext, which is free for a
// non-file-system device's own use, to PANO_CONSUMER_MARK
static volatile LONG g_Consumers;
static volatile LONG g_DroppedNoConsumer; // dropped since the last delivery, no consumer
#define PANO_CONSUMER_MARK ((PVOID)(ULONG_PTR)0x50414E4F) // 'PANO'

// The process of the handle that most recently became a consumer, or 0 when there is none.
// Each consumer handle keeps its process ID in FileObject->FsContext2 (also free for our
// use) so cleanup only clears this if it still names that handle's process
static volatile LONG64 g_ConsumerProcessId;

#pragma region Event FIFO

// Removes and returns the oldest buffered event, or NULL if the FIFO is empty.
static PPANO_EVENT_NODE DequeueEvent()
{
	KIRQL irql;
	PPANO_EVENT_NODE node = NULL;

	KeAcquireSpinLock(&g_EventLock, &irql);
	if (!IsListEmpty(&g_EventList)) {
		PLIST_ENTRY entry = RemoveHeadList(&g_EventList);
		node = CONTAINING_RECORD(entry, PANO_EVENT_NODE, ListEntry);
		g_EventCount--;
	}
	KeReleaseSpinLock(&g_EventLock, irql);
	return node;
}

// Buffers an event at the tail of the FIFO. If the FIFO is full the event is
// freed and counted as dropped; the oldest buffered events are kept so the
// stream stays contiguous up to the drop point.
static void EnqueueEvent(PPANO_EVENT_NODE node)
{
	KIRQL irql;
	KeAcquireSpinLock(&g_EventLock, &irql);

	// The last consumer may have left since the event was allocated. Checked under
	// the lock: EventQueueCleanupFile drops the count before taking the lock to
	// empty the FIFO, so an event is either emptied out with the rest or dropped here
	if (g_Consumers == 0) {
		KeReleaseSpinLock(&g_EventLock, irql);
		ExFreePoolWithTag(node, PANO_EVENT_POOL_TAG);
		InterlockedIncrement(&g_DroppedNoConsumer);
		return;
	}

	if (g_EventCount >= PANO_MAX_QUEUED_EVENTS) {
		KeReleaseSpinLock(&g_EventLock, irql);
		ExFreePoolWithTag(node, PANO_EVENT_POOL_TAG);
		InterlockedIncrement(&g_Dropped);
		return;
	}
	InsertTailList(&g_EventList, &node->ListEntry);
	g_EventCount++;
	KeReleaseSpinLock(&g_EventLock, irql);
}

// Reinserts an event at the head of the FIFO, preserving order. Used only on the
// rare race where a request was pulled out from under a just-buffered event.
static void RequeueEventFront(PPANO_EVENT_NODE node)
{
	KIRQL irql;
	KeAcquireSpinLock(&g_EventLock, &irql);
	InsertHeadList(&g_EventList, &node->ListEntry);
	g_EventCount++;
	KeReleaseSpinLock(&g_EventLock, irql);
}

#pragma endregion

#pragma region IRP delivery

// Copies a buffered event into a GET_EVENT request and completes it. The request
// was validated to hold at least PANO_MAX_EVENT_SIZE bytes, and node->Size never
// exceeds that, so the whole event always fits. Frees the node.
static void DeliverEventToIrp(PIRP Irp, PPANO_EVENT_NODE node)
{
	RtlCopyMemory(Irp->AssociatedIrp.SystemBuffer, node->Data, node->Size);

	// Report (and reset) the drop counts accumulated since the previous delivery.
	PPANO_EVENT_HEADER header = (PPANO_EVENT_HEADER)Irp->AssociatedIrp.SystemBuffer;
	header->Dropped = (UINT32)InterlockedExchange(&g_Dropped, 0);
	header->DroppedNoConsumer = (UINT32)InterlockedExchange(&g_DroppedNoConsumer, 0);

	ULONG size = node->Size;
	ExFreePoolWithTag(node, PANO_EVENT_POOL_TAG);

	Irp->IoStatus.Status = STATUS_SUCCESS;
	Irp->IoStatus.Information = size;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

#pragma endregion

#pragma region Cancel-safe queue callbacks

static VOID CsqInsertIrp(PIO_CSQ Csq, PIRP Irp)
{
	UNREFERENCED_PARAMETER(Csq);
	InsertTailList(&g_IrpList, &Irp->Tail.Overlay.ListEntry);
}

static VOID CsqRemoveIrp(PIO_CSQ Csq, PIRP Irp)
{
	UNREFERENCED_PARAMETER(Csq);
	RemoveEntryList(&Irp->Tail.Overlay.ListEntry);
}

// PeekContext is NULL to take any request, or a PFILE_OBJECT to take only that
// handle's requests (used when the handle is cleaned up)
static PIRP CsqPeekNextIrp(PIO_CSQ Csq, PIRP Irp, PVOID PeekContext)
{
	UNREFERENCED_PARAMETER(Csq);

	PLIST_ENTRY next = (Irp == NULL)
		? g_IrpList.Flink
		: Irp->Tail.Overlay.ListEntry.Flink;

	for (; next != &g_IrpList; next = next->Flink) {
		PIRP candidate = CONTAINING_RECORD(next, IRP, Tail.Overlay.ListEntry);
		if (PeekContext == NULL ||
			IoGetCurrentIrpStackLocation(candidate)->FileObject == (PFILE_OBJECT)PeekContext) {
			return candidate;
		}
	}
	return NULL;
}

_IRQL_raises_(DISPATCH_LEVEL)
_Acquires_lock_(g_IrpLock)
static VOID CsqAcquireLock(PIO_CSQ Csq, PKIRQL Irql)
{
	UNREFERENCED_PARAMETER(Csq);
	KeAcquireSpinLock(&g_IrpLock, Irql);
}

_Releases_lock_(g_IrpLock)
static VOID CsqReleaseLock(PIO_CSQ Csq, KIRQL Irql)
{
	UNREFERENCED_PARAMETER(Csq);
	KeReleaseSpinLock(&g_IrpLock, Irql);
}

static VOID CsqCompleteCanceledIrp(PIO_CSQ Csq, PIRP Irp)
{
	UNREFERENCED_PARAMETER(Csq);
	Irp->IoStatus.Status = STATUS_CANCELLED;
	Irp->IoStatus.Information = 0;
	IoCompleteRequest(Irp, IO_NO_INCREMENT);
}

#pragma endregion

NTSTATUS EventQueueInit()
{
	InitializeListHead(&g_IrpList);
	InitializeListHead(&g_EventList);
	KeInitializeSpinLock(&g_IrpLock);
	KeInitializeSpinLock(&g_EventLock);
	g_EventCount = 0;
	g_Dropped = 0;
	g_Consumers = 0;
	g_DroppedNoConsumer = 0;

	return IoCsqInitialize(
		&g_Csq,
		CsqInsertIrp,
		CsqRemoveIrp,
		CsqPeekNextIrp,
		CsqAcquireLock,
		CsqReleaseLock,
		CsqCompleteCanceledIrp);
}

void EventQueueCleanup()
{
	// Cancel every parked request.
	PIRP irp;
	while ((irp = IoCsqRemoveNextIrp(&g_Csq, NULL)) != NULL) {
		irp->IoStatus.Status = STATUS_CANCELLED;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	// Drop every buffered event.
	PPANO_EVENT_NODE node;
	while ((node = DequeueEvent()) != NULL) {
		ExFreePoolWithTag(node, PANO_EVENT_POOL_TAG);
	}
}

BOOLEAN EventQueueReceiveRequest(PIRP Irp, NTSTATUS* Status)
{
	PIO_STACK_LOCATION irpSp = IoGetCurrentIrpStackLocation(Irp);

	// Every buffered event is <= PANO_MAX_EVENT_SIZE, so a request that can hold
	// that much can hold any event and the copy at delivery never truncates.
	if (irpSp->Parameters.DeviceIoControl.OutputBufferLength < PANO_MAX_EVENT_SIZE) {
		*Status = STATUS_BUFFER_TOO_SMALL;
		return FALSE;
	}

	// The handle's first request makes it a consumer, and events start being kept
	if (InterlockedCompareExchangePointer(&irpSp->FileObject->FsContext, PANO_CONSUMER_MARK, NULL) == NULL) {
		// The device has no drivers above it, so the request is dispatched in the context of
		// the thread that sent it
		LONG64 processId = (LONG64)(ULONG_PTR)PsGetCurrentProcessId();
		irpSp->FileObject->FsContext2 = (PVOID)(ULONG_PTR)processId;
		InterlockedExchange64(&g_ConsumerProcessId, processId);
		InterlockedIncrement(&g_Consumers);
	}

	// Fast path: an event is already waiting.
	PPANO_EVENT_NODE node = DequeueEvent();
	if (node != NULL) {
		DeliverEventToIrp(Irp, node);
		*Status = STATUS_SUCCESS;
		return TRUE;
	}

	// Park the request. IoCsqInsertIrp marks it pending for us.
	IoCsqInsertIrp(&g_Csq, Irp, NULL);

	// An event may have been buffered after our DequeueEvent and before the
	// insert, while no request was parked to receive it. Drain it now so the
	// request does not stall behind an event that already arrived.
	node = DequeueEvent();
	if (node != NULL) {
		PIRP waiter = IoCsqRemoveNextIrp(&g_Csq, NULL);
		if (waiter != NULL) {
			DeliverEventToIrp(waiter, node);
		}
		else {
			// Our request was already taken (by a producer); put the event back.
			RequeueEventFront(node);
		}
	}

	*Status = STATUS_PENDING;
	return TRUE;
}

BOOLEAN EventQueueIsConsumerProcess(UINT64 ProcessId)
{
	// An aligned 64-bit read is atomic on x64
	LONG64 consumer = g_ConsumerProcessId;
	return consumer != 0 && (UINT64)consumer == ProcessId;
}

void EventQueueCleanupFile(PFILE_OBJECT FileObject)
{
	// Complete the requests this handle still has parked. A process that is exiting
	// has had them cancelled already, but one that just closes its handle has not
	PIRP irp;
	while ((irp = IoCsqRemoveNextIrp(&g_Csq, FileObject)) != NULL) {
		irp->IoStatus.Status = STATUS_CANCELLED;
		irp->IoStatus.Information = 0;
		IoCompleteRequest(irp, IO_NO_INCREMENT);
	}

	// Called for both IRP_MJ_CLEANUP and IRP_MJ_CLOSE; only the first unmarks the
	// handle. IRP_MJ_CLOSE covers a GET_EVENT request that was still being
	// dispatched when IRP_MJ_CLEANUP arrived and marked the handle afterwards
	if (InterlockedCompareExchangePointer(&FileObject->FsContext, NULL, PANO_CONSUMER_MARK) != PANO_CONSUMER_MARK) {
		return;
	}

	// Stop exempting this handle's process, unless a newer consumer has replaced it
	InterlockedCompareExchange64(&g_ConsumerProcessId, 0, (LONG64)(ULONG_PTR)FileObject->FsContext2);
	FileObject->FsContext2 = NULL;

	if (InterlockedDecrement(&g_Consumers) != 0) {
		return;
	}

	// No consumer is left. What is buffered would only reach the next service as
	// stale events, so it is dropped and counted
	KIRQL irql;
	LIST_ENTRY dropped;
	InitializeListHead(&dropped);
	LONG count = 0;

	KeAcquireSpinLock(&g_EventLock, &irql);
	while (!IsListEmpty(&g_EventList)) {
		InsertTailList(&dropped, RemoveHeadList(&g_EventList));
		count++;
	}
	g_EventCount = 0;
	KeReleaseSpinLock(&g_EventLock, irql);

	while (!IsListEmpty(&dropped)) {
		PPANO_EVENT_NODE node = CONTAINING_RECORD(RemoveHeadList(&dropped), PANO_EVENT_NODE, ListEntry);
		ExFreePoolWithTag(node, PANO_EVENT_POOL_TAG);
	}
	InterlockedAdd(&g_DroppedNoConsumer, count);
}

// Allocates an event node large enough for PayloadSize bytes after the header,
// fills in the header, and returns a pointer to the payload region in *Payload.
// Returns NULL (and counts a drop) if no consumer is connected, the event is too
// large, or allocation fails.
static PPANO_EVENT_NODE AllocEventNode(PANO_EVENT_TYPE Type, UINT32 PayloadSize, void** Payload)
{
	// Nothing would read the event, so skip the allocation. EnqueueEvent checks
	// again under the lock for a consumer that leaves after this point
	if (g_Consumers == 0) {
		InterlockedIncrement(&g_DroppedNoConsumer);
		return NULL;
	}

	UINT32 size = (UINT32)sizeof(PANO_EVENT_HEADER) + PayloadSize;
	if (size > PANO_MAX_EVENT_SIZE) {
		InterlockedIncrement(&g_Dropped);
		return NULL;
	}

	PPANO_EVENT_NODE node = (PPANO_EVENT_NODE)ExAllocatePool2(
		POOL_FLAG_NON_PAGED,
		FIELD_OFFSET(PANO_EVENT_NODE, Data) + size,
		PANO_EVENT_POOL_TAG);
	if (node == NULL) {
		InterlockedIncrement(&g_Dropped);
		return NULL;
	}

	node->Size = size;

	PPANO_EVENT_HEADER header = (PPANO_EVENT_HEADER)node->Data;
	header->Size = size;
	header->Type = Type;
	LARGE_INTEGER now;
	KeQuerySystemTimePrecise(&now);
	header->Timestamp = now.QuadPart;
	header->Dropped = 0; // both filled in at delivery
	header->DroppedNoConsumer = 0;

	*Payload = node->Data + sizeof(PANO_EVENT_HEADER);
	return node;
}

// Delivers a fully built event node to a pending request, or buffers it.
static void SubmitEventNode(PPANO_EVENT_NODE node)
{
	// Hand straight to a waiting request if there is one.
	PIRP irp = IoCsqRemoveNextIrp(&g_Csq, NULL);
	if (irp != NULL) {
		DeliverEventToIrp(irp, node);
		return;
	}

	// No request waiting: buffer it.
	EnqueueEvent(node);

	// A request may have been parked after our RemoveNextIrp returned NULL and
	// before we buffered the event, leaving a request waiting on a non-empty
	// FIFO. Pair them up.
	irp = IoCsqRemoveNextIrp(&g_Csq, NULL);
	if (irp != NULL) {
		PPANO_EVENT_NODE queued = DequeueEvent();
		if (queued != NULL) {
			DeliverEventToIrp(irp, queued);
		}
		else {
			// The event we just buffered was already delivered by a concurrent
			// request; nothing to hand this one, so put it back to wait.
			IoCsqInsertIrp(&g_Csq, irp, NULL);
		}
	}
}

NTSTATUS PanoReportEvent(PANO_EVENT_TYPE Type, const void* Payload, UINT32 PayloadSize)
{
	void* dest;
	PPANO_EVENT_NODE node = AllocEventNode(Type, PayloadSize, &dest);
	if (node == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	if (PayloadSize != 0) {
		RtlCopyMemory(dest, Payload, PayloadSize);
	}

	SubmitEventNode(node);
	return STATUS_SUCCESS;
}

NTSTATUS PanoReportFileEvent(
	PANO_EVENT_TYPE Type,
	UINT64 ProcessId,
	UINT64 ThreadId,
	INT64 FileOffset,
	UINT32 Length,
	UINT32 Flags,
	const WCHAR* FileName,
	UINT32 NameLength)
{
	if (FileName == NULL) {
		NameLength = 0;
	}
	if (NameLength > PANO_MAX_FILE_NAME_LENGTH) {
		NameLength = (UINT32)PANO_MAX_FILE_NAME_LENGTH;
		Flags |= PANO_FLAG_NAME_TRUNCATED;
	}

	UINT32 payloadSize = (UINT32)FIELD_OFFSET(PANO_FILE_EVENT_DATA, FileName) + NameLength * (UINT32)sizeof(WCHAR);

	// Assemble straight into the pooled node to avoid a large kernel-stack copy.
	void* dest;
	PPANO_EVENT_NODE node = AllocEventNode(Type, payloadSize, &dest);
	if (node == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PPANO_FILE_EVENT_DATA data = (PPANO_FILE_EVENT_DATA)dest;
	data->ProcessId = ProcessId;
	data->ThreadId = ThreadId;
	data->FileOffset = FileOffset;
	data->Length = Length;
	data->Flags = Flags;
	data->NameLength = NameLength;
	if (NameLength != 0) {
		RtlCopyMemory(data->FileName, FileName, NameLength * sizeof(WCHAR));
	}

	SubmitEventNode(node);
	return STATUS_SUCCESS;
}

NTSTATUS PanoReportFileModifiedEvent(
	UINT64 ProcessId,
	UINT64 ThreadId,
	UINT64 Writes,
	UINT64 Bytes,
	INT64 FirstWriteTime,
	UINT32 Flags,
	const WCHAR* FileName,
	UINT32 NameLength)
{
	if (FileName == NULL) {
		NameLength = 0;
	}
	if (NameLength > PANO_MAX_MODIFIED_FILE_NAME_LENGTH) {
		NameLength = (UINT32)PANO_MAX_MODIFIED_FILE_NAME_LENGTH;
		Flags |= PANO_FLAG_NAME_TRUNCATED;
	}

	UINT32 payloadSize = (UINT32)FIELD_OFFSET(PANO_FILE_MODIFIED_EVENT_DATA, FileName) + NameLength * (UINT32)sizeof(WCHAR);

	void* dest;
	PPANO_EVENT_NODE node = AllocEventNode(PANO_EVENT_FILE_MODIFIED, payloadSize, &dest);
	if (node == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PPANO_FILE_MODIFIED_EVENT_DATA data = (PPANO_FILE_MODIFIED_EVENT_DATA)dest;
	data->ProcessId = ProcessId;
	data->ThreadId = ThreadId;
	data->Writes = Writes;
	data->Bytes = Bytes;
	data->FirstWriteTime = FirstWriteTime;
	data->Flags = Flags;
	data->NameLength = NameLength;
	if (NameLength != 0) {
		RtlCopyMemory(data->FileName, FileName, NameLength * sizeof(WCHAR));
	}

	SubmitEventNode(node);
	return STATUS_SUCCESS;
}

// Shrinks two string lengths so their sum fits in MaxTotal WCHARs. The longer string is
// trimmed first, so a short string is never cut to make room for a long one.
static void FitTwoStrings(UINT32* FirstLength, UINT32* SecondLength, UINT32 MaxTotal, BOOLEAN* FirstCut, BOOLEAN* SecondCut)
{
	const UINT32 first = *FirstLength;
	const UINT32 second = *SecondLength;
	*FirstCut = FALSE;
	*SecondCut = FALSE;

	// Compare in 64 bits so huge lengths cannot wrap the sum
	if ((UINT64)first + second <= MaxTotal) {
		return;
	}

	const UINT32 half = MaxTotal / 2;
	if (first > half && second > half) {
		*FirstLength = half;
		*SecondLength = MaxTotal - half;
	}
	else if (first > second) {
		*FirstLength = MaxTotal - second;
	}
	else {
		*SecondLength = MaxTotal - first;
	}
	*FirstCut = (*FirstLength != first);
	*SecondCut = (*SecondLength != second);
}

NTSTATUS PanoReportRenameEvent(
	UINT64 ProcessId,
	UINT64 ThreadId,
	UINT32 Flags,
	const WCHAR* SourceName,
	UINT32 SourceNameLength,
	const WCHAR* DestinationName,
	UINT32 DestinationNameLength)
{
	if (SourceName == NULL) {
		SourceNameLength = 0;
	}
	if (DestinationName == NULL) {
		DestinationNameLength = 0;
	}

	BOOLEAN sourceCut, destinationCut;
	FitTwoStrings(&SourceNameLength, &DestinationNameLength, (UINT32)PANO_MAX_RENAME_NAMES_LENGTH, &sourceCut, &destinationCut);
	if (sourceCut || destinationCut) {
		Flags |= PANO_FLAG_NAME_TRUNCATED;
	}

	UINT32 payloadSize = (UINT32)FIELD_OFFSET(PANO_RENAME_EVENT_DATA, Names) +
		(SourceNameLength + DestinationNameLength) * (UINT32)sizeof(WCHAR);

	void* dest;
	PPANO_EVENT_NODE node = AllocEventNode(PANO_EVENT_FILE_RENAME, payloadSize, &dest);
	if (node == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PPANO_RENAME_EVENT_DATA data = (PPANO_RENAME_EVENT_DATA)dest;
	data->ProcessId = ProcessId;
	data->ThreadId = ThreadId;
	data->Flags = Flags;
	data->SourceNameLength = SourceNameLength;
	data->DestinationNameLength = DestinationNameLength;
	if (SourceNameLength != 0) {
		RtlCopyMemory(data->Names, SourceName, SourceNameLength * sizeof(WCHAR));
	}
	if (DestinationNameLength != 0) {
		RtlCopyMemory(data->Names + SourceNameLength, DestinationName, DestinationNameLength * sizeof(WCHAR));
	}

	SubmitEventNode(node);
	return STATUS_SUCCESS;
}

NTSTATUS PanoReportProcessEvent(
	PANO_EVENT_TYPE Type,
	UINT64 ProcessId,
	UINT64 ParentProcessId,
	UINT64 CreatingProcessId,
	UINT64 CreatingThreadId,
	const WCHAR* ImageName,
	UINT32 ImageNameLength,
	const WCHAR* CommandLine,
	UINT32 CommandLineLength)
{
	UINT32 flags = 0;
	if (ImageName == NULL) {
		ImageNameLength = 0;
	}
	if (CommandLine == NULL) {
		CommandLineLength = 0;
	}

	BOOLEAN imageCut, commandLineCut;
	FitTwoStrings(&ImageNameLength, &CommandLineLength, (UINT32)PANO_MAX_PROCESS_STRINGS_LENGTH, &imageCut, &commandLineCut);
	if (imageCut) {
		flags |= PANO_FLAG_NAME_TRUNCATED;
	}
	if (commandLineCut) {
		flags |= PANO_FLAG_COMMAND_LINE_TRUNCATED;
	}

	UINT32 payloadSize = (UINT32)FIELD_OFFSET(PANO_PROCESS_EVENT_DATA, Strings) +
		(ImageNameLength + CommandLineLength) * (UINT32)sizeof(WCHAR);

	void* dest;
	PPANO_EVENT_NODE node = AllocEventNode(Type, payloadSize, &dest);
	if (node == NULL) {
		return STATUS_INSUFFICIENT_RESOURCES;
	}

	PPANO_PROCESS_EVENT_DATA data = (PPANO_PROCESS_EVENT_DATA)dest;
	data->ProcessId = ProcessId;
	data->ParentProcessId = ParentProcessId;
	data->CreatingProcessId = CreatingProcessId;
	data->CreatingThreadId = CreatingThreadId;
	data->Flags = flags;
	data->ImageNameLength = ImageNameLength;
	data->CommandLineLength = CommandLineLength;
	if (ImageNameLength != 0) {
		RtlCopyMemory(data->Strings, ImageName, ImageNameLength * sizeof(WCHAR));
	}
	if (CommandLineLength != 0) {
		RtlCopyMemory(data->Strings + ImageNameLength, CommandLine, CommandLineLength * sizeof(WCHAR));
	}

	SubmitEventNode(node);
	return STATUS_SUCCESS;
}
