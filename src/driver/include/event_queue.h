#pragma once
#include <ntddk.h>
#include "pano_events.h"

// Inverted-call event delivery.
//
// The service keeps one (or more) IOCTL_PANOPTES_GET_EVENT requests pending at
// all times. When an event fires in a kernel callback, the driver completes a
// pending request with that event's data. If no request happens to be pending,
// the event is buffered in a bounded FIFO and handed to the next request that
// arrives. Events that fire when the FIFO is full are dropped and counted; the
// drop count is reported in the next delivered PANO_EVENT_HEADER::Dropped.
//
// Events are only produced for a connected consumer. A handle becomes a consumer
// with its first GET_EVENT request and stops being one when it is cleaned up
// (closed, or its process exits). While there is no consumer, events are dropped
// rather than buffered, so a service that starts or restarts is not handed a
// backlog of stale events; the events buffered when the last consumer leaves are
// dropped too. These are counted separately and reported in the next delivered
// PANO_EVENT_HEADER::DroppedNoConsumer. Other handles, such as one opened only to
// send IOCTL_PANOPTES_TERMINATE_PROCESS, never become consumers.

/// @brief Maximum number of events buffered while no GET_EVENT request is pending.
/// Older buffered events are not discarded; new events are dropped once the FIFO is full.
#define PANO_MAX_QUEUED_EVENTS 2048

/// @brief Initializes the event queue. Call once from DriverEntry before any
/// producer can run and before the device is exposed.
NTSTATUS EventQueueInit();

/// @brief Cancels every pending GET_EVENT request and frees all buffered events.
/// Call from the unload path after all producers have been stopped.
void EventQueueCleanup();

/// @brief Queues a GET_EVENT request. Call from the IOCTL dispatch routine.
/// On success the IRP is either completed immediately (an event was waiting) or
/// marked pending and parked in the cancel-safe queue; in both cases the dispatch
/// routine must return the value written to *Status and must not touch the IRP again.
/// @param Irp The IOCTL_PANOPTES_GET_EVENT request (METHOD_BUFFERED).
/// @param Status Receives the status the dispatch routine should return.
/// @return TRUE if the queue took ownership of the IRP, FALSE if the caller must
/// complete it with *Status (e.g. the output buffer was too small).
BOOLEAN EventQueueReceiveRequest(PIRP Irp, NTSTATUS* Status);

/// @brief Checks whether a process is the one reading events (the service). The filter
/// does not report that process's own file activity: its log writes, database and scans
/// would otherwise each produce more events for it to read, and it discards them anyway.
/// Tracks the process of the handle that most recently became a consumer. Safe at any
/// IRQL <= DISPATCH_LEVEL.
BOOLEAN EventQueueIsConsumerProcess(UINT64 ProcessId);

/// @brief Handles IRP_MJ_CLEANUP for a handle to the device: cancels the GET_EVENT
/// requests still parked for it and, if it was the last consumer, drops the buffered
/// events. Call from the IRP_MJ_CLEANUP dispatch routine.
/// @param FileObject The file object being cleaned up.
void EventQueueCleanupFile(PFILE_OBJECT FileObject);

/// @brief Reports one event. Delivers it to a pending GET_EVENT request if one is
/// waiting, otherwise buffers it. Safe to call at IRQL <= DISPATCH_LEVEL.
/// @param Type A PANO_EVENT_TYPE.
/// @param Payload The event body that follows the header (e.g. a PANO_FILE_EVENT_DATA).
/// @param PayloadSize Size of Payload in bytes.
/// @return STATUS_SUCCESS if delivered or buffered, STATUS_INSUFFICIENT_RESOURCES if
/// the event could not be allocated, STATUS_BUFFER_OVERFLOW if the event is too large.
NTSTATUS PanoReportEvent(PANO_EVENT_TYPE Type, _In_reads_bytes_(PayloadSize) const void* Payload, UINT32 PayloadSize);

/// @brief Convenience wrapper that builds a PANO_FILE_EVENT_DATA event. FileName is
/// copied and truncated to PANO_MAX_FILE_NAME_LENGTH (PANO_FLAG_NAME_TRUNCATED is set
/// in Flags when truncation occurs). Pass NameLength in WCHARs.
NTSTATUS PanoReportFileEvent(
	PANO_EVENT_TYPE Type,
	UINT64 ProcessId,
	UINT64 ThreadId,
	INT64 FileOffset,
	UINT32 Length,
	UINT32 Flags,
	_In_reads_opt_(NameLength) const WCHAR* FileName,
	UINT32 NameLength);

/// @brief Convenience wrapper that builds a PANO_EVENT_FILE_MODIFIED event. FileName is
/// copied and truncated to PANO_MAX_MODIFIED_FILE_NAME_LENGTH (PANO_FLAG_NAME_TRUNCATED is set
/// when truncation occurs). Pass NameLength in WCHARs.
NTSTATUS PanoReportFileModifiedEvent(
	UINT64 ProcessId,
	UINT64 ThreadId,
	UINT64 Writes,
	UINT64 Bytes,
	INT64 FirstWriteTime,
	UINT32 Flags,
	_In_reads_opt_(NameLength) const WCHAR* FileName,
	UINT32 NameLength);

/// @brief Convenience wrapper that builds a PANO_RENAME_EVENT_DATA event. If the two names
/// together exceed PANO_MAX_RENAME_NAMES_LENGTH they are truncated (the longer one first) and
/// PANO_FLAG_NAME_TRUNCATED is set. Pass lengths in WCHARs.
NTSTATUS PanoReportRenameEvent(
	UINT64 ProcessId,
	UINT64 ThreadId,
	UINT32 Flags,
	_In_reads_opt_(SourceNameLength) const WCHAR* SourceName,
	UINT32 SourceNameLength,
	_In_reads_opt_(DestinationNameLength) const WCHAR* DestinationName,
	UINT32 DestinationNameLength);

/// @brief Convenience wrapper that builds a PANO_PROCESS_EVENT_DATA event. If the image name and
/// command line together exceed PANO_MAX_PROCESS_STRINGS_LENGTH they are truncated (the longer one
/// first) and PANO_FLAG_NAME_TRUNCATED / PANO_FLAG_COMMAND_LINE_TRUNCATED are set for whichever was
/// cut. Pass lengths in WCHARs.
NTSTATUS PanoReportProcessEvent(
	PANO_EVENT_TYPE Type,
	UINT64 ProcessId,
	UINT64 ParentProcessId,
	UINT64 CreatingProcessId,
	UINT64 CreatingThreadId,
	_In_reads_opt_(ImageNameLength) const WCHAR* ImageName,
	UINT32 ImageNameLength,
	_In_reads_opt_(CommandLineLength) const WCHAR* CommandLine,
	UINT32 CommandLineLength);
