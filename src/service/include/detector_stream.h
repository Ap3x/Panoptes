#pragma once
#include <Windows.h>
#include <memory>
#include <string>
#include <vector>
#include <nlohmann/json.hpp>

// Fan-out of logged events to PanoptesDetector over the SubscribeEvents RPC.
//
// The driver and hook event threads log through RecordEvent, which numbers each event, writes
// it to pano.log and queues it for every subscriber. Each subscriber has a bounded queue; when
// it is full the event is dropped for that subscriber rather than blocking the event threads,
// and the gap in the sequence numbers tells the detector events were lost.
//
// The sequence number is the event's "Seq" in pano.log, so a detection's EventSequences name
// the exact log lines it matched. It starts at the service's start time in microseconds since
// 1970 and then counts up by one per event, so numbers keep increasing across restarts and a
// Seq names one line across every pano.log file. It stays below 2^53, so JSON readers that
// parse numbers as doubles read it exactly.

/// @brief One event as sent to the detector (a DetectorEvent message)
struct DetectorEventRecord {
	UINT64 Sequence;   // the event's Seq in pano.log
	INT64 Timestamp;   // FILETIME, UTC
	std::string Json;  // the line written to pano.log, without the newline
};

/// @brief Gives event the next sequence number (appended as "Seq"), writes it to pano.log and
/// queues it for every subscriber that wants it, in that order for every event, so Seq
/// increases down the log
/// @param time When the event happened, at full resolution, for the detector
/// @return The line written, without the newline
std::string RecordEvent(nlohmann::ordered_json& event, const FILETIME& time);

struct DetectorSubscriberState;

/// @brief A registered subscriber. Unregisters when destroyed
class DetectorSubscription {
public:
	/// @brief Registers a subscriber. Returns nullptr when the service is stopping or too many
	/// subscribers are connected
	/// @param eventNames Only events whose "Event" is in this list are queued; empty means all
	static std::unique_ptr<DetectorSubscription> Open(const std::vector<std::string>& eventNames);
	~DetectorSubscription();

	/// @brief Waits up to timeoutMs for events and moves the queued ones into out (which it
	/// clears first). Returns false once StopDetectorStreams has been called
	bool Wait(std::vector<DetectorEventRecord>& out, DWORD timeoutMs);

	DetectorSubscription(const DetectorSubscription&) = delete;
	DetectorSubscription& operator=(const DetectorSubscription&) = delete;

private:
	explicit DetectorSubscription(std::shared_ptr<DetectorSubscriberState> state);
	std::shared_ptr<DetectorSubscriberState> m_state;
};

/// @brief The current time as a FILETIME, for events that carry no timestamp of their own
FILETIME CurrentFileTime();

/// @brief Wakes every subscriber's Wait with false and refuses new subscribers, so the
/// SubscribeEvents calls return before the server shuts down
void StopDetectorStreams();
