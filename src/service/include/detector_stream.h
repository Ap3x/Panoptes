#pragma once
#include <Windows.h>
#include <memory>
#include <string>
#include <vector>

// Fan-out of logged events to PanoptesDetector over the SubscribeEvents RPC.
//
// The driver and hook event threads call PublishDetectorEvent next to WriteToLogFile. Each
// subscriber has a bounded queue; when it is full the event is dropped for that subscriber
// rather than blocking the event threads, and the gap in its sequence numbers tells the
// detector events were lost.

/// @brief One event as sent to the detector (a DetectorEvent message)
struct DetectorEventRecord {
	UINT64 Sequence;   // per subscriber, increments by one for every event meant for it
	INT64 Timestamp;   // FILETIME, UTC
	std::string Json;  // the line written to pano.log, without the newline
};

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

/// @brief Queues an event for every subscriber that wants eventName. Cheap when nobody is
/// subscribed. Never blocks on a subscriber
/// @param eventName The event's "Event" field
/// @param json The log line, without the trailing newline
/// @param time When the event happened
void PublishDetectorEvent(const std::string& eventName, const std::string& json, const FILETIME& time);

/// @brief The current time as a FILETIME, for events that carry no timestamp of their own
FILETIME CurrentFileTime();

/// @brief Wakes every subscriber's Wait with false and refuses new subscribers, so the
/// SubscribeEvents calls return before the server shuts down
void StopDetectorStreams();
