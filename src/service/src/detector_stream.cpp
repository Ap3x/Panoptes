#include "detector_stream.h"
#include "pano_log.h"
#include <algorithm>
#include <atomic>
#include <chrono>
#include <condition_variable>
#include <deque>
#include <mutex>
#include <unordered_set>

// Events held per subscriber before new ones are dropped. A few seconds of a busy machine; the
// detector normally drains its queue within milliseconds
#define PANO_DETECTOR_QUEUE_MAX 16384

// The detector holds one stream. A few more allow a debugging copy without letting a stuck
// client tie up the server's threads
#define PANO_MAX_DETECTOR_SUBSCRIBERS 4

struct DetectorSubscriberState {
	std::mutex Lock;
	std::condition_variable Wake;
	std::deque<DetectorEventRecord> Queue;
	std::unordered_set<std::string> EventNames; // empty: every event
	bool Stopping = false;
};

static std::mutex g_SubscribersLock;
static std::vector<std::shared_ptr<DetectorSubscriberState>> g_Subscribers;
static bool g_Stopping = false;
// Read without the lock so publishing costs one load while no detector is connected
static std::atomic<size_t> g_SubscriberCount{ 0 };

std::unique_ptr<DetectorSubscription> DetectorSubscription::Open(const std::vector<std::string>& eventNames)
{
	auto state = std::make_shared<DetectorSubscriberState>();
	state->EventNames.insert(eventNames.begin(), eventNames.end());

	std::lock_guard<std::mutex> guard(g_SubscribersLock);
	if (g_Stopping || g_Subscribers.size() >= PANO_MAX_DETECTOR_SUBSCRIBERS) {
		return nullptr;
	}
	g_Subscribers.push_back(state);
	g_SubscriberCount = g_Subscribers.size();
	return std::unique_ptr<DetectorSubscription>(new DetectorSubscription(state));
}

DetectorSubscription::DetectorSubscription(std::shared_ptr<DetectorSubscriberState> state)
	: m_state(std::move(state))
{
}

DetectorSubscription::~DetectorSubscription()
{
	std::lock_guard<std::mutex> guard(g_SubscribersLock);
	g_Subscribers.erase(std::remove(g_Subscribers.begin(), g_Subscribers.end(), m_state), g_Subscribers.end());
	g_SubscriberCount = g_Subscribers.size();
}

bool DetectorSubscription::Wait(std::vector<DetectorEventRecord>& out, DWORD timeoutMs)
{
	out.clear();
	std::unique_lock<std::mutex> lock(m_state->Lock);
	m_state->Wake.wait_for(lock, std::chrono::milliseconds(timeoutMs),
		[this] { return !m_state->Queue.empty() || m_state->Stopping; });
	if (m_state->Stopping) {
		return false;
	}
	out.assign(std::make_move_iterator(m_state->Queue.begin()), std::make_move_iterator(m_state->Queue.end()));
	m_state->Queue.clear();
	return true;
}

static void PublishDetectorEvent(const std::string& eventName, UINT64 sequence, const std::string& json, const FILETIME& time)
{
	if (g_SubscriberCount.load(std::memory_order_relaxed) == 0) {
		return;
	}

	INT64 timestamp = ((INT64)time.dwHighDateTime << 32) | time.dwLowDateTime;
	std::lock_guard<std::mutex> guard(g_SubscribersLock);
	for (auto& subscriber : g_Subscribers) {
		{
			std::lock_guard<std::mutex> lock(subscriber->Lock);
			if (!subscriber->EventNames.empty() && subscriber->EventNames.count(eventName) == 0) {
				continue;
			}
			// A dropped event leaves a gap in the sequence, which tells the detector
			if (subscriber->Queue.size() >= PANO_DETECTOR_QUEUE_MAX) {
				continue;
			}
			subscriber->Queue.push_back({ sequence, timestamp, json });
		}
		subscriber->Wake.notify_one();
	}
}

// Microseconds since 1970 when the service started (see detector_stream.h)
static UINT64 FirstSequence()
{
	ULARGE_INTEGER now;
	FILETIME time = CurrentFileTime();
	now.LowPart = time.dwLowDateTime;
	now.HighPart = time.dwHighDateTime;
	const UINT64 unixEpoch = 116444736000000000ULL; // 1970-01-01 as a FILETIME
	return (now.QuadPart - unixEpoch) / 10;
}

// Held from numbering an event until it is written and queued, so Seq increases down pano.log
// and along each subscriber's stream
static std::mutex g_RecordLock;
static UINT64 g_NextSequence = FirstSequence();

std::string RecordEvent(nlohmann::ordered_json& event, const FILETIME& time)
{
	std::lock_guard<std::mutex> guard(g_RecordLock);
	UINT64 sequence = g_NextSequence++;
	event["Seq"] = sequence;
	std::string line = event.dump();
	WriteToLogFile(line + "\n");
	PublishDetectorEvent(event.value("Event", ""), sequence, line, time);
	return line;
}

FILETIME CurrentFileTime()
{
	FILETIME now;
	GetSystemTimeAsFileTime(&now);
	return now;
}

void StopDetectorStreams()
{
	std::lock_guard<std::mutex> guard(g_SubscribersLock);
	g_Stopping = true;
	for (auto& subscriber : g_Subscribers) {
		{
			std::lock_guard<std::mutex> lock(subscriber->Lock);
			subscriber->Stopping = true;
		}
		subscriber->Wake.notify_all();
	}
}
