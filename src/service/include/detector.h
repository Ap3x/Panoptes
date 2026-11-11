#pragma once
#include <string>

class Configuration;
class Detection;

// The service side of the behavioral detector (src/detector): who may call its RPCs and what
// a reported detection makes the service do.

/// @brief Whether a gRPC peer is PanoptesDetector.exe from the service's folder. The server
/// listens on localhost without credentials, so this keeps other local processes from reading
/// the event stream or asking the service to kill processes
/// @param peer grpc::ServerContext::peer(), e.g. "ipv4:127.0.0.1:50123"
/// @param serverPort The port the service listens on
/// @param why Set to the reason when the peer is refused
bool IsDetectorPeer(const std::string& peer, int serverPort, std::string& why);

/// @brief Carries out a detection's action and describes what was done, for the log. Kill and
/// quarantine only happen with EnforceDetectionActions; they are refused for system processes,
/// the service and its children, critical processes, and a process ID reused since the match
std::string RespondToDetection(const Detection& detection, const Configuration& configuration);
