# Panoptes EDR Architecture Design Review

**Review Date:** 2026-01-17
**Diagram:** `assets/diagrams/EDR_Overview.gif`
**Reviewer:** Claude Code Analysis

---

## Executive Summary

The Panoptes EDR architecture demonstrates a well-thought-out modular design with clear separation of concerns. The use of containers for extensibility modules, RocksDB for persistent storage, and gRPC for inter-component communication shows modern architectural thinking. However, several **critical design gaps**, **scalability concerns**, and **operational challenges** need to be addressed.

**Overall Design Rating:** 7/10 - Solid foundation with room for improvement

---

## Architecture Analysis

### High-Level Flow

```
Kernel Events → ETW → Service → Containers (gRPC) → Extensibility Modules → Results → Logs/DB
      ↓                ↓                                                              ↑
User Mode Hooks → ETW  ↓                                                              ↓
                       └────────────→ Scanner Tools ──────────────────────────────────┘
```

---

## Strengths

### ✅ 1. Excellent Modular Design

**Observation:** Clear separation between kernel driver, service, containers, and extensibility modules.

**Benefits:**
- Easy to add new scanning engines
- Fault isolation (container crash doesn't bring down service)
- Independent development and testing
- Ability to update modules without driver changes

**Example:** Adding a new scanning module (e.g., ML-based detection) only requires a new container DLL.

---

### ✅ 2. Container-Based Extensibility Pattern

**Component:** Panoptes Containers + Extensibility DLLs

**Strengths:**
- **Fault isolation:** If Yara scanner crashes, AMSI/PE modules continue working
- **Resource management:** Can limit memory/CPU per container
- **Parallel processing:** Containers can run scans concurrently
- **Easy updates:** Replace DLLs without service restart

**Modern Pattern:** Similar to commercial EDR solutions (CrowdStrike, SentinelOne)

---

### ✅ 3. Dual Event Sources

**Components:**
- Kernel Driver (kernel-mode events)
- User Mode Hooks (user-mode events)

**Benefits:**
- **Comprehensive coverage:** Catches events at both levels
- **Evasion resistance:** Hard to bypass both kernel and user-mode hooks
- **Redundancy:** If user hooks are bypassed, kernel still monitors

**Smart Design:** Early DLL injection ensures monitoring from process start.

---

### ✅ 4. Persistent Storage with RocksDB

**Benefits:**
- Fast key-value lookups for file metadata
- Persistent scan results across reboots
- Query optimization for historical data
- Better than SQLite for high-throughput scenarios

**Good Choice:** RocksDB is battle-tested (Facebook, LinkedIn) for high-performance storage.

---

### ✅ 5. Configuration Management

**Component:** Panoptes Linter + JSON Configuration

**Benefits:**
- Validates configuration before service starts
- Prevents runtime errors from malformed config
- JSON format is human-readable and editable
- Built-in linter reduces misconfiguration

---

## Critical Design Issues

### 🔴 1. Missing Event Queue Architecture

**Problem:** No visible event queue between kernel/hooks and service.

**Current Flow:**
```
Kernel Driver → ETW → Service (immediate processing?)
```

**Issues:**
- **Event loss during high load:** If service can't keep up, events dropped
- **No backpressure mechanism:** Kernel doesn't know if service is overwhelmed
- **No priority handling:** All events treated equally
- **Service restart = lost events:** No buffering during downtime

**Recommended Design:**
```
Kernel/Hooks → ETW → Event Queue (Ring Buffer/Circular Queue)
                          ↓
                    Service Consumer (batching)
                          ↓
                      Containers
```

**Implementation Options:**
- Use ETW's built-in buffering (configure larger buffers)
- Add in-memory circular buffer (lockless ring buffer)
- Use named shared memory for kernel ↔ service communication

**Priority System:**
```
HIGH: Process injection, code execution, privilege escalation
MEDIUM: File modifications, registry changes
LOW: Benign file reads, normal process creation
```

---

### 🔴 2. Unclear Error Handling and Recovery

**Missing Information:**
- What happens if a container crashes?
- What happens if RocksDB becomes unavailable?
- What happens if gRPC communication fails?
- Is there a watchdog for container health?

**Questions:**
1. **Container crash recovery:**
   - Does service auto-restart containers?
   - Are in-flight scan requests retried?
   - How are partial results handled?

2. **Database failure:**
   - Does service continue without DB (degraded mode)?
   - Is there a fallback to file-based logging?
   - How is data consistency ensured?

3. **Communication failures:**
   - gRPC timeout handling?
   - Retry logic for scan requests?
   - Circuit breaker pattern for failing modules?

**Recommendation:** Add explicit error handling flows to diagram:
```
Container Crash → Health Monitor → Container Restart → Retry Scan
DB Unavailable  → Fallback Mode  → File Logging     → Queue writes
gRPC Timeout    → Circuit Breaker → Skip Module     → Log failure
```

---

### 🔴 3. No Mention of Event Correlation

**Problem:** Diagram shows individual events but no correlation engine.

**Missing Component:** **Event Correlation Engine**

**Why It Matters:**
Modern EDR systems correlate events to detect attack patterns:

**Example Attack Chain (Ransomware):**
```
1. Process Creation (suspicious.exe)
2. File Modification (shadow copy deletion)
3. Registry Change (persistence mechanism)
4. Mass File Encryption (rapid file writes)
→ Correlation Engine → ALERT: Ransomware behavior detected
```

**Without Correlation:**
- Each event analyzed independently
- Miss complex attack patterns
- High false positive rate
- No behavioral analysis

**Recommendation:** Add correlation engine between Service and Containers:
```
Service → Event Buffer → Correlation Engine → Pattern Matching → Containers
                              ↓
                    Process Tree Builder
                    Timeline Constructor
                    Behavioral Analyzer
```

---

### 🔴 4. Scalability Bottlenecks

#### a) Single Service Instance

**Problem:** "Panoptes Service is the main brain" suggests single-threaded or single-instance design.

**Concerns:**
- **CPU bottleneck:** One service handling all events on multi-core system
- **Memory pressure:** Large process trees consume memory
- **No load distribution:** Can't scale horizontally

**Recommendation:**
```
Service Architecture:
├── Event Consumer Thread Pool (N threads)
├── gRPC Server Thread Pool (M threads)
├── Container Manager (orchestrator)
└── Health Monitor (watchdog)
```

#### b) gRPC Communication Overhead

**Issue:** Every scan request requires gRPC call (serialization + network stack).

**Performance Impact:**
- Serialization/deserialization overhead
- Context switching between service and containers
- Latency for each scan operation

**Better Design for High Throughput:**
```
Option 1: Shared Memory IPC
- Service writes events to shared memory
- Containers read directly (zero-copy)
- Spinlock or semaphore for synchronization

Option 2: Batch Processing
- Service batches 100-1000 events
- Single gRPC call per batch
- Reduces overhead by 100-1000x
```

---

### 🟡 5. Unclear Data Flow for Scan Results

**Question:** How do scan results flow back to the service?

**From Diagram:**
```
Container → (gRPC?) → Service → Log Files + RocksDB
```

**Missing Details:**
1. **Result format:** Structured data? JSON? Protobuf?
2. **Result aggregation:** If Yara detects malware BUT PE scan says benign, what happens?
3. **Decision logic:** Where is the "quarantine vs allow" decision made?
4. **User notification:** Where does the tray notification come from?

**Clearer Flow Needed:**
```
Containers → Results (protobuf) → Service → Decision Engine
                                                ↓
                        ┌───────────────────────┼───────────────────┐
                        ↓                       ↓                   ↓
                    Quarantine               Allow              Investigate
                    (move file)          (log only)          (flag for review)
                        ↓
                  Notify User
```

---

### 🟡 6. Missing Network Communication Monitoring

**Observation:** Diagram shows file system, process, registry monitoring BUT no network monitoring.

**Missing Capability:** Network event capture

**Why Important for EDR:**
- C2 (Command & Control) communication detection
- DNS tunneling detection
- Exfiltration detection
- Lateral movement detection

**Common EDR Network Monitoring:**
- Windows Filtering Platform (WFP) callbacks
- Network Driver Interface Specification (NDIS) filter
- ETW network event providers

**Recommendation:** Add network monitoring component:
```
Panoptes Network Monitor (Optional Module)
├── WFP Callout Driver (kernel)
├── Network Event Parser (service)
└── Threat Intel Lookup (container)
    ├── Malicious IP database
    ├── Domain reputation check
    └── TLS certificate inspection
```

---

### 🟡 7. User Mode Hook Injection Dependency

**Concern:** System depends on successful DLL injection for user-mode events.

**Failure Scenarios:**
1. **Protected Process:** Can't inject into PPL (Protected Process Light)
2. **Early process exit:** Process exits before injection completes
3. **Injection blocked:** AV/EDR blocks DLL injection
4. **Code signing:** Process only loads signed DLLs

**Impact:** Incomplete event coverage.

**Mitigation Strategies:**
```
1. Fallback to Kernel-Only Monitoring
   - If injection fails, rely on kernel callbacks
   - Log injection failure for visibility

2. ETW-Based User-Mode Monitoring (No Injection)
   - Use Microsoft-Windows-Kernel-Process ETW provider
   - Capture NTDLL events without hooks
   - Limitation: Fewer events, less detail

3. Process Doppelgänging Detection
   - Monitor for injection evasion techniques
   - Alert on suspicious process creation patterns
```

---

### 🟡 8. No Mention of Performance Impact

**Missing Information:**
- Expected CPU overhead (%)
- Memory footprint per component
- I/O impact on system performance
- Worst-case latency for file operations

**Why It Matters:**
- EDR systems must have **minimal performance impact** (<5% CPU)
- File system filter can slow down I/O significantly
- Users will uninstall if system becomes sluggish

**Recommendation:** Add performance characteristics to diagram:
```
Component               CPU     Memory    Disk I/O
─────────────────────────────────────────────────
Kernel Driver          1-2%     5 MB      Minimal
Service                2-3%    50 MB      Low
Containers (each)      0.5%    30 MB      Medium
User Mode Hooks        <1%     10 MB      Minimal
─────────────────────────────────────────────────
Total (worst case)     ~8%    180 MB      Low-Med
```

---

## Security Design Concerns

### 🔴 1. Missing Tamper Protection

**Observation:** No mention of self-protection mechanisms.

**Attack Vectors:**
1. **Kill Panoptes Service** → System unprotected
2. **Unload kernel driver** → Monitoring disabled
3. **Delete/modify extensibility DLLs** → Reduced detection
4. **Corrupt RocksDB** → Lost forensic data
5. **Modify configuration file** → Weaken monitoring

**Recommendation:** Add tamper protection layer:
```
Panoptes Self-Protection (Anti-Tampering)
├── Service process protection (ObRegisterCallbacks)
├── Driver unload prevention (DriverEntry return)
├── File integrity monitoring (catalog-signed DLLs)
├── Configuration signing (HMAC validation)
└── Registry protection (CmRegisterCallback)
```

---

### 🔴 2. Trust Boundary Not Defined

**Question:** Which components run in what security context?

**Assumed Trust Model:**
```
Kernel Driver     → SYSTEM (kernel-mode)
Service           → SYSTEM (admin privileges)
Containers        → SYSTEM? LocalService? Sandboxed?
Extensibility DLLs → Same as container
Scanner Tools     → User context
```

**Security Concern:** If containers run as SYSTEM and get compromised (e.g., Yara exploit), attacker gains SYSTEM privileges.

**Recommendation:**
```
Least Privilege Design:
├── Kernel Driver    → Kernel mode (required)
├── Service          → SYSTEM (required for driver communication)
├── Containers       → LocalService (sandboxed)
│   └── Use impersonation for file access
└── Extensibility    → AppContainer (Win10+)
    └── Limited capabilities (read-only file access)
```

---

### 🟡 3. Code Signing Not Emphasized

**Observation:** Diagram doesn't show code signing requirements.

**Risk:** Unsigned DLLs can be replaced by malware.

**Recommendation:** Add to diagram:
```
All Components Must Be:
✓ Catalog-signed (Microsoft Authenticode)
✓ Signature validated on load
✓ Integrity checked periodically
```

---

## Operational Concerns

### 🟡 1. No Central Management

**Observation:** Diagram shows single-host architecture.

**Enterprise Requirement:** Central management console for fleet management.

**Missing Features:**
```
Panoptes Management Console (Future)
├── Agent deployment
├── Policy management (push configs)
├── Event aggregation (SIEM integration)
├── Threat hunting (cross-host queries)
├── Incident response (remote quarantine)
└── Dashboard (alerts, stats)
```

**Recommendation:** Design with centralization in mind from day one.

---

### 🟡 2. Logging Format Not Specified

**Observation:** "JSON-formatted logs" mentioned, but schema not defined.

**Critical Questions:**
1. **Event schema:** What fields are logged?
2. **Normalization:** Are events in standard format (e.g., ECS, OSSEM)?
3. **Volume:** How many events per day? (Disk space planning)
4. **Rotation:** Log rotation policy? Compression?
5. **Privacy:** PII handling? GDPR compliance?

**Recommendation:** Define standard event schema:
```json
{
  "timestamp": "2026-01-17T10:30:45.123Z",
  "event_type": "process_creation",
  "process": {
    "pid": 1234,
    "name": "malware.exe",
    "path": "C:\\Temp\\malware.exe",
    "command_line": "malware.exe --payload",
    "parent_pid": 5678,
    "hash_sha256": "abc123..."
  },
  "user": "DOMAIN\\username",
  "host": "DESKTOP-12345",
  "severity": "high",
  "detection": {
    "yara_rule": "Ransomware.Gen",
    "confidence": 0.95
  }
}
```

---

### 🟡 3. Update Mechanism Missing

**Question:** How are components updated?

**Update Scenarios:**
1. **Yara rules update** → Easy (just replace .pkg file)
2. **Service update** → Requires service restart
3. **Kernel driver update** → Requires reboot
4. **Container DLL update** → Container restart?

**Recommendation:** Design hot-reload capability:
```
Update Strategy:
├── Yara Rules    → Hot reload (monitor file changes)
├── Config        → Hot reload (notify service via IPC)
├── Containers    → Graceful restart (finish in-flight scans)
├── Service       → Planned maintenance window
└── Driver        → Reboot required (minimize frequency)
```

---

## Diagram Clarity and Documentation

### 🟡 1. Visual Complexity

**Issue:** Many components with complex interconnections.

**Readability Concerns:**
- Dotted lines (communication paths) overlap
- Legend missing (what do different line types mean?)
- Component criticality not indicated (which are optional?)

**Suggestions:**
```
Visual Improvements:
├── Add legend (solid line = data flow, dotted = control flow)
├── Color code by layer (kernel=red, service=blue, user=green)
├── Number the flow (1→2→3 for event processing sequence)
├── Use swim lanes (kernel space | user space | containers)
└── Add icons for component types (DB, service, driver)
```

---

### 🟡 2. Missing Component Details

**What's Missing from Diagram:**

| Component | Missing Info |
|-----------|--------------|
| **Kernel Driver** | File system filter types (pre/post callbacks), callback IRQL |
| **Service** | Threading model, gRPC server config, event buffer size |
| **RocksDB** | Schema design, indexing strategy, cleanup policy |
| **Containers** | Lifecycle (long-running or per-request?), health checks |
| **Log Files** | Rotation policy, max size, compression |

**Recommendation:** Create supplementary diagrams:
1. **Detailed Component Diagram** (internal architecture of each)
2. **Sequence Diagram** (event flow with timing)
3. **Deployment Diagram** (file system layout)

---

## Design Pattern Analysis

### ✅ Well-Applied Patterns

1. **Microservices Architecture** (container-based modules)
   - Pro: Modularity, fault isolation
   - Con: Communication overhead

2. **Producer-Consumer** (kernel → service → containers)
   - Pro: Decoupling, backpressure handling
   - Con: Requires careful queue sizing

3. **Plugin Architecture** (extensibility DLLs)
   - Pro: Easy to extend
   - Con: Must validate plugin integrity

---

### 🟡 Missing Patterns

1. **Circuit Breaker** (for failing containers)
   ```
   If Yara container fails 5 times in 60s:
   → Open circuit (stop sending requests)
   → Retry after 5 minutes
   → Log failure and alert admin
   ```

2. **Bulkhead** (resource isolation per container)
   ```
   Limit each container:
   - Max 4 concurrent scans
   - Max 500MB memory
   - Max 30s scan time
   ```

3. **Observer Pattern** (for config changes)
   ```
   Config file updated → Notify service → Reload config → Notify containers
   ```

---

## Specific Recommendations

### High Priority

1. **Add Event Queue with Backpressure**
   ```
   Kernel → Lockless Ring Buffer (1M events) → Service
            ↓
     If 90% full → Rate limit kernel events
     If 100% full → Drop low-priority events + alert
   ```

2. **Define Error Handling Flows**
   - Document retry logic for each failure mode
   - Add health checks and auto-recovery
   - Implement graceful degradation

3. **Add Event Correlation Engine**
   ```
   Service → Correlation Engine → Attack Pattern Database
                ↓
          Process Tree Builder
          Behavioral Analyzer
          Threat Scoring
   ```

4. **Implement Container Health Monitoring**
   ```
   Service → Health Monitor (watchdog)
                ↓
          Poll containers every 10s
          Restart on failure
          Alert on repeated failures
   ```

---

### Medium Priority

5. **Add Performance Metrics to Design**
   - Document expected overhead
   - Set performance budgets (max 5% CPU)
   - Add performance monitoring

6. **Define Logging Schema**
   - Standardize on event format (JSON Schema)
   - Plan for log volume (GB/day estimates)
   - Define retention policy

7. **Add Network Monitoring Component**
   - WFP callout driver or ETW network events
   - DNS query logging
   - Outbound connection tracking

8. **Design Tamper Protection**
   - Service process protection
   - Driver unload prevention
   - Configuration integrity checks

---

### Low Priority

9. **Improve Diagram Clarity**
   - Add legend and swim lanes
   - Color code by layer
   - Number event flow sequence

10. **Plan for Central Management**
    - Multi-host architecture
    - Policy distribution
    - Event aggregation

11. **Document Update Strategy**
    - Hot reload for rules/config
    - Graceful updates for containers
    - Maintenance windows for driver

---

## Comparison with Commercial EDR

### What Panoptes Has (Good Coverage)

✅ Kernel driver for event capture
✅ User-mode hooks
✅ Modular scanning engines
✅ Persistent storage
✅ ETW integration
✅ File system monitoring

### What's Missing (Compared to Commercial EDR)

❌ **Behavioral analysis engine** (MITRE ATT&CK mapping)
❌ **Network monitoring** (C2 detection)
❌ **Memory scanning** (fileless malware)
❌ **Threat intelligence integration** (IoC feeds)
❌ **Cloud-based analysis** (send samples to sandbox)
❌ **EDR telemetry** (detailed attack chain reconstruction)
❌ **Automatic response** (kill process, isolate host)

---

## Positive Design Highlights

Despite the concerns raised, the architecture has many strong points:

✅ **Modern tech stack** (gRPC, RocksDB, Protocol Buffers)
✅ **Extensible design** (easy to add scanners)
✅ **Proper separation of concerns** (kernel, service, containers)
✅ **Dual-layer monitoring** (kernel + user mode)
✅ **Built-in tools** (linter, CLI scanner)
✅ **Persistent storage** (survives reboots)
✅ **Educational clarity** (good for learning EDR concepts)

---

## Overall Assessment

### Strengths
- Clean modular architecture
- Well-chosen technology stack
- Container-based extensibility is excellent
- Dual-layer monitoring (kernel + user)

### Critical Gaps
- No event queue/buffering (event loss risk)
- Missing error handling design
- No event correlation (pattern detection)
- Scalability concerns (single service bottleneck)

### Recommended Next Steps

1. **Address critical gaps** (event queue, error handling)
2. **Add performance budgets** to design
3. **Design correlation engine** for behavioral detection
4. **Plan for scalability** (thread pools, batching)
5. **Add tamper protection** to architecture
6. **Document logging schema** and retention

---

## Final Recommendation

**Current State:** Excellent educational project demonstrating EDR fundamentals.

**Production Readiness:** Requires addressing critical gaps (event queue, correlation, error handling) and extensive testing.

**Rating:** 7/10 - Solid foundation, needs refinement for real-world deployment.

The architecture shows strong understanding of EDR concepts and uses modern design patterns. With the recommended improvements, this could become a robust EDR solution.

