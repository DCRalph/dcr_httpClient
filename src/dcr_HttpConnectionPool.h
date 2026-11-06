#pragma once
// ═══════════════════════════════════════════════════════════════════
//  HttpConnectionPool.h – Persistent HTTPS connection reuse
// ═══════════════════════════════════════════════════════════════════
//
//  Maintains a single long-lived WiFiClientSecure + HTTPClient pair
//  pointed at the primary API server. Subsequent requests reuse the
//  existing TCP+TLS session (HTTP/1.1 keep-alive), collapsing the
//  per-request cost from ~5-6 RTTs to 1 RTT.
//
//  Thread safety: all access is serialised through Mutex::httpRequest
//  (the same mutex already used in httpRequest.cpp).
//
//  An idle socket is recycled after IDLE_RECYCLE_MS and kept alive with TCP
//  keepalive probes in between, because consumer NATs and phone hotspots drop
//  idle TCP mappings long before Cloudflare's 400 s keep-alive window.
//

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <dcr_INetLink.h>
#include <cstdint>

namespace HTTP
{

  class ConnectionPool
  {
  public:
    // Lifetime counters plus the current socket. Written under the request
    // mutex; every field is a single word, so a reader without it sees whole values.
    struct Stats
    {
      uint32_t socketsOpened = 0; // WiFiClientSecure allocations
      uint32_t uses = 0;          // successful requests over the pool
      uint32_t invalidations = 0; // torn down after a failed request
      uint32_t idleRecycles = 0;
      uint32_t deadSockets = 0;   // connected() false when acquired
      uint32_t linkDrops = 0;     // torn down because the WiFi disconnect seq advanced
      uint32_t socketSinceMs = 0; // millis() the current socket was allocated, 0 when none
      uint32_t lastUsedMs = 0;
      uint32_t usesOnSocket = 0;
      int fd = -1;
    };

    ConnectionPool() = default;
    ~ConnectionPool();

    // Non-copyable, non-movable.
    ConnectionPool(const ConnectionPool &) = delete;
    ConnectionPool &operator=(const ConnectionPool &) = delete;

    /// Initialise the pool. Call once from setup() after HTTP::init().
    /// `netLinkMonitor` is used to detect socket-fd recycling after WiFi
    /// disconnects; pass an INetLink implementation (typically the global
    /// netLink singleton).
    void init(INetLink *netLinkMonitor = nullptr);

    /// Get a WiFiClientSecure that is either already connected (reused)
    /// or freshly constructed. The caller must NOT delete the pointer.
    /// Returns nullptr if WiFi is not connected.
    WiFiClientSecure *acquireClient();

    /// Get the shared HTTPClient, pre-configured with setReuse(true).
    /// Returns nullptr if WiFi is not connected.
    HTTPClient *acquireHttp();

    /// Call after a successful request to record the last-use timestamp.
    void markUsed();

    /// Call after a failed request (negative status code or transport
    /// error) to tear down the connection so the next attempt starts
    /// fresh.
    void invalidate();

    /// Proactively recycle if idle too long. Called from the HTTPS
    /// worker task or the main loop periodically.
    void recycleIfStale();

    /// True when the underlying TCP+TLS socket is still connected.
    bool isConnected() const;

    // Lock-free; see Stats.
    const Stats &stats() const { return _stats; }
    static constexpr uint32_t idleRecycleMs() { return IDLE_RECYCLE_MS; }

  private:
    enum class TeardownReason : uint8_t
    {
      Invalidate,
      Idle,
      Dead,
      LinkDrop,
      Shutdown
    };

    // LinkDrop/Shutdown: the cached fd may already belong to another VFS driver
    // (lwip socket freed, fd recycled), so close(fd) is skipped.
    void teardown(TeardownReason reason);

    WiFiClientSecure *_secureClient = nullptr;
    HTTPClient *_http = nullptr;
    Stats _stats;
    bool _initialised = false;
    INetLink *_netLink = nullptr;

    // Snapshot of NetLink::disconnectEventSeq() taken when the cached
    // _secureClient was set up. If the seq advances, the underlying lwip
    // socket may have been recycled and the cached fd must NOT be passed
    // to close().
    uint32_t _lastSeenDisconnectSeq = 0;

    // Socket fd that already has keepalive options applied.
    int _keepaliveFd = -1;

    // Recycle the connection if idle for longer than this. Consumer NATs and
    // phone hotspots expire idle TCP mappings in 60-300 s; a fresh handshake
    // costs ~1 s, a stale socket costs a 10 s timeout and a failed job.
    static constexpr uint32_t IDLE_RECYCLE_MS = 45u * 1000u;
  };

  /// Global singleton. Defined in HttpConnectionPool.cpp.
  extern ConnectionPool connectionPool;

} // namespace HTTP
