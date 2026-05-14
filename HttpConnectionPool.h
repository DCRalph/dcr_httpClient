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
//  Cloudflare's client-side keep-alive window is 400 seconds. If the
//  connection has been idle longer than IDLE_RECYCLE_MS, the pool
//  proactively tears it down so the next request gets a clean
//  handshake rather than discovering a reset mid-flight.
//

#include <HTTPClient.h>
#include <WiFiClientSecure.h>
#include <netLink/INetLink.h>
#include <cstdint>

namespace HTTP
{

  class ConnectionPool
  {
  public:
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

  private:
    // linkSuspect=true: cached fd may already point at another VFS driver
    // (the lwip socket was freed and the fd recycled). Use the safe-close
    // path that bypasses close(fd) — see implementation for details.
    void teardown(bool linkSuspect = false);

    WiFiClientSecure *_secureClient = nullptr;
    HTTPClient *_http = nullptr;
    uint32_t _lastUsedMs = 0;
    bool _initialised = false;
    INetLink *_netLink = nullptr;

    // Snapshot of NetLink::disconnectEventSeq() taken when the cached
    // _secureClient was set up. If the seq advances, the underlying lwip
    // socket may have been recycled and the cached fd must NOT be passed
    // to close().
    uint32_t _lastSeenDisconnectSeq = 0;

    // Recycle the connection if idle for longer than this.
    // Cloudflare closes client connections after 400 s of inactivity;
    // we recycle at 350 s to avoid hitting a reset.
    static constexpr uint32_t IDLE_RECYCLE_MS = 350u * 1000u;
  };

  /// Global singleton. Defined in HttpConnectionPool.cpp.
  extern ConnectionPool connectionPool;

} // namespace HTTP
