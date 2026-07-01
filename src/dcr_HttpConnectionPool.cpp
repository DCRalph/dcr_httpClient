#include "dcr_HttpConnectionPool.h"
#include "dcr_HttpRequest.h"
#include <dcr_Logger.h>
#include <WiFi.h>
#include <lwip/sockets.h>

#undef LOG_TAG
#define LOG_TAG "POOL"

namespace
{
  // Returns true if fd is currently a live lwip socket. Uses lwip_getsockopt
  // (NOT VFS getsockopt) so it never dispatches into LittleFS on a recycled fd.
  bool isLwipSocket(int fd)
  {
    if (fd < 0)
      return false;
    int sockType = 0;
    socklen_t len = sizeof(sockType);
    return lwip_getsockopt(fd, SOL_SOCKET, SO_TYPE, &sockType, &len) == 0;
  }
} // namespace

namespace HTTP
{

  ConnectionPool connectionPool;

  ConnectionPool::~ConnectionPool()
  {
    teardown(/*linkSuspect=*/true);
  }

  void ConnectionPool::init(INetLink *netLinkMonitor)
  {
    if (_initialised)
      return;

    _initialised = true;
    _netLink = netLinkMonitor;
    _lastSeenDisconnectSeq = _netLink ? _netLink->disconnectEventSeq() : 0;
    debugI("HTTP connection pool initialised");
  }

  void ConnectionPool::teardown(bool linkSuspect)
  {
    // A link disconnect since this client was set up means the cached lwip
    // socket fd may already have been freed and recycled to another VFS
    // driver (e.g. LittleFS). Treat the fd as suspect on those paths too, so
    // callers that do NOT pass linkSuspect explicitly -- invalidate() and the
    // destructor -- are still protected. (Previously invalidate() relied
    // solely on the isLwipSocket() heuristic, which is unreliable: see below.)
    const uint32_t curSeq = _netLink ? _netLink->disconnectEventSeq() : 0;
    if (_secureClient && curSeq != _lastSeenDisconnectSeq)
      linkSuspect = true;

    // NEVER let WiFiClientSecure drive the VFS close() on the cached fd.
    //
    // WiFiClientSecure::stop() calls close(fd), which is VFS-routed. If `fd`
    // was recycled from a dead lwip socket to a LittleFS file, close(fd)
    // dispatches into vfs_littlefs_close() with no open file and trips
    //   assert failed: lfs_file_close ... lfs_mlist_isopen(...)   -> panic.
    //
    // The old guard tried to detect this with isLwipSocket() (lwip_getsockopt),
    // but that checks lwip's INTERNAL socket table, not whether the GLOBAL VFS
    // fd still routes to the socket driver. After fd recycling the two
    // namespaces diverge, so the check returns false positives and stop() ran
    // close() on a fd that now belonged to LittleFS -> the crash.
    //
    // Instead: (1) snapshot the fd, (2) neutralise sslclient->socket to -1 via
    // the socket() side-effect accessor BEFORE any _http->end(),
    // _secureClient->stop() or ~WiFiClientSecure() can run -- this makes the
    // VFS close() impossible -- then (3) close the real socket ourselves with
    // lwip_close(), the lwip-namespace close that can NEVER dispatch into the
    // LittleFS VFS. We only issue the explicit close when the link is not
    // suspect and the fd still looks like a live socket; on the suspect path
    // we skip it (the socket was almost certainly already torn down by the
    // stack), trading a rare, recoverable socket leak for guaranteed
    // crash-safety.
    if (_secureClient)
    {
      const int fd = _secureClient->fd();
      (void)_secureClient->socket(); // intentional side-effect: assign -1

      if (!linkSuspect && fd >= 0 && isLwipSocket(fd))
      {
        lwip_close(fd); // lwip namespace: cannot dispatch into LittleFS
      }
      else if (fd >= 0)
      {
        debugW("teardown: not closing fd %d via close() (linkSuspect=%d)",
               fd, static_cast<int>(linkSuspect));
      }
    }

    if (_http)
    {
      _http->end(); // safe: underlying client's fd is already -1
      delete _http;
      _http = nullptr;
    }

    if (_secureClient)
    {
      // Re-neutralise the socket fd to -1 IMMEDIATELY before destruction.
      // The socket() call near the top of teardown() already set it to -1,
      // but _http->end() and ~HTTPClient run in between and can leave a
      // (recycled) fd in the sslclient context again. ~WiFiClientSecure ->
      // stop() issues the VFS-routed close() on any fd >= 0; if that fd was
      // recycled from a freed socket to a LittleFS file, close() dispatches
      // into vfs_littlefs_close() -> lfs_file_close() and trips
      //   assert failed: lfs_file_close ... lfs_mlist_isopen(...)  -> panic.
      // Forcing -1 here, with nothing running before delete, makes stop()'s
      // close() an unconditional no-op. The real socket, when live and the
      // link is healthy, was already closed via lwip_close() in the guard
      // above (lwip namespace, can never dispatch into LittleFS).
      (void)_secureClient->socket(); // intentional side-effect: assign -1
      delete _secureClient;
      _secureClient = nullptr;
    }

    _lastUsedMs = 0;
    _lastSeenDisconnectSeq = _netLink ? _netLink->disconnectEventSeq() : 0;
  }

  WiFiClientSecure *ConnectionPool::acquireClient()
  {
    if (WiFi.status() != WL_CONNECTED)
      return nullptr;

    // If WiFi disconnected since this client was set up, the cached lwip
    // socket fd may already have been freed and recycled to another VFS
    // driver. Force a safe teardown BEFORE we touch _secureClient->connected()
    // (which itself can drive stop()->close() on the stale fd).
    const uint32_t curSeq = _netLink ? _netLink->disconnectEventSeq() : 0;
    if (_secureClient && curSeq != _lastSeenDisconnectSeq)
    {
      debugI("acquireClient: disconnect seq advanced (%lu -> %lu); safe teardown",
             static_cast<unsigned long>(_lastSeenDisconnectSeq),
             static_cast<unsigned long>(curSeq));
      teardown(/*linkSuspect=*/true);
    }

    if (_secureClient && !_secureClient->connected())
      teardown();

    // Recycle stale connections before handing one out.
    recycleIfStale();

    if (!_secureClient)
    {
      _secureClient = new WiFiClientSecure();
      if (!_secureClient)
      {
        debugE("Failed to allocate WiFiClientSecure");
        return nullptr;
      }

      // TODO(security): Replace setInsecure() with setCACert() using the
      // server's root CA to enable proper TLS verification.
      _secureClient->setInsecure();
      _secureClient->setHandshakeTimeout(30);
      // FIX: baseline from a FRESH read, not the stale curSeq snapshot taken at
      // the top of acquireClient(). If a disconnect fired during this call, curSeq
      // is already outdated and would make the next acquire tear down this
      // brand-new client needlessly (extra handshake during WiFi instability).
      _lastSeenDisconnectSeq = _netLink ? _netLink->disconnectEventSeq() : 0;

      debugD("Allocated new WiFiClientSecure");
    }

    return _secureClient;
  }

  HTTPClient *ConnectionPool::acquireHttp()
  {
    if (WiFi.status() != WL_CONNECTED)
      return nullptr;

    // FIX(use-after-free): acquireHttp() must NOT probe _secureClient->connected()
    // or tear the pool down. Connection validity + teardown are owned entirely by
    // acquireClient(), which the caller invokes FIRST. Previously this re-probed
    // connected() and, if a keep-alive FIN landed between the two acquire calls,
    // ran teardown() -- freeing the very WiFiClientSecure the caller had already
    // taken from acquireClient() -- leaving that pointer dangling for the
    // subsequent http->begin(*client)/client->connected() (heap corruption/panic).
    // Since teardown() always frees _http together with _secureClient, whenever
    // acquireClient() rebuilds the client it leaves _http == nullptr, so a fresh
    // HTTPClient is allocated here anyway; no second connectivity check is needed.
    if (!_http)
    {
      _http = new HTTPClient();
      if (!_http)
      {
        debugE("Failed to allocate HTTPClient");
        return nullptr;
      }

      _http->setReuse(true);
      _http->setUserAgent(HTTP::userAgent());

      debugD("Allocated new HTTPClient with keep-alive");
    }

    return _http;
  }

  void ConnectionPool::markUsed()
  {
    _lastUsedMs = millis();
  }

  void ConnectionPool::invalidate()
  {
    debugD("Connection invalidated; tearing down for fresh handshake");
    teardown();
  }

  void ConnectionPool::recycleIfStale()
  {
    if (!_secureClient || _lastUsedMs == 0)
      return;

    // Same race protection as acquireClient(): if WiFi dropped since the
    // client was set up, force a safe teardown before doing anything else.
    const uint32_t curSeq = _netLink ? _netLink->disconnectEventSeq() : 0;
    if (curSeq != _lastSeenDisconnectSeq)
    {
      debugI("recycleIfStale: disconnect seq advanced (%lu -> %lu); safe teardown",
             static_cast<unsigned long>(_lastSeenDisconnectSeq),
             static_cast<unsigned long>(curSeq));
      teardown(/*linkSuspect=*/true);
      return;
    }

    const uint32_t elapsed = millis() - _lastUsedMs;
    if (elapsed >= IDLE_RECYCLE_MS)
    {
      debugI("Recycling idle connection (%lu ms idle)", static_cast<unsigned long>(elapsed));
      teardown();
    }
  }

  bool ConnectionPool::isConnected() const
  {
    if (!_secureClient)
      return false;
    // FIX: do NOT probe connected() when the link dropped since this client was
    // set up -- connected() can drive stop()->close() on a fd that may have been
    // recycled to a LittleFS file (the lfs_file_close panic class). Being const,
    // this accessor cannot perform the safe teardown, so it reports "not
    // connected" on a seq advance; the next acquireClient() tears down safely.
    const uint32_t curSeq = _netLink ? _netLink->disconnectEventSeq() : 0;
    if (curSeq != _lastSeenDisconnectSeq)
      return false;
    return _secureClient->connected();
  }

} // namespace HTTP
