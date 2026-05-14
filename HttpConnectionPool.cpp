#include "httpClient/HttpConnectionPool.h"
#include "httpClient/HttpRequest.h"
#include <logger/Logger.h>
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
    // Order matters: clear the sslclient socket field FIRST, before any
    // _http->end() that could itself drive _client->stop()->close(fd).
    if (_secureClient)
    {
      const int fd = _secureClient->fd();
      const bool fdIsSuspect = linkSuspect || (fd >= 0 && !isLwipSocket(fd));

      if (fdIsSuspect)
      {
        debugW("teardown: fd %d suspect (linkSuspect=%d); skipping close()",
               fd, static_cast<int>(linkSuspect));
        (void)_secureClient->socket(); // intentional side-effect: assign -1
      }
    }

    if (_http)
    {
      _http->end();
      delete _http;
      _http = nullptr;
    }

    if (_secureClient)
    {
      if (!linkSuspect && _secureClient->fd() >= 0)
        _secureClient->stop();
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
      _lastSeenDisconnectSeq = curSeq; // baseline for this fresh client

      debugD("Allocated new WiFiClientSecure");
    }

    return _secureClient;
  }

  HTTPClient *ConnectionPool::acquireHttp()
  {
    if (WiFi.status() != WL_CONNECTED)
      return nullptr;

    if (_http && (!_secureClient || !_secureClient->connected()))
      teardown();

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
    return _secureClient && _secureClient->connected();
  }

} // namespace HTTP
