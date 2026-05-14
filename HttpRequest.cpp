#include "httpClient/HttpRequest.h"

#include "httpClient/HttpConnectionPool.h"

#include <rtosUtils/FreeRtosRaii.h>
#include <rtosUtils/MutexRegistry.h>
#include <logger/Logger.h>
#include <netLink/NetLink.h>
#include <esp_heap_caps.h>
#include <ESP.h>

#include <algorithm>
#include <array>
#include <cstring>

#undef LOG_TAG
#define LOG_TAG "HTTP"

// ═══════════════════════════════════════════════════════════════════
//  RAII helpers
// ═══════════════════════════════════════════════════════════════════

namespace
{
  using CompletionSignal = FreeRtosRaii::BinarySemaphore;

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════
//  Constants
// ═══════════════════════════════════════════════════════════════════

namespace
{
  constexpr uint32_t LOW_INTERNAL_HEAP_THRESHOLD = 16u * 1024u;
  constexpr uint32_t LOW_INTERNAL_HEAP_RECOVERY_COOLDOWN_MS = 10ul * 60ul * 1000ul;
  constexpr uint32_t HTTP_FAILURE_DEDUPE_WINDOW_MS = 60ul * 1000ul;
  constexpr size_t HTTP_FAILURE_DEDUPE_HISTORY = 16;

  constexpr TickType_t MUTEX_WAIT_SHORT = pdMS_TO_TICKS(500);
  constexpr TickType_t MUTEX_WAIT_DEFAULT = pdMS_TO_TICKS(1000);
  constexpr TickType_t MUTEX_WAIT_REQUEST = pdMS_TO_TICKS(15000);

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════
//  Module state
// ═══════════════════════════════════════════════════════════════════

namespace HTTP
{
  static std::vector<String> s_persistentHeaders;
  static uint32_t s_lastLowInternalHeapRecoveryMs = 0;
  static String s_userAgent = "esp32-httpclient";
  static FailureLogger s_failureLogger;

  static FreeRtosRaii::Mutex &httpRequestMutex()
  {
    static FreeRtosRaii::Mutex m{FreeRtosRaii::DeferredCreate};
    return m;
  }
  static FreeRtosRaii::Mutex &httpHeadersMutex()
  {
    static FreeRtosRaii::Mutex m{FreeRtosRaii::DeferredCreate};
    return m;
  }
  static FreeRtosRaii::Mutex &httpHeapRecoveryMutex()
  {
    static FreeRtosRaii::Mutex m{FreeRtosRaii::DeferredCreate};
    return m;
  }
  static FreeRtosRaii::Mutex &httpFailureDedupMutex()
  {
    static FreeRtosRaii::Mutex m{FreeRtosRaii::DeferredCreate};
    return m;
  }

  static String s_serverEndpoint;
  static DeviceIdentityProvider s_deviceIdentityProvider;

  FreeRtosRaii::Mutex &requestMutex() { return httpRequestMutex(); }
  void setUserAgent(const String &userAgent) { s_userAgent = userAgent; }
  String userAgent() { return s_userAgent; }
  void setFailureLogger(FailureLogger logger) { s_failureLogger = std::move(logger); }
  void setServerEndpoint(const String &baseUrl) { s_serverEndpoint = baseUrl; }
  void setDeviceIdentityProvider(DeviceIdentityProvider provider) { s_deviceIdentityProvider = std::move(provider); }
} // namespace HTTP

// ═══════════════════════════════════════════════════════════════════
//  Header helpers
// ═══════════════════════════════════════════════════════════════════

namespace
{
  void parseHeaderLines(const String &raw, std::vector<String> &dest)
  {
    if (raw.length() == 0)
      return;

    int start = 0;
    while (true)
    {
      const int end = raw.indexOf('\n', start);
      String line = (end >= 0) ? raw.substring(start, end)
                               : raw.substring(start);
      line.trim();
      if (line.length() > 0 && line.indexOf(':') >= 0)
        dest.push_back(std::move(line));
      if (end < 0)
        break;
      start = end + 1;
    }
  }

  int findHeaderByKey(const std::vector<String> &headers, const String &key)
  {
    for (size_t i = 0; i < headers.size(); ++i)
    {
      const int sep = headers[i].indexOf(':');
      if (sep < 0)
        continue;

      String existing = headers[i].substring(0, sep);
      existing.trim();
      if (existing.equalsIgnoreCase(key))
        return static_cast<int>(i);
    }
    return -1;
  }

  void upsertHeader(std::vector<String> &headers,
                    const String &key, const String &value)
  {
    String line = key + ": " + value;
    const int idx = findHeaderByKey(headers, key);
    if (idx >= 0)
      headers[idx] = std::move(line);
    else
      headers.push_back(std::move(line));
  }

  void applyDeviceIdentityHeaders(std::vector<String> &headers)
  {
    if (HTTP::s_deviceIdentityProvider)
      HTTP::s_deviceIdentityProvider(headers);
  }

  void applyHeadersToClient(HTTPClient &client,
                            const std::vector<String> &headers)
  {
    for (const auto &h : headers)
    {
      const int sep = h.indexOf(':');
      if (sep < 0)
        continue;
      String key = h.substring(0, sep);
      String val = h.substring(sep + 1);
      key.trim();
      val.trim();
      client.addHeader(key, val);
    }
  }

  String joinHeaders(const std::vector<String> &headers)
  {
    String result;
    for (const auto &h : headers)
    {
      result += h;
      result += '\n';
    }
    return result;
  }

  /// Build a merged header set: persistent + additional + device identity.
  std::vector<String> buildMergedHeaders(const String &additionalHeaders)
  {
    std::vector<String> merged;

    if (auto lock = FreeRtosRaii::tryLock(HTTP::httpHeadersMutex(), MUTEX_WAIT_SHORT))
      merged = HTTP::s_persistentHeaders;

    parseHeaderLines(additionalHeaders, merged);
    applyDeviceIdentityHeaders(merged);
    return merged;
  }

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════
//  Failure log deduplication
// ═══════════════════════════════════════════════════════════════════

namespace
{

  struct FailureDedupEntry
  {
    String signature;
    uint32_t lastLoggedMs = 0;
  };

  std::vector<FailureDedupEntry> s_recentFailures;

  String classifyFailureCategory(int statusCode, const String &error)
  {
    String lowered = error;
    lowered.toLowerCase();

    if (lowered.indexOf("failed to acquire") >= 0 ||
        lowered.indexOf("no network connection") >= 0 ||
        lowered.indexOf("queue full") >= 0)
      return "local";

    if (statusCode <= 0)
    {
      if (lowered.indexOf("dns") >= 0 || lowered.indexOf("hostbyname") >= 0)
        return "dns";
      if (lowered.indexOf("timeout") >= 0 || lowered.indexOf("timed out") >= 0)
        return "timeout";
      return "transport";
    }

    if (statusCode >= 500)
      return "server";
    if (statusCode >= 400)
      return "client";

    return "other";
  }

  String extractEndpointPath(const String &url)
  {
    const String base = HTTP::s_serverEndpoint;
    if (url.startsWith(base))
      return url.substring(base.length());

    const int scheme = url.indexOf("://");
    const int slash = url.indexOf('/', scheme >= 0 ? scheme + 3 : 0);
    return (slash >= 0) ? url.substring(slash + 1) : url;
  }

  String buildFailureSignature(const char *method, const String &url,
                               int statusCode, const String &error)
  {
    return String(method) + "|" +
           extractEndpointPath(url) + "|" +
           classifyFailureCategory(statusCode, error);
  }

  /// Returns true if this failure should be logged (not a duplicate).
  bool shouldLogFailure(const String &signature, uint32_t nowMs)
  {
    auto lock = FreeRtosRaii::tryLock(HTTP::httpFailureDedupMutex(), MUTEX_WAIT_SHORT);
    if (!lock)
      return true; // If we cannot acquire the lock, err on the side of logging.

    for (auto &entry : s_recentFailures)
    {
      if (entry.signature != signature)
        continue;

      const uint32_t elapsed = nowMs - entry.lastLoggedMs;
      if (elapsed < HTTP_FAILURE_DEDUPE_WINDOW_MS)
      {
        // BUG FIX: Do NOT update lastLoggedMs here. The original code
        // caused the dedup window to slide forward indefinitely,
        // suppressing all repeat failures after the first one.
        return false;
      }

      entry.lastLoggedMs = nowMs;
      return true;
    }

    // New signature: record it.
    if (s_recentFailures.size() >= HTTP_FAILURE_DEDUPE_HISTORY)
      s_recentFailures.erase(s_recentFailures.begin());

    s_recentFailures.push_back({signature, nowMs});
    return true;
  }

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════
//  Diagnostics and logging
// ═══════════════════════════════════════════════════════════════════

namespace
{

  struct WiFiRequestTrace
  {
    const char *failureStage = "not-started";
    unsigned long beginMs = 0;
    unsigned long requestMs = 0;
  };

  struct HeapSnapshot
  {
    uint32_t freeHeap;
    uint32_t maxAllocHeap;
    uint32_t internalLargestBlock;
    wl_status_t wifiStatus;
    int rssi;
  };

  HeapSnapshot captureHeapSnapshot()
  {
    const wl_status_t status = WiFi.status();
    return {
        .freeHeap = ESP.getFreeHeap(),
        .maxAllocHeap = ESP.getMaxAllocHeap(),
        .internalLargestBlock = heap_caps_get_largest_free_block(MALLOC_CAP_INTERNAL),
        .wifiStatus = status,
        .rssi = (status == WL_CONNECTED) ? WiFi.RSSI() : 0,
    };
  }

  void scheduleLowHeapRecovery(uint32_t internalLargestBlock)
  {
    if (internalLargestBlock >= LOW_INTERNAL_HEAP_THRESHOLD)
      return;

    // Guard with a dedicated mutex so multiple tasks don't race on the
    // cooldown timestamp.
    auto lock = FreeRtosRaii::tryLock(HTTP::httpHeapRecoveryMutex(), MUTEX_WAIT_SHORT);
    if (!lock)
      return;

    const uint32_t nowMs = millis();
    if (HTTP::s_lastLowInternalHeapRecoveryMs != 0)
    {
      const uint32_t elapsed = nowMs - HTTP::s_lastLowInternalHeapRecoveryMs;
      if (elapsed < LOW_INTERNAL_HEAP_RECOVERY_COOLDOWN_MS)
        return;
    }

    HTTP::s_lastLowInternalHeapRecoveryMs = nowMs;

    debugW("Internal heap largest block low (%u B); freeing pool TLS context "
           "and cycling WiFi",
           internalLargestBlock);

    // The connection pool's WiFiClientSecure owns a mbedTLS context that
    // lives in DRAM and is typically the largest single internal-heap
    // consumer. Freeing it is the most direct way to recover headroom;
    // cycling WiFi alone leaves the TLS state allocated. The pool
    // contract requires HTTP::httpRequestMutex(), so we take it here. If we
    // cannot acquire it within the short wait, skip the invalidate — the
    // next failed request will tear the connection down on its own.
    if (auto requestLock = FreeRtosRaii::tryLock(HTTP::httpRequestMutex(),
                                                 MUTEX_WAIT_DEFAULT))
      HTTP::connectionPool.invalidate();
    else
      debugW("Skipping pool invalidate during recovery; request mutex busy");

    // Use the silent reconnect path so the user's current screen is not
    // covered by "WiFi Disconnect / Please Wait" popups during recovery.
    netLink.requestSilentReconnect();
  }

  void logRequestError(const char *method, const String &url,
                       unsigned long ms, int code, const String &err,
                       const String &reqBody, const String &resBody,
                       const WiFiRequestTrace *trace = nullptr)
  {
    const auto snap = captureHeapSnapshot();

    debugE("%s %s failed after %lums | Code: %d | %s",
           method, url.c_str(), ms, code, err.c_str());

    if (trace)
      debugE("WiFi stages | begin: %lums | request: %lums",
             trace->beginMs, trace->requestMs);

    debugE("Diagnostics | Free heap: %u | Largest block: %u | "
           "Internal largest: %u | WiFi: %d | RSSI: %d",
           snap.freeHeap, snap.maxAllocHeap, snap.internalLargestBlock,
           static_cast<int>(snap.wifiStatus), snap.rssi);

    scheduleLowHeapRecovery(snap.internalLargestBlock);

    if (reqBody.length() > 0)
      debugE("Request body (%d B): %s", reqBody.length(), reqBody.c_str());
    if (resBody.length() > 0)
      debugE("Response body (%d B): %s", resBody.length(), resBody.c_str());
    else
      debugE("Response body: <empty>");
  }

  void logRequestSuccess(const char *method, const String &url,
                         unsigned long ms, int code)
  {
    debugD("%s %s completed in %lums | Code: %d",
           method, url.c_str(), ms, code);
  }

  void logRequestVerbose(const char *method,
                         const std::vector<String> &reqHeaders,
                         const String &reqBody,
                         const String &resHeaders,
                         const String &resBody)
  {
    if (!reqHeaders.empty())
    {
      debugV("Request headers:");
      for (const auto &h : reqHeaders)
        debugV("  %s", h.c_str());
    }
    if (reqBody.length() > 0)
      debugV("Request body (%d B):\n%s", reqBody.length(), reqBody.c_str());
    if (resHeaders.length() > 0)
      debugV("Response headers:\n%s", resHeaders.c_str());
    if (resBody.length() > 0)
      debugV("Response body (%d B):\n%s", resBody.length(), resBody.c_str());
  }

  void queueFailureLog(const char *method, const String &url, int /*timeout*/,
                       const std::vector<String> & /*headers*/,
                       const String & /*requestBody*/, int statusCode,
                       const String &error, const String &responseBody,
                       unsigned long /*durationMs*/, bool logErrors)
  {
    if (!logErrors)
      return;
    if (!HTTP::s_failureLogger)
      return;

    const uint32_t nowMs = millis();
    const String sig = buildFailureSignature(method, url, statusCode, error);
    if (!shouldLogFailure(sig, nowMs))
      return;

    HTTP::s_failureLogger(statusCode, String(method), url, responseBody,
                          LoggerInternal::GetLatestLogs());
  }

  bool isWiFiAvailable()
  {
    return WiFi.status() == WL_CONNECTED;
  }

} // anonymous namespace

// ═══════════════════════════════════════════════════════════════════
//  WiFi transport
// ═══════════════════════════════════════════════════════════════════

namespace
{
  String extractResponseHeaders(HTTPClient &client)
  {
    String out;
    for (int i = 0; i < client.headers(); ++i)
    {
      out += client.headerName(i);
      out += ": ";
      out += client.header(i);
      out += '\n';
    }
    return out;
  }

  /// Returns true if this URL targets the primary API and can use the
  /// connection pool. Other hosts (e.g. OTA, stress test endpoints)
  /// fall back to one-shot connections.
  bool isPoolableUrl(const String &url)
  {
    return !HTTP::s_serverEndpoint.isEmpty() && url.startsWith(HTTP::s_serverEndpoint);
  }

  /// Execute an HTTP request using the persistent connection pool.
  /// The caller must hold HTTP::httpRequestMutex().
  HTTP::HttpResponse executePooledRequest(
      const char *method,
      const String &url,
      std::function<int(HTTPClient *)> requestFn,
      int timeoutMs,
      const String &requestBody,
      const std::vector<String> &headers,
      WiFiRequestTrace &trace)
  {
    HTTP::HttpResponse response;
    bool invalidated = false;

    WiFiClientSecure *client = HTTP::connectionPool.acquireClient();
    HTTPClient *http = HTTP::connectionPool.acquireHttp();
    if (!client || !http)
    {
      response.error = "Connection pool allocation failed";
      return response;
    }

    http->setTimeout(timeoutMs);

    trace.failureStage = "http-begin";
    const unsigned long t0 = millis();
    const bool begun = http->begin(*client, url);
    trace.beginMs = millis() - t0;

    if (!begun)
    {
      response.error = "HTTP begin() failed";
      HTTP::connectionPool.invalidate();
      invalidated = true;
      return response;
    }

    applyHeadersToClient(*http, headers);

    trace.failureStage = "http-request";
    const unsigned long t1 = millis();
    response.statusCode = requestFn(http);
    trace.requestMs = millis() - t1;

    if (response.statusCode > 0)
    {
      response.payload = http->getString();
      response.success = (response.statusCode >= 200 && response.statusCode < 300);

      if (!response.success)
      {
        trace.failureStage = "http-status";
        response.error = HTTP::formatHttpError(response.statusCode,
                                               response.payload);
      }
      else
      {
        trace.failureStage = "completed";
      }
    }
    else
    {
      response.error = "HTTP error code: " + String(response.statusCode);
      // Negative status means transport failure; tear down so next
      // request gets a fresh TLS handshake.
      HTTP::connectionPool.invalidate();
      invalidated = true;
    }

    const String resHeaders = (response.statusCode > 0 && !invalidated)
                                  ? extractResponseHeaders(*http)
                                  : String();
    logRequestVerbose(method, headers, requestBody, resHeaders,
                      response.payload);
    debugV("Pooled request %s %s | begin: %lums | request: %lums",
           method, url.c_str(), trace.beginMs, trace.requestMs);

    if (response.success && !invalidated && !client->connected())
    {
      trace.failureStage = "http-closed";
      response.success = false;
      response.error = "HTTP connection closed during read";
      HTTP::connectionPool.invalidate();
      invalidated = true;
    }

    if (response.success && !invalidated)
      HTTP::connectionPool.markUsed();

    if (!invalidated)
      http->end();

    return response;
  }

  /// Execute a one-shot HTTP request (non-pooled). Used for URLs that
  /// are not the primary API server.
  HTTP::HttpResponse executeOneShotRequest(
      const char *method,
      const String &url,
      std::function<int(HTTPClient *)> requestFn,
      int timeoutMs,
      const String &requestBody,
      const std::vector<String> &headers,
      WiFiRequestTrace &trace)
  {
    HTTP::HttpResponse response;
    HTTPClient http;

    http.setUserAgent(HTTP::userAgent());
    http.setTimeout(timeoutMs);

    const bool https = HTTP::isHttpsUrl(url);

    // TODO(security): Replace setInsecure() with setCACert() using the
    // server's root CA to enable proper TLS verification.
    WiFiClientSecure httpsClient;
    WiFiClient tcpClient;
    if (https)
      httpsClient.setInsecure();

    trace.failureStage = "http-begin";
    const unsigned long t0 = millis();
    const bool begun = https ? http.begin(httpsClient, url)
                             : http.begin(tcpClient, url);
    trace.beginMs = millis() - t0;

    if (!begun)
    {
      response.error = "HTTP begin() failed";
      return response;
    }

    applyHeadersToClient(http, headers);

    trace.failureStage = "http-request";
    const unsigned long t1 = millis();
    response.statusCode = requestFn(&http);
    trace.requestMs = millis() - t1;

    if (response.statusCode > 0)
    {
      response.payload = http.getString();
      response.success = (response.statusCode >= 200 && response.statusCode < 300);

      if (!response.success)
      {
        trace.failureStage = "http-status";
        response.error = HTTP::formatHttpError(response.statusCode,
                                               response.payload);
      }
      else
      {
        trace.failureStage = "completed";
      }
    }
    else
    {
      response.error = "HTTP error code: " + String(response.statusCode);
    }

    const String resHeaders = (response.statusCode > 0)
                                  ? extractResponseHeaders(http)
                                  : String();
    logRequestVerbose(method, headers, requestBody, resHeaders,
                      response.payload);
    debugV("WiFi stages for %s %s | begin: %lums | request: %lums",
           method, url.c_str(), trace.beginMs, trace.requestMs);

    http.end();
    return response;
  }

} // anonymous namespace


// ═══════════════════════════════════════════════════════════════════
//  Core request orchestrator
// ═══════════════════════════════════════════════════════════════════

namespace HTTP
{
  namespace
  {

    HttpResponse orchestrateRequest(
        const char *method,
        const String &url,
        std::function<int(HTTPClient *)> wifiFn,
        int timeoutMs,
        const String &requestBody,
        bool logErrors,
        const String &additionalHeaders)
    {
      HttpResponse response;
      const unsigned long startMs = millis();
      const auto allHeaders = buildMergedHeaders(additionalHeaders);

      if (!isWiFiAvailable())
      {
        response.error = "No network connection";
        const unsigned long dur = millis() - startMs;
        if (logErrors)
          logRequestError(method, url, dur, -1, response.error,
                          requestBody, "");
        queueFailureLog(method, url, timeoutMs, allHeaders, requestBody,
                        response.statusCode, response.error, "",
                        dur, logErrors);
        return response;
      }

      WiFiRequestTrace trace;
      // The request mutex is held only for the duration of the actual
      // request. Diagnostic logging and failure-queue work below run
      // without it, so a slow log path can't stall the next request and
      // so scheduleLowHeapRecovery (which itself takes the request mutex
      // to invalidate the pool) doesn't recurse into a held lock.
      {
        auto lock = FreeRtosRaii::tryLock(HTTP::httpRequestMutex(), MUTEX_WAIT_REQUEST);
        if (!lock)
        {
          response.error = "Failed to acquire HTTP request mutex";
          const unsigned long dur = millis() - startMs;
          if (logErrors)
            logRequestError(method, url, dur, -1, response.error,
                            requestBody, "");
          queueFailureLog(method, url, timeoutMs, allHeaders, requestBody,
                          response.statusCode, response.error, "",
                          dur, logErrors);
          return response;
        }

        if (isPoolableUrl(url))
        {
          response = executePooledRequest(method, url, wifiFn, timeoutMs,
                                        requestBody, allHeaders, trace);
        }
        else
        {
          response = executeOneShotRequest(method, url, wifiFn, timeoutMs,
                                           requestBody, allHeaders, trace);
        }
      }
      // HTTP::httpRequestMutex() released here as `lock` goes out of scope.

      const unsigned long dur = millis() - startMs;
      const bool isError = !response.success;

      if (isError)
      {
        if (logErrors)
          logRequestError(method, url, dur, response.statusCode,
                          response.error, requestBody, response.payload,
                          &trace);
        queueFailureLog(method, url, timeoutMs, allHeaders, requestBody,
                        response.statusCode, response.error,
                        response.payload, dur, logErrors);
      }
      else
      {
        logRequestSuccess(method, url, dur, response.statusCode);
      }

      return response;
    }

  } // anonymous namespace

  // ═══════════════════════════════════════════════════════════════
  //  Public API
  // ═══════════════════════════════════════════════════════════════

  void init()
  {
    HTTP::httpRequestMutex().ensureCreated();
    HTTP::httpHeadersMutex().ensureCreated();
    HTTP::httpHeapRecoveryMutex().ensureCreated();
    HTTP::httpFailureDedupMutex().ensureCreated();

    RtosUtils::registerMutex(HTTP::httpRequestMutex(), "http.request");
    RtosUtils::registerMutex(HTTP::httpHeadersMutex(), "http.headers");
    RtosUtils::registerMutex(HTTP::httpHeapRecoveryMutex(), "http.heapRecovery");
    RtosUtils::registerMutex(HTTP::httpFailureDedupMutex(), "http.failureDedup");

    if (auto lock = FreeRtosRaii::tryLock(HTTP::httpHeadersMutex()))
      s_persistentHeaders.clear();

    if (auto lock = FreeRtosRaii::tryLock(HTTP::httpFailureDedupMutex()))
    {
      s_recentFailures.clear();
      s_recentFailures.reserve(HTTP_FAILURE_DEDUPE_HISTORY);
    }
  }

  bool isHttpsUrl(const String &url) { return url.startsWith("https://"); }

  String formatHttpError(int statusCode, const String &response)
  {
    String err = "HTTP Error " + String(statusCode);
    if (response.length() > 0)
    {
      err += ": ";
      err += response;
    }
    return err;
  }

  // ── Persistent header management ───────────────────────────

  void addCustomHeaders(const String &headers)
  {
    if (auto lock = FreeRtosRaii::tryLock(HTTP::httpHeadersMutex()))
      parseHeaderLines(headers, s_persistentHeaders);
  }

  String getCustomHeaders()
  {
    String out;
    if (auto lock = FreeRtosRaii::tryLock(HTTP::httpHeadersMutex()))
    {
      for (const auto &h : s_persistentHeaders)
      {
        out += h;
        out += '\n';
      }
    }
    return out;
  }

  int getHeadersCount()
  {
    if (auto lock = FreeRtosRaii::tryLock(HTTP::httpHeadersMutex()))
      return static_cast<int>(s_persistentHeaders.size());
    return 0;
  }

  void clearCustomHeaders()
  {
    if (auto lock = FreeRtosRaii::tryLock(HTTP::httpHeadersMutex()))
      s_persistentHeaders.clear();
  }

  void appendDeviceIdentityHeaders(String &headers)
  {
    std::vector<String> parsed;
    parseHeaderLines(headers, parsed);
    applyDeviceIdentityHeaders(parsed);
    headers = joinHeaders(parsed);
    if (headers.endsWith("\n"))
      headers.remove(headers.length() - 1);
  }

  void addDeviceIdentityHeaders(HTTPClient &client)
  {
    if (!HTTP::s_deviceIdentityProvider)
      return;
    std::vector<String> headers;
    HTTP::s_deviceIdentityProvider(headers);
    applyHeadersToClient(client, headers);
  }

  // ── Convenience wrappers ───────────────────────────────────
  //
  // BUG FIX: Lambda captures for `post()` and `put()` now take a copy
  // of the payload String rather than capturing by reference. The
  // original code captured `const String &payload` by reference; if the
  // caller's String went out of scope or was modified before the lambda
  // executed inside the WiFi request path, the reference would dangle.
  //

  HttpResponse get(const String &url, const String &headers,
                   int timeoutMs, bool logErrors)
  {
    return orchestrateRequest(
        "GET", url,
        [](HTTPClient *c)
        { return c ? c->GET() : -1; },
        timeoutMs, "", logErrors, headers);
  }

  HttpResponse post(const String &url, const String &payload,
                    const String &contentType, const String &headers,
                    int timeoutMs, bool logErrors)
  {
    String allH = "Content-Type: " + contentType;
    if (headers.length() > 0)
    {
      allH += '\n';
      allH += headers;
    }

    // Capture payload by value to avoid dangling reference.
    const String payloadCopy = payload;
    return orchestrateRequest(
        "POST", url,
        [payloadCopy](HTTPClient *c)
        {
          return c ? c->POST(payloadCopy) : -1;
        },
        timeoutMs, payloadCopy, logErrors, allH);
  }

  HttpResponse postBinary(const String &url, const uint8_t *data,
                          size_t length, const String &contentType,
                          const String &headers, int timeoutMs,
                          bool logErrors)
  {
    String allH = "Content-Type: " + contentType;
    if (headers.length() > 0)
    {
      allH += '\n';
      allH += headers;
    }

    const String bodyDesc = "[Binary data: " + String(length) + " bytes]";

    return orchestrateRequest(
        "POST", url,
        [data, length](HTTPClient *c)
        {
          return c ? c->POST(const_cast<uint8_t *>(data), length) : -1;
        },
        timeoutMs, bodyDesc, logErrors, allH);
  }

  HttpResponse put(const String &url, const String &payload,
                   const String &contentType, const String &headers,
                   int timeoutMs, bool logErrors)
  {
    String allH = "Content-Type: " + contentType;
    if (headers.length() > 0)
    {
      allH += '\n';
      allH += headers;
    }

    const String payloadCopy = payload;
    return orchestrateRequest(
        "PUT", url,
        [payloadCopy](HTTPClient *c)
        {
          return c ? c->PUT(payloadCopy) : -1;
        },
        timeoutMs, payloadCopy, logErrors, allH);
  }

  HttpResponse del(const String &url, const String &headers,
                   int timeoutMs, bool logErrors)
  {
    return orchestrateRequest(
        "DELETE", url,
        [](HTTPClient *c)
        {
          return c ? c->sendRequest("DELETE") : -1;
        },
        timeoutMs, "", logErrors, headers);
  }

  HttpResponse performHttpRequest(
      const char *method, const String &url,
      std::function<int(HTTPClient *)> requestFn, int timeoutMs,
      const String &requestBody, bool logErrors,
      const String &additionalHeaders)
  {
    return orchestrateRequest(method, url, std::move(requestFn), timeoutMs,
                              requestBody, logErrors, additionalHeaders);
  }

  // ── URL encoding ───────────────────────────────────────────

  String urlEncode(const String &s)
  {
    static constexpr auto isUnreserved = [](char c) -> bool
    {
      return (c >= '0' && c <= '9') ||
             (c >= 'a' && c <= 'z') ||
             (c >= 'A' && c <= 'Z') ||
             c == '-' || c == '_' || c == '.' ||
             c == '!' || c == '~' || c == '*' ||
             c == '\'' || c == '(' || c == ')';
    };

    String out;
    out.reserve(s.length() * 2);

    for (size_t i = 0; i < s.length(); ++i)
    {
      const char c = s.charAt(i);
      if (isUnreserved(c))
      {
        out += c;
      }
      else if (c == ' ')
      {
        out += '+';
      }
      else
      {
        const auto hi = static_cast<uint8_t>(c) >> 4;
        const auto lo = static_cast<uint8_t>(c) & 0x0Fu;
        out += '%';
        out += static_cast<char>(hi <= 9 ? '0' + hi : 'a' + hi - 10);
        out += static_cast<char>(lo <= 9 ? '0' + lo : 'a' + lo - 10);
      }
    }
    return out;
  }

} // namespace HTTP