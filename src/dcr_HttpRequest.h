#pragma once
// ═══════════════════════════════════════════════════════════════════
//  httpRequest.h – Unified HTTP client over WiFi
// ═══════════════════════════════════════════════════════════════════
//
//  Provides a single request pipeline that:
//    • Manages persistent headers (e.g. auth tokens)
//    • Deduplicates failure logs to the server log service
//    • Applies device identity headers to every request
//
//  All public functions are thread-safe.
//

#include <dcr_taskManager/FreeRtosRaii.h>
#include <HTTPClient.h>
#include <WiFi.h>
#include <WiFiClientSecure.h>

#include <cstddef>
#include <cstdint>
#include <functional>
#include <vector>

namespace HTTP
{

  // ─── Result types ──────────────────────────────────────────

  struct HttpResponse
  {
    int statusCode = -1;
    String payload;
    String error;
    bool success = false;
  };

  // ─── Lifecycle ─────────────────────────────────────────────

  /// Create HTTP subsystem mutexes and clear state. Call once from setup().
  void init();

  /// Exposes the request-serialisation mutex. Callers that bypass HTTP::get()
  /// and friends (e.g. OTA HTTPS streaming, HTTPS worker pre-check) must take
  /// this lock around their HTTPClient usage to serialise with the library.
  FreeRtosRaii::Mutex &requestMutex();

  // ─── Customisation hooks ───────────────────────────────────

  /// Set the User-Agent header sent with every request. Default: "esp32-httpclient".
  void setUserAgent(const String &userAgent);
  String userAgent();

  /// Register an application sink that receives failure information for
  /// dedup'd remote logging (e.g. ServerLogService::log). Pass nullptr to clear.
  using FailureLogger = std::function<void(int statusCode,
                                           const String &method,
                                           const String &url,
                                           const String &response,
                                           const std::vector<String> &latestLogs)>;
  void setFailureLogger(FailureLogger logger);

  /// Configure the API base URL used for dedup signature computation. URLs
  /// starting with this prefix are reported as relative paths in failure
  /// signatures. Default: empty (no prefix stripping).
  void setServerEndpoint(const String &baseUrl);

  /// Register a callback that adds project-specific device identity headers
  /// (e.g. device MAC, serial number, custom auth tokens) to every request.
  /// Default: no headers added.
  using DeviceIdentityProvider = std::function<void(std::vector<String> &headers)>;
  void setDeviceIdentityProvider(DeviceIdentityProvider provider);

  /// Receives the Unix epoch from the Date header of every successful pooled
  /// (API host) response. Lets the application keep a clock without NTP.
  using ServerTimeSink = std::function<void(uint32_t epoch)>;
  void setServerTimeSink(ServerTimeSink sink);

  /// One record per finished request, delivered on the requesting task after
  /// the request mutex is released. `url` is only valid during the call.
  struct RequestEvent
  {
    const char *method;
    const char *url;
    int statusCode;      // >0 HTTP status, <0 HTTPClient error, -1 if never sent
    uint32_t durationMs; // whole request, including the mutex wait
    uint32_t beginMs;    // DNS + connect + TLS; ~0 on a reused socket
    uint32_t requestMs;  // send + response headers
    const char *stage;   // completed, http-status, http-begin, http-request, http-closed, no-network, mutex
    bool pooled;
    bool reused;  // pooled attempt went out on the existing socket
    bool retried; // pooled: second attempt on a fresh socket
    size_t payloadBytes;
  };
  using RequestObserver = std::function<void(const RequestEvent &)>;
  void setRequestObserver(RequestObserver observer);

  // ─── Request API ───────────────────────────────────────────
  //
  // Each function blocks until the request completes (or times out).
  // `headers` is a newline-separated "Key: Value" string appended to
  // persistent headers and device identity headers.
  //

  HttpResponse get(
      const String &url,
      const String &headers = "",
      int timeoutMs = 10000,
      bool logErrors = true);

  HttpResponse post(
      const String &url,
      const String &payload,
      const String &contentType = "application/json",
      const String &headers = "",
      int timeoutMs = 10000,
      bool logErrors = true);

  HttpResponse postBinary(
      const String &url,
      const uint8_t *data,
      size_t length,
      const String &contentType = "application/octet-stream",
      const String &headers = "",
      int timeoutMs = 10000,
      bool logErrors = true);

  HttpResponse put(
      const String &url,
      const String &payload,
      const String &contentType = "application/json",
      const String &headers = "",
      int timeoutMs = 10000,
      bool logErrors = true);

  HttpResponse del(
      const String &url,
      const String &headers = "",
      int timeoutMs = 10000,
      bool logErrors = true);

  /// Low-level entry point for callers that need a custom HTTPClient lambda.
  HttpResponse performHttpRequest(
      const char *method,
      const String &url,
      std::function<int(HTTPClient *)> requestFn,
      int timeoutMs = 10000,
      const String &requestBody = "",
      bool logErrors = true,
      const String &additionalHeaders = "");

  // ─── Persistent headers ────────────────────────────────────

  void addCustomHeaders(const String &headers);
  String getCustomHeaders();
  int getHeadersCount();
  void clearCustomHeaders();

  // ─── Device identity ───────────────────────────────────────

  void appendDeviceIdentityHeaders(String &headers);
  void addDeviceIdentityHeaders(HTTPClient &client);

  // ─── Utilities ─────────────────────────────────────────────

  bool isHttpsUrl(const String &url);
  String formatHttpError(int statusCode, const String &response);
  String urlEncode(const String &s);

} // namespace HTTP