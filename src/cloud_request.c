// Function to upload logs to CloudWatch
#include "cloud_request.h"
#include "aws_sigv4.h"
#include "slf_backoff.h"
#include <core_http_client.h>
#include <errno.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/vector.h>
#include <netdb.h>
#include <openssl/ssl.h>
#include <string.h>
#include <sys/socket.h>
#include <transport_interface.h>
#include <unistd.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

// As Required by the sigv4 library
#define DATE_BUFFER_LEN (17)
#define MAX_AUTH_HEADER_LEN (1024)
#define MAX_SIGV4_HEADER_LEN (2048)

// HTTP request retry configuration
#define HTTP_RETRY_BASE_DELAY_MS (1000) // 1 second base delay
#define HTTP_RETRY_MAX_DELAY_MS (64000) // 64 second max delay

typedef struct {
    HttpEndpoint endpoint;
    GglBuffer payload;
    SigV4Details sigv4_details;
    const char *target;
    HTTPResponse_t *response_out;
    GglError err;
} HttpRequestRetryCtx;

static int32_t transport_send(
    NetworkContext_t *network_context, const void *buffer, size_t bytes_to_send
) {
    TLSContext *tls = (TLSContext *) network_context;
    return (int32_t) SSL_write(tls->ssl, buffer, (int) bytes_to_send);
}

static int32_t transport_recv(
    NetworkContext_t *network_context, void *buffer, size_t bytes_to_recv
) {
    TLSContext *tls = (TLSContext *) network_context;
    return (int32_t) SSL_read(tls->ssl, buffer, (int) bytes_to_recv);
}

static TLSContext *create_tls_connection(const HttpEndpoint *endpoint) {
    GGL_LOGT("Attempting to connect to %s:%s", endpoint->host, endpoint->port);

    static bool ssl_initialized = false;
    if (!ssl_initialized) {
        SSL_load_error_strings();
        OpenSSL_add_ssl_algorithms();
        ssl_initialized = true;
    }

    static TLSContext tls_context;
    TLSContext *tls = &tls_context;
    memset(tls, 0, sizeof(TLSContext));

    tls->ctx = SSL_CTX_new(TLS_client_method());
    if (!tls->ctx) {
        GGL_LOGE("Failed to create SSL context");
        return NULL;
    }

    // Set SSL options for better compatibility
    SSL_CTX_set_options(tls->ctx, SSL_OP_NO_SSLv2 | SSL_OP_NO_SSLv3);
    SSL_CTX_set_verify(tls->ctx, SSL_VERIFY_PEER, NULL);
    SSL_CTX_set_default_verify_paths(tls->ctx);

    struct addrinfo hints = { 0 };
    struct addrinfo *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    int dns_result
        = getaddrinfo(endpoint->host, endpoint->port, &hints, &result);
    if (dns_result != 0) {
        GGL_LOGE(
            "DNS resolution failed for %s:%s - %s",
            endpoint->host,
            endpoint->port,
            gai_strerror(dns_result)
        );
        SSL_CTX_free(tls->ctx);
        return NULL;
    }
    char error_buf[256] = { 0 };

    tls->sockfd
        = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (tls->sockfd < 0) {
        if (strerror_r(errno, error_buf, sizeof(error_buf)) != 0) {
            snprintf(error_buf, sizeof(error_buf), "Unknown error %d", errno);
        }
        GGL_LOGE("Failed to create socket: %s", error_buf);
        freeaddrinfo(result);
        SSL_CTX_free(tls->ctx);
        return NULL;
    }

    if (connect(tls->sockfd, result->ai_addr, result->ai_addrlen) < 0) {
        if (strerror_r(errno, error_buf, sizeof(error_buf)) != 0) {
            snprintf(error_buf, sizeof(error_buf), "Unknown error %d", errno);
        }
        GGL_LOGE(
            "Failed to connect to %s:%s - %s",
            endpoint->host,
            endpoint->port,
            error_buf
        );
        close(tls->sockfd);
        freeaddrinfo(result);
        SSL_CTX_free(tls->ctx);
        return NULL;
    }
    freeaddrinfo(result);

    tls->ssl = SSL_new(tls->ctx);
    if (!tls->ssl) {
        GGL_LOGE("Failed to create SSL object");
        close(tls->sockfd);
        SSL_CTX_free(tls->ctx);
        return NULL;
    }

    SSL_set_fd(tls->ssl, tls->sockfd);
    SSL_set_tlsext_host_name(tls->ssl, endpoint->host);

    int ssl_result = SSL_connect(tls->ssl);
    if (ssl_result <= 0) {
        int ssl_error = SSL_get_error(tls->ssl, ssl_result);
        GGL_LOGE(
            "SSL connection failed to %s:%s - SSL error: %d",
            endpoint->host,
            endpoint->port,
            ssl_error
        );
        SSL_free(tls->ssl);
        close(tls->sockfd);
        SSL_CTX_free(tls->ctx);
        return NULL;
    }

    GGL_LOGI(
        "Successfully connected to %s:%s with TLS",
        endpoint->host,
        endpoint->port
    );
    return tls;
}

static void close_tls_connection(TLSContext *tls) {
    if (tls) {
        if (tls->ssl) {
            SSL_shutdown(tls->ssl);
            SSL_free(tls->ssl);
        }
        if (tls->sockfd >= 0) {
            close(tls->sockfd);
        }
        if (tls->ctx) {
            SSL_CTX_free(tls->ctx);
        }
    }
}

const char *slf_http_status_to_string(HTTPStatus_t status) {
    switch (status) {
    case HTTPSuccess:
        return "Success";
    case HTTPInvalidParameter:
        return "InvalidParameter";
    case HTTPNetworkError:
        return "NetworkError";
    case HTTPPartialResponse:
        return "PartialResponse";
    case HTTPNoResponse:
        return "NoResponse";
    case HTTPInsufficientMemory:
        return "InsufficientMemory";
    case HTTPSecurityAlertExtraneousResponseData:
        return "SecurityAlertExtraneousResponseData";
    case HTTPSecurityAlertInvalidChunkHeader:
        return "SecurityAlertInvalidChunkHeader";
    case HTTPSecurityAlertInvalidProtocolVersion:
        return "SecurityAlertInvalidProtocolVersion";
    case HTTPSecurityAlertInvalidStatusCode:
        return "SecurityAlertInvalidStatusCode";
    case HTTPSecurityAlertInvalidCharacter:
        return "SecurityAlertInvalidCharacter";
    case HTTPSecurityAlertInvalidContentLength:
        return "SecurityAlertInvalidContentLength";
    case HTTPParserPaused:
        return "ParserPaused";
    case HTTPParserInternalError:
        return "ParserInternalError";
    case HTTPHeaderNotFound:
        return "HeaderNotFound";
    case HTTPInvalidResponse:
        return "InvalidResponse";
    default:
        return "Unknown HTTP Status";
    }
}

static bool slf_can_retry_http_status(uint16_t status_code) {
    switch (status_code) {
    case 408: // Request timeout
    case 429: // Too many requests
    case 500: // Internal server error
    case 502: // Bad gateway
    case 503: // Service unavailable
    case 504: // Gateway timeout
        return true;
    default:
        return false;
    }
}

static GglError send_http_request_impl(
    HttpEndpoint endpoint,
    GglBuffer payload,
    SigV4Details sigv4_details,
    const char *target,
    HTTPResponse_t *response_out
) {
    GGL_LOGT("Creating TLS connection");
    TLSContext *tls = create_tls_connection(&endpoint);
    if (!tls) {
        GGL_LOGE("Failed to create TLS connection");
        return GGL_ERR_FATAL;
    }

    TransportInterface_t transport
        = { .send = transport_send,
            .recv = transport_recv,
            .pNetworkContext = (NetworkContext_t *) tls };

    HTTPRequestInfo_t request_info
        = { .pMethod = HTTP_METHOD_POST,
            .methodLen = sizeof(HTTP_METHOD_POST) - 1,
            .pPath = endpoint.path,
            .pathLen = strlen(endpoint.path),
            .pHost = endpoint.host,
            .hostLen = strlen(endpoint.host) };

    char header_buffer[MAX_HEADER_BUFFER_SIZE];
    HTTPRequestHeaders_t request_headers
        = { .pBuffer = (uint8_t *) header_buffer,
            .bufferLen = sizeof(header_buffer) };

    /* Initialize HTTP headers */
    GGL_LOGT("Initializing HTTP headers");
    HTTPStatus_t http_error
        = HTTPClient_InitializeRequestHeaders(&request_headers, &request_info);
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Failed to initialize header, coreHTTP error code: %d (%s)",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FAILURE;
    }
    GGL_LOGT(
        "After init the request header length is %zu",
        request_headers.headersLen
    );

    char current_datetime[DATE_BUFFER_LEN] = { 0 };
    size_t date_status = aws_sigv4_get_iso8601_time(
        current_datetime, sizeof(current_datetime)
    );
    if (date_status == 0) {
        GGL_LOGE("Failed to get current iso date time. Got 0 length date");
        close_tls_connection(tls);
        return GGL_ERR_FAILURE;
    }

    // TODO: transfer headers to its own function
    http_error = HTTPClient_AddHeader(
        &request_headers,
        "Content-Type",
        strlen("Content-Type"),
        "application/x-amz-json-1.1",
        strlen("application/x-amz-json-1.1")
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding header. coreHTTP error code: %d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }

    http_error = HTTPClient_AddHeader(
        &request_headers,
        "X-Amz-Date",
        strlen("X-Amz-Date"),
        current_datetime,
        DATE_BUFFER_LEN - 1
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding header. coreHTTP error code: %d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }

    http_error = HTTPClient_AddHeader(
        &request_headers,
        "X-Amz-Target",
        strlen("X-Amz-Target"),
        target,
        strlen(target)
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `X-Amz-Target` header. coreHTTP error code: %d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }

    http_error = HTTPClient_AddHeader(
        &request_headers,
        "X-Amz-Security-Token",
        strlen("X-Amz-Security-Token"),
        (char *) sigv4_details.session_token.data,
        sigv4_details.session_token.len
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `X-Amz-Security-Token` header. coreHTTP error code: "
            "%d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }
    http_error = HTTPClient_AddHeader(
        &request_headers, "Accept", strlen("Accept"), "*/*", strlen("*/*")
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `Accept` header. coreHTTP error code: "
            "%d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }

    http_error = HTTPClient_AddHeader(
        &request_headers,
        "Accept-Encoding",
        strlen("Accept-Encoding"),
        "gzip, deflate",
        strlen("gzip, deflate")
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `Accept-Encoding` header. coreHTTP error code: "
            "%d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }
    http_error = HTTPClient_AddHeader(
        &request_headers,
        "Connection",
        strlen("Connection"),
        "keep-alive",
        strlen("keep-alive")
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `Connection` header. coreHTTP error code: "
            "%d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }

    GGL_LOGT("Generating SigV4 authorization header");
    static uint8_t sigv4_headers_buffer[MAX_SIGV4_HEADER_LEN] = { 0 };
    GglByteVec headers_to_sign
        = { .buf = { .data = sigv4_headers_buffer, .len = 0 },
            .capacity = sizeof(sigv4_headers_buffer) };

    CloudwatchRequiredHeaders required_headers = {
        .x_amz_target = { .data = (uint8_t *) target, .len = strlen(target) },
        .x_amz_date
        = { .data = (uint8_t *) current_datetime, .len = DATE_BUFFER_LEN - 1 },
        .amz_security_token = sigv4_details.session_token,
        .host
        = { .data = (uint8_t *) endpoint.host, .len = strlen(endpoint.host) },
        .content_type = GGL_STR("application/x-amz-json-1.1"),
    };

    static uint8_t auth_buffer[MAX_AUTH_HEADER_LEN] = { 0 };
    GglBuffer auth_header = { .data = auth_buffer, .len = sizeof(auth_buffer) };
    GglError ret = aws_sigv4_cloudwatch_post_header(
        sigv4_details, payload, required_headers, &headers_to_sign, &auth_header
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("SigV4 header generation failed with error: %d", ret);
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }

    // Ensure Authorization header is null-terminated
    if (auth_header.len >= sizeof(auth_buffer)) {
        GGL_LOGE("Authorization header buffer too small");
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }
    auth_header.data[auth_header.len] = '\0';

    http_error = HTTPClient_AddHeader(
        &request_headers,
        "Authorization",
        strlen("Authorization"),
        (char *) auth_header.data,
        auth_header.len
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `Authorization` header. coreHTTP error code: "
            "%d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close_tls_connection(tls);
        return GGL_ERR_FATAL;
    }

    static uint8_t local_response_buffer[MAX_RESPONSE_BUFFER_SIZE] = { 0 };
    HTTPResponse_t response;

    response = (HTTPResponse_t) { .pBuffer = local_response_buffer,
                                  .bufferLen = sizeof(local_response_buffer) };

    if (response_out != NULL) {
        *response_out = response;
    }

    GGL_LOGD("Sending HTTP request to %s%s", endpoint.host, endpoint.path);
    GGL_LOGT("Request headers length: %zu", request_headers.headersLen);
    GGL_LOGT("Sending HTTP request with payload size: %zu", payload.len);

    // Log the complete request headers for debugging
    GGL_LOGT(
        "Request headers: %.*s",
        (int) request_headers.headersLen,
        (char *) request_headers.pBuffer
    );

    HTTPStatus_t status = HTTPClient_Send(
        &transport, &request_headers, payload.data, payload.len, &response, 0
    );

    GGL_LOGD(
        "HTTP Status: %d (%s), Response Code: %u",
        status,
        slf_http_status_to_string(status),
        response.statusCode
    );
    if (response.pBody && response.bodyLen > 0) {
        GGL_LOGD(
            "Response: %.*s", (int) response.bodyLen, (char *) response.pBody
        );
    }

    close_tls_connection(tls);
    if (status != HTTPSuccess) {
        GGL_LOGE(
            "HTTP request failed with status: %d (%s)",
            status,
            slf_http_status_to_string(status)
        );
        return GGL_ERR_FAILURE;
    }
    if (response.statusCode != 200) {
        if (response_out != NULL) {
            *response_out = response;
        }
        return GGL_ERR_FAILURE;
    }

    GGL_LOGT("HTTP request completed successfully");
    return GGL_ERR_OK;
}

static GglError http_request_retry_wrapper(void *ctx) {
    HttpRequestRetryCtx *retry_ctx = (HttpRequestRetryCtx *) ctx;

    GglError result = send_http_request_impl(
        retry_ctx->endpoint,
        retry_ctx->payload,
        retry_ctx->sigv4_details,
        retry_ctx->target,
        retry_ctx->response_out
    );

    if (result == GGL_ERR_OK) {
        retry_ctx->err = GGL_ERR_OK;
        return GGL_ERR_OK;
    }

    // Check if we should retry based on the response status code
    if (retry_ctx->response_out != NULL) {
        HTTPResponse_t *response = retry_ctx->response_out;
        if (slf_can_retry_http_status(response->statusCode)) {
            GGL_LOGW(
                "HTTP request failed with status %u, will retry",
                response->statusCode
            );
            retry_ctx->err = result;
            return GGL_ERR_FAILURE; // Trigger retry
        }
    }

    retry_ctx->err = result;
    return GGL_ERR_OK; // Don't retry
}

static GglError send_http_request(
    HttpEndpoint endpoint,
    GglBuffer payload,
    SigV4Details sigv4_details,
    const char *target,
    HTTPResponse_t *response_out
) {
    HttpRequestRetryCtx ctx = { .endpoint = endpoint,
                                .payload = payload,
                                .sigv4_details = sigv4_details,
                                .target = target,
                                .response_out = response_out,
                                .err = GGL_ERR_OK };

    slf_backoff_indefinite(
        HTTP_RETRY_BASE_DELAY_MS,
        HTTP_RETRY_MAX_DELAY_MS,
        http_request_retry_wrapper,
        &ctx
    );

    return ctx.err;
}

typedef struct {
    GglBuffer payload;
    const char *target;
    const char *resource_type;
    GglBuffer resource_name;
} EnsureResourceCtx;

static GglError slf_ensure_resource_exists(
    SigV4Details sigv4_details, HttpEndpoint endpoint, EnsureResourceCtx *ctx
) {
    HTTPResponse_t response = { 0 };
    GglError ret = send_http_request(
        endpoint, ctx->payload, sigv4_details, ctx->target, &response
    );

    if (ret != GGL_ERR_OK) {
        if (response.pBody && response.bodyLen > 0) {
            GglBuffer response_buf = { .data = (uint8_t *) response.pBody,
                                       .len = response.bodyLen };
            if (ggl_buffer_contains(
                    response_buf,
                    GGL_STR("ResourceAlreadyExistsException"),
                    NULL
                )) {
                GGL_LOGD(
                    "%s '%.*s' already exists",
                    ctx->resource_type,
                    (int) ctx->resource_name.len,
                    ctx->resource_name.data
                );
                return GGL_ERR_OK;
            }
        }

        GGL_LOGE(
            "Failed to create %s '%.*s'",
            ctx->resource_type,
            (int) ctx->resource_name.len,
            ctx->resource_name.data
        );
        if (response.pBody && response.bodyLen > 0) {
            GGL_LOGE(
                "Error response: %.*s",
                (int) response.bodyLen,
                (char *) response.pBody
            );
        }
        return ret;
    }

    GGL_LOGI(
        "%s '%.*s' found/created successfully",
        ctx->resource_type,
        (int) ctx->resource_name.len,
        ctx->resource_name.data
    );

    return GGL_ERR_OK;
}

static GglError slf_build_endpoint(
    SigV4Details sigv4_details, Config config, HttpEndpoint *endpoint
) {
    if ((sigv4_details.aws_region.len == 0U)
        || (sigv4_details.aws_region.data == NULL)) {
        GGL_LOGE("Invalid region configuration");
        return GGL_ERR_INVALID;
    }

    static uint8_t hosturl_mem[64] = { 0 };
    GglByteVec hosturl = GGL_BYTE_VEC(hosturl_mem);

    GglError ret = ggl_byte_vec_append(&hosturl, GGL_STR("logs."));
    ggl_byte_vec_chain_append(&ret, &hosturl, sigv4_details.aws_region);
    ggl_byte_vec_chain_append(&ret, &hosturl, GGL_STR(".amazonaws.com"));

    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to construct host url");
        return ret;
    }

    endpoint->host = (char *) hosturl.buf.data;
    endpoint->port = (char *) config.port.data;
    endpoint->path = "/";

    return GGL_ERR_OK;
}

static bool slf_is_resource_not_found(HTTPResponse_t response) {
    if ((response.pBody == NULL) || (response.bodyLen == 0U)) {
        return false;
    }

    GglBuffer response_buf
        = { .data = (uint8_t *) response.pBody, .len = response.bodyLen };
    return ggl_buffer_contains(
        response_buf, GGL_STR("ResourceNotFoundException"), NULL
    );
}

static GglError slf_build_resource_payload(
    GglByteVec *payload, Config config, bool include_stream
) {
    payload->buf.len = 0;
    GglError ret
        = ggl_byte_vec_append(payload, GGL_STR("{\"logGroupName\":\""));
    ggl_byte_vec_chain_append(&ret, payload, config.logGroup);

    if (include_stream) {
        ggl_byte_vec_chain_append(
            &ret, payload, GGL_STR("\",\"logStreamName\":\"")
        );
        ggl_byte_vec_chain_append(&ret, payload, config.logStream);
    }

    ggl_byte_vec_chain_append(&ret, payload, GGL_STR("\"}"));
    return ret;
}

static GglError slf_create_resources(
    SigV4Details sigv4_details, HttpEndpoint endpoint, Config config
) {
    static uint8_t payload_mem[512];
    GglByteVec payload = GGL_BYTE_VEC(payload_mem);

    // Create log group
    GglError ret = slf_build_resource_payload(&payload, config, false);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to build log group payload");
        return ret;
    }

    EnsureResourceCtx group_ctx = { .payload = payload.buf,
                                    .target = "Logs_20140328.CreateLogGroup",
                                    .resource_type = "Log group",
                                    .resource_name = config.logGroup };

    ret = slf_ensure_resource_exists(sigv4_details, endpoint, &group_ctx);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    payload = GGL_BYTE_VEC(payload_mem);
    // Create log stream
    ret = slf_build_resource_payload(&payload, config, true);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to build log stream payload");
        return ret;
    }

    EnsureResourceCtx stream_ctx = { .payload = payload.buf,
                                     .target = "Logs_20140328.CreateLogStream",
                                     .resource_type = "Log stream",
                                     .resource_name = config.logStream };

    return slf_ensure_resource_exists(sigv4_details, endpoint, &stream_ctx);
}

GglError slf_upload_logs_to_cloud_watch(
    GglBuffer log_lines, SigV4Details sigv4_details, Config config
) {
    HttpEndpoint endpoint;
    GglError ret = slf_build_endpoint(sigv4_details, config, &endpoint);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    HTTPResponse_t response = { 0 };
    GglError upload_result = send_http_request(
        endpoint,
        log_lines,
        sigv4_details,
        "Logs_20140328.PutLogEvents",
        &response
    );

    if ((upload_result != GGL_ERR_OK) && slf_is_resource_not_found(response)) {
        GGL_LOGI("Creating missing CloudWatch resources");

        ret = slf_create_resources(sigv4_details, endpoint, config);
        if (ret != GGL_ERR_OK) {
            return ret;
        }

        upload_result = send_http_request(
            endpoint,
            log_lines,
            sigv4_details,
            "Logs_20140328.PutLogEvents",
            NULL
        );
    }

    if (upload_result == GGL_ERR_OK) {
        GGL_LOGI("Successfully uploaded logs to CloudWatch");
    } else {
        GGL_LOGE("Failed to upload logs to CloudWatch");
    }

    return upload_result;
}
