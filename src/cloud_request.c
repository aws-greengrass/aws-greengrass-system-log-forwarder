// Function to upload logs to CloudWatch
#include "cloud_request.h"
#include "aws_sigv4.h"
#include "core_http_client.h"
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

// As Required by the sigv4 library
#define DATE_BUFFER_LEN (17)
#define MAX_AUTH_HEADER_LEN (1024)
#define MAX_SIGV4_HEADER_LEN (2048)

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
        return NULL;
    }

    struct addrinfo hints = { 0 };
    struct addrinfo *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(endpoint->host, endpoint->port, &hints, &result) != 0) {
        SSL_CTX_free(tls->ctx);
        return NULL;
    }

    tls->sockfd
        = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (tls->sockfd < 0) {
        freeaddrinfo(result);
        SSL_CTX_free(tls->ctx);
        return NULL;
    }

    if (connect(tls->sockfd, result->ai_addr, result->ai_addrlen) < 0) {
        close(tls->sockfd);
        freeaddrinfo(result);
        SSL_CTX_free(tls->ctx);
        return NULL;
    }
    freeaddrinfo(result);

    tls->ssl = SSL_new(tls->ctx);
    SSL_set_fd(tls->ssl, tls->sockfd);

    if (SSL_connect(tls->ssl) <= 0) {
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

static const char *http_status_to_string(HTTPStatus_t status) {
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

static GglError send_batch(
    const HttpEndpoint *endpoint, GglBuffer payload, SigV4Details sigv4_details
) {
    GGL_LOGT("Creating TLS connection");
    TLSContext *tls = create_tls_connection(endpoint);
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
            .pPath = endpoint->path,
            .pathLen = strlen(endpoint->path),
            .pHost = endpoint->host,
            .hostLen = strlen(endpoint->host) };

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
            http_status_to_string(http_error)
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
            http_status_to_string(http_error)
        );
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
            http_status_to_string(http_error)
        );
        return GGL_ERR_FATAL;
    }

    http_error = HTTPClient_AddHeader(
        &request_headers,
        "X-Amz-Target",
        strlen("X-Amz-Target"),
        "Logs_20140328.PutLogEvents",
        strlen("Logs_20140328.PutLogEvents")
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `X-Amz-Target` header. coreHTTP error code: %d (%s).",
            http_error,
            http_status_to_string(http_error)
        );
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
            http_status_to_string(http_error)
        );
    }
    http_error = HTTPClient_AddHeader(
        &request_headers, "Accept", strlen("Accept"), "*/*", strlen("*/*")
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding `Accept` header. coreHTTP error code: "
            "%d (%s).",
            http_error,
            http_status_to_string(http_error)
        );
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
            http_status_to_string(http_error)
        );
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
            http_status_to_string(http_error)
        );
    }

    GGL_LOGT("Generating SigV4 authorization header");
    static uint8_t sigv4_headers_buffer[MAX_SIGV4_HEADER_LEN] = { 0 };
    GglByteVec headers_to_sign
        = { .buf = { .data = sigv4_headers_buffer, .len = 0 },
            .capacity = sizeof(sigv4_headers_buffer) };

    CloudwatchRequiredHeaders required_headers = {
        .x_amz_target = GGL_STR("Logs_20140328.PutLogEvents"),
        .x_amz_date = { (uint8_t *) current_datetime, DATE_BUFFER_LEN - 1 },
        .amz_security_token = sigv4_details.session_token,
        .host = (GglBuffer) { .data = (uint8_t *) endpoint->host,
                              .len = strlen(endpoint->host) },
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
            http_status_to_string(http_error)
        );
    }

    uint8_t response_buffer[MAX_RESPONSE_BUFFER_SIZE];
    HTTPResponse_t response
        = { .pBuffer = response_buffer, .bufferLen = sizeof(response_buffer) };

    GGL_LOGT("Sending batched logs to %s%s", endpoint->host, endpoint->path);

    GGL_LOGT("Request headers length: %zu", request_headers.headersLen);
    GGL_LOGT("Sending HTTP request with payload size: %zu", payload.len);
    GGL_LOGT("Payload is: %.*s", (int) payload.len, payload.data);

    // Log the complete request headers for debugging
    GGL_LOGT(
        "Request headers: %.*s",
        (int) request_headers.headersLen,
        (char *) request_headers.pBuffer
    );

    HTTPStatus_t status = HTTPClient_Send(
        &transport, &request_headers, payload.data, payload.len, &response, 0
    );

    GGL_LOGI(
        "HTTP Status: %d (%s), Response Code: %u",
        status,
        http_status_to_string(status),
        response.statusCode
    );
    if (response.pBody && response.bodyLen > 0) {
        GGL_LOGI(
            "Response: %.*s", (int) response.bodyLen, (char *) response.pBody
        );
    }

    close_tls_connection(tls);
    if (status != HTTPSuccess) {
        GGL_LOGE(
            "HTTP request failed with status: %d (%s)",
            status,
            http_status_to_string(status)
        );
        return GGL_ERR_FAILURE;
    }
    if (response.statusCode != 200) {
        GGL_LOGE("HTTP response code not 200: %u", response.statusCode);
        return GGL_ERR_FAILURE;
    }

    GGL_LOGI("Batch sent successfully");
    return 0;
}

GglError slf_upload_logs_to_cloud_watch(
    GglBuffer log_lines, SigV4Details sigv4_details, Config config
) {
    GGL_LOGT("Starting to send logs");

    uint8_t hosturl_mem[32];
    GglByteVec hosturl = GGL_BYTE_VEC(hosturl_mem);

    GglError ret = ggl_byte_vec_append(&hosturl, GGL_STR("logs."));
    ggl_byte_vec_chain_append(&ret, &hosturl, config.region);
    ggl_byte_vec_chain_append(&ret, &hosturl, GGL_STR(".amazonaws.com\0"));
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to construct host url");
        return ret;
    }

    HttpEndpoint endpoint = { .host = (char *) hosturl.buf.data,
                              .port = (char *) config.port.data,
                              .path = "/" };

    GGL_LOGT(
        "Endpoint configured: %s:%s%s",
        endpoint.host,
        endpoint.port,
        endpoint.path
    );

    return send_batch(&endpoint, log_lines, sigv4_details);
}
