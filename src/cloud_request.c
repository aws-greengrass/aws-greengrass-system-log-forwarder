// Function to upload logs to CloudWatch
#include "cloud_request.h"
#include "aws_sigv4.h"
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

static GglError send_http_request(
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

    GGL_LOGT("Sending HTTP request to %s%s", endpoint.host, endpoint.path);
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

    GGL_LOGT(
        "HTTP Status: %d (%s), Response Code: %u",
        status,
        slf_http_status_to_string(status),
        response.statusCode
    );
    if (response.pBody && response.bodyLen > 0) {
        GGL_LOGT(
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

// Ensure log group exists by attempting to create it
static GglError slf_ensure_log_group_exists(
    SigV4Details sigv4_details, HttpEndpoint endpoint, Config config
) {
    GGL_LOGT(
        "Ensuring log group exists: %.*s",
        (int) config.logGroup.len,
        config.logGroup.data
    );

    char payload_buffer[256];
    snprintf(
        payload_buffer,
        sizeof(payload_buffer),
        "{\"logGroupName\":\"%.*s\"}",
        (int) config.logGroup.len,
        config.logGroup.data
    );

    GglBuffer payload
        = { .data = (uint8_t *) payload_buffer, .len = strlen(payload_buffer) };

    HTTPResponse_t response = { 0 };
    GglError ret = send_http_request(
        endpoint,
        payload,
        sigv4_details,
        "Logs_20140328.CreateLogGroup",
        &response
    );

    if (ret != GGL_ERR_OK) {
        // Check if it's just because the log group already exists
        if (response.pBody && response.bodyLen > 0
            && strstr((char *) response.pBody, "ResourceAlreadyExistsException")
                != NULL) {
            GGL_LOGD(
                "Log group '%.*s' already exists",
                (int) config.logGroup.len,
                config.logGroup.data
            );
            return GGL_ERR_OK;
        }

        GGL_LOGE(
            "Failed to create log group '%.*s'",
            (int) config.logGroup.len,
            config.logGroup.data
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
        "Log group '%.*s' found/created successfully",
        (int) config.logGroup.len,
        config.logGroup.data
    );

    return GGL_ERR_OK;
}

// Create a log stream
static GglError slf_ensure_log_stream_exists(
    SigV4Details sigv4_details, HttpEndpoint endpoint, Config config
) {
    char payload_buffer[512];
    int ret = snprintf(
        payload_buffer,
        sizeof(payload_buffer),
        "{\"logGroupName\":\"%.*s\",\"logStreamName\":\"%.*s\"}",
        (int) config.logGroup.len,
        config.logGroup.data,
        (int) config.logStream.len,
        config.logStream.data
    );
    if (ret < 0 || ret >= (int) sizeof(payload_buffer)) {
        GGL_LOGE("Payload buffer too small for log stream creation");
        return GGL_ERR_FAILURE;
    }

    GglBuffer payload
        = { .data = (uint8_t *) payload_buffer, .len = strlen(payload_buffer) };

    GGL_LOGI(
        "Creating log stream '%.*s' in group '%.*s'",
        (int) config.logStream.len,
        config.logStream.data,
        (int) config.logGroup.len,
        config.logGroup.data
    );

    HTTPResponse_t create_response = { 0 };
    GglError result = send_http_request(
        endpoint,
        payload,
        sigv4_details,
        "Logs_20140328.CreateLogStream",
        &create_response
    );

    if (result != GGL_ERR_OK) {
        // Check if it's just because the log stream already exists
        if (create_response.pBody && create_response.bodyLen > 0
            && strstr(
                   (char *) create_response.pBody,
                   "ResourceAlreadyExistsException"
               ) != NULL) {
            GGL_LOGD(
                "Log stream '%.*s' already exists",
                (int) config.logStream.len,
                config.logStream.data
            );
            return GGL_ERR_OK;
        }
        GGL_LOGE(
            "Failed to create log stream '%.*s'",
            (int) config.logStream.len,
            config.logStream.data
        );
        if (create_response.pBody && create_response.bodyLen > 0) {
            GGL_LOGE(
                "Error response: %.*s",
                (int) create_response.bodyLen,
                (char *) create_response.pBody
            );
        }
        return result;
    }

    GGL_LOGI(
        "Log stream '%.*s' found/created successfully",
        (int) config.logStream.len,
        config.logStream.data
    );

    return result;
}

GglError slf_upload_logs_to_cloud_watch(
    GglBuffer log_lines, SigV4Details sigv4_details, Config config
) {
    GGL_LOGT("Starting to send logs");

    // Validate region configuration
    if (sigv4_details.aws_region.len == 0
        || sigv4_details.aws_region.data == NULL) {
        GGL_LOGE(
            "Region configuration is empty or invalid - len: %zu, data: %p",
            sigv4_details.aws_region.len,
            (void *) sigv4_details.aws_region.data
        );
        return GGL_ERR_INVALID;
    }

    uint8_t hosturl_mem[64];
    GglByteVec hosturl = GGL_BYTE_VEC(hosturl_mem);

    GGL_LOGI(
        "Constructing hostname with aws_region: '%.*s' (len=%zu)",
        (int) sigv4_details.aws_region.len,
        sigv4_details.aws_region.data,
        sigv4_details.aws_region.len
    );

    GglError ret = ggl_byte_vec_append(&hosturl, GGL_STR("logs."));
    ggl_byte_vec_chain_append(&ret, &hosturl, sigv4_details.aws_region);
    ggl_byte_vec_chain_append(&ret, &hosturl, GGL_STR(".amazonaws.com"));

    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to construct host url");
        return ret;
    }

    HttpEndpoint endpoint = { .host = (char *) hosturl.buf.data,
                              .port = (char *) config.port.data,
                              .path = "/" };

    GGL_LOGI(
        "Endpoint configured: %s:%s%s",
        endpoint.host,
        endpoint.port,
        endpoint.path
    );

    // Ensure log group and stream exist before uploading logs
    ret = slf_ensure_log_group_exists(sigv4_details, endpoint, config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to ensure log group exists");
        return ret;
    }

    ret = slf_ensure_log_stream_exists(sigv4_details, endpoint, config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to ensure log stream exists");
        return ret;
    }

    GglError upload_result = send_http_request(
        endpoint, log_lines, sigv4_details, "Logs_20140328.PutLogEvents", NULL
    );

    if (upload_result == GGL_ERR_OK) {
        GGL_LOGI("Successfully uploaded logs to CloudWatch");
    } else {
        GGL_LOGE("Failed to upload logs to CloudWatch");
    }

    return upload_result;
}
