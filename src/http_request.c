#include "aws_sigv4.h"
#include "core_http_client.h"
#include "ggl/log.h"
#include "system-log-forwarder.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/json_encode.h>
#include <ggl/list.h>
#include <ggl/map.h>
#include <ggl/object.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>

// typedef struct RequestLogBody {
//     uint64_t timestamp;
//     GglBuffer message;
// } RequestLogBody;

// typedef struct RequestBody {
//     GglBuffer logGroupName;
//     GglBuffer logStreamName;
//     RequestLogBody logEvents[MAX_LOG_EVENTS];
// } RequestBody;

/* Function to get current timestamp in milliseconds */
static uint64_t get_current_time_millis(void) {
    struct timespec ts;
    clock_gettime(CLOCK_REALTIME, &ts);
    return (uint64_t) (ts.tv_sec) * 1000 + (uint64_t) (ts.tv_nsec) / 1000000;
}

static int32_t transport_send(
    NetworkContext_t *pNetworkContext, const void *pBuffer, size_t bytesToSend
) {
    int sockfd = *(int *) pNetworkContext;
    return (int32_t) send(sockfd, pBuffer, bytesToSend, 0);
}

static int32_t transport_recv(
    NetworkContext_t *pNetworkContext, void *pBuffer, size_t bytesToRecv
) {
    int sockfd = *(int *) pNetworkContext;
    return (int32_t) recv(sockfd, pBuffer, bytesToRecv, 0);
}

static int create_connection(void) {
    struct addrinfo hints = { 0 }, *result;
    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    GGL_LOGI("Resolving logs.us-west-2.amazonaws.com:443");
    if (getaddrinfo("logs.us-west-2.amazonaws.com", "443", &hints, &result)
        != 0) {
        GGL_LOGE("DNS resolution failed");
        return -1;
    }

    int sockfd
        = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd < 0) {
        GGL_LOGE("Socket creation failed");
        freeaddrinfo(result);
        return -1;
    }

    /* Set socket timeout */
    struct timeval timeout = { .tv_sec = 5, .tv_usec = 0 };
    setsockopt(sockfd, SOL_SOCKET, SO_RCVTIMEO, &timeout, sizeof(timeout));
    setsockopt(sockfd, SOL_SOCKET, SO_SNDTIMEO, &timeout, sizeof(timeout));

    GGL_LOGI("Connecting to CloudWatch Logs");
    if (connect(sockfd, result->ai_addr, result->ai_addrlen) < 0) {
        GGL_LOGE("Connection failed");
        close(sockfd);
        freeaddrinfo(result);
        return -1;
    }

    GGL_LOGI("Connection established successfully");
    freeaddrinfo(result);
    return sockfd;
}

// /* Function to create CloudWatch PutLogEvents request body */
// static GglError create_put_log_events_body(GglBufList log_lines, RequestBody
// *root) {
//     uint64_t timestamp = get_current_time_millis();
//     for (size_t line_number = 0; line_number < log_lines.len; line_number++)
//     {
//         root->logEvents[line_number].timestamp = timestamp + line_number;
//         root->logEvents[line_number].message = log_lines.bufs[line_number];
//     }
//     root->logGroupName = GGL_STR("/aws/greengrass/LogBatchUploader");
//     root->logStreamName = GGL_STR("device-logs");

//     return GGL_ERR_OK;
// }

static GglError send_batch(
    GglObject *log_events, size_t batch_size, SigV4Details sigv4_details
) {
    /* Build main request body */
    GglKV body_kvs[] = {
        ggl_kv(GGL_STR("logGroupName"), ggl_obj_buf(GGL_STR("test/logs"))),
        ggl_kv(GGL_STR("logStreamName"), ggl_obj_buf(GGL_STR("device-logs"))),
        ggl_kv(
            GGL_STR("logEvents"),
            ggl_obj_list((GglList) { .items = log_events, .len = batch_size })
        )
    };
    GglMap body_map = { .pairs = body_kvs, .len = 3 };
    GglObject request_body = ggl_obj_map(body_map);

    /* Serialize JSON to buffer */
    static uint8_t json_buffer[MAX_UPLOAD_SIZE];
    GglBuffer json_payload
        = { .data = json_buffer, .len = sizeof(json_buffer) };
    GglError ret = ggl_json_encode(request_body, &json_payload);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("JSON encode failed, batch_size: %zu", batch_size);
        return ret;
    }

    /* Print the JSON packet */
    GGL_LOGI(
        "CloudWatch JSON packet (%zu bytes): %.*s",
        json_payload.len,
        (int) json_payload.len,
        (char *) json_payload.data
    );

    /* Debug credentials */
    GGL_LOGI("Access Key ID length: %zu", sigv4_details.access_key_id.len);
    GGL_LOGI(
        "Secret Access Key length: %zu", sigv4_details.secret_access_key.len
    );
    GGL_LOGI("Session Token length: %zu", sigv4_details.session_token.len);

    /* Generate date for consistent use in signing and headers */
    char date_buffer[17];
    aws_sigv4_get_iso8601_time(date_buffer, sizeof(date_buffer));

    /* Generate authorization header */
    static uint8_t auth_buffer[1024];
    GglBuffer auth_header = { .data = auth_buffer, .len = sizeof(auth_buffer) };
    GglBuffer date_buf = { .data = (uint8_t *) date_buffer, .len = 16 };
    ret = aws_sigv4_cloudwatch_post_header(
        sigv4_details, json_payload, date_buf, &auth_header
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("SigV4 header generation failed with error: %d", ret);
        return ret;
    }

    /* Create connection */
    static int sockfd = -1;
    if (sockfd < 0) {
        sockfd = create_connection();
        if (sockfd < 0) {
            GGL_LOGE("Failed to create connection");
            return GGL_ERR_FAILURE;
        }
    }

    /* Set up HTTP request */
    TransportInterface_t transport
        = { .send = transport_send,
            .recv = transport_recv,
            .pNetworkContext = (NetworkContext_t *) &sockfd };

    /* Set up HTTP request info */
    HTTPRequestInfo_t request_info
        = { .pMethod = HTTP_METHOD_POST,
            .methodLen = sizeof(HTTP_METHOD_POST) - 1,
            .pPath = "/",
            .pathLen = 1,
            .pHost = "logs.us-west-2.amazonaws.com",
            .hostLen = strlen("logs.us-west-2.amazonaws.com") };

    static char header_buffer[2048];
    HTTPRequestHeaders_t request_headers
        = { .pBuffer = (uint8_t *) header_buffer,
            .bufferLen = sizeof(header_buffer) };

    /* Initialize headers */
    HTTPStatus_t header_status
        = HTTPClient_InitializeRequestHeaders(&request_headers, &request_info);
    if (header_status != HTTPSuccess) {
        GGL_LOGE("Failed to initialize request headers: %d", header_status);
        return GGL_ERR_FAILURE;
    }

    /* Add required headers using same date as signing */
    HTTPClient_AddHeader(
        &request_headers,
        "Content-Type",
        strlen("Content-Type"),
        "application/x-amz-json-1.1",
        strlen("application/x-amz-json-1.1")
    );
    HTTPClient_AddHeader(
        &request_headers, "Date", strlen("Date"), date_buffer, 16
    );
    HTTPClient_AddHeader(
        &request_headers,
        "X-Amz-Target",
        strlen("X-Amz-Target"),
        "Logs_20140328.PutLogEvents",
        strlen("Logs_20140328.PutLogEvents")
    );
    HTTPClient_AddHeader(
        &request_headers, "X-Amz-Date", strlen("X-Amz-Date"), date_buffer, 16
    );
    HTTPClient_AddHeader(
        &request_headers,
        "Accept",
        strlen("Accept"),
        "application/json",
        strlen("application/json")
    );
    HTTPClient_AddHeader(
        &request_headers,
        "Connection",
        strlen("Connection"),
        "Keep-Alive",
        strlen("Keep-Alive")
    );

    /* Add Content-Length header */
    char content_length[32];
    snprintf(content_length, sizeof(content_length), "%zu", json_payload.len);
    HTTPClient_AddHeader(
        &request_headers,
        "Content-Length",
        strlen("Content-Length"),
        content_length,
        strlen(content_length)
    );

    /* Add authorization header */
    char auth_value[1024];
    snprintf(
        auth_value,
        sizeof(auth_value),
        "%.*s",
        (int) auth_header.len,
        (char *) auth_header.data
    );
    HTTPClient_AddHeader(
        &request_headers,
        "Authorization",
        strlen("Authorization"),
        auth_value,
        strlen(auth_value)
    );

    static uint8_t response_buffer[1024];
    HTTPResponse_t response
        = { .pBuffer = response_buffer, .bufferLen = sizeof(response_buffer) };

    /* Validate parameters before HTTPClient_Send */
    GGL_LOGI("Validating HTTPClient_Send parameters:");
    GGL_LOGI("- transport.send: %p", (void *) transport.send);
    GGL_LOGI("- transport.recv: %p", (void *) transport.recv);
    GGL_LOGI(
        "- transport.pNetworkContext: %p", (void *) transport.pNetworkContext
    );
    GGL_LOGI("- request_headers.pBuffer: %p", (void *) request_headers.pBuffer);
    GGL_LOGI("- request_headers.bufferLen: %zu", request_headers.bufferLen);
    GGL_LOGI("- request_headers.headersLen: %zu", request_headers.headersLen);
    GGL_LOGI("- json_payload.data: %p", (void *) json_payload.data);
    GGL_LOGI("- json_payload.len: %zu", json_payload.len);
    GGL_LOGI("- response.pBuffer: %p", (void *) response.pBuffer);
    GGL_LOGI("- response.bufferLen: %zu", response.bufferLen);

    /* Check for NULL pointers that would cause InvalidParameter */
    if (transport.send == NULL) {
        GGL_LOGE("transport.send is NULL");
        return GGL_ERR_FAILURE;
    }
    if (transport.recv == NULL) {
        GGL_LOGE("transport.recv is NULL");
        return GGL_ERR_FAILURE;
    }
    if (transport.pNetworkContext == NULL) {
        GGL_LOGE("transport.pNetworkContext is NULL");
        return GGL_ERR_FAILURE;
    }
    if (request_headers.pBuffer == NULL) {
        GGL_LOGE("request_headers.pBuffer is NULL");
        return GGL_ERR_FAILURE;
    }
    if (response.pBuffer == NULL) {
        GGL_LOGE("response.pBuffer is NULL");
        return GGL_ERR_FAILURE;
    }

    /* Check buffer sizes */
    if (request_headers.bufferLen == 0) {
        GGL_LOGE("request_headers.bufferLen is 0");
        return GGL_ERR_FAILURE;
    }
    if (response.bufferLen == 0) {
        GGL_LOGE("response.bufferLen is 0");
        return GGL_ERR_FAILURE;
    }

    /* Print actual headers being sent */
    GGL_LOGI("Headers being sent (%zu bytes):", request_headers.headersLen);
    GGL_LOGI("%.*s", (int) request_headers.headersLen, request_headers.pBuffer);

    if (!transport.send || !transport.recv || !transport.pNetworkContext) {
        GGL_LOGE("Invalid transport interface parameters");
        return GGL_ERR_FAILURE;
    }

    if (!request_headers.pBuffer || request_headers.bufferLen == 0) {
        GGL_LOGE("Invalid request headers parameters");
        return GGL_ERR_FAILURE;
    }

    if (!json_payload.data || json_payload.len == 0) {
        GGL_LOGE("Invalid payload parameters");
        return GGL_ERR_FAILURE;
    }

    if (!response.pBuffer || response.bufferLen == 0) {
        GGL_LOGE("Invalid response buffer parameters");
        return GGL_ERR_FAILURE;
    }

    GGL_LOGI("All parameters appear valid. Calling HTTPClient_Send...");
    HTTPStatus_t status = HTTPClient_Send(
        &transport,
        &request_headers,
        (uint8_t *) json_payload.data,
        json_payload.len,
        &response,
        0
    );

    GGL_LOGI("HTTPClient_Send completed with status: %d", status);
    GGL_LOGI("Response status code: %u", response.statusCode);
    GGL_LOGI("Response body length: %zu", response.bodyLen);

    if (response.pBody && response.bodyLen > 0) {
        GGL_LOGI(
            "Response body: %.*s",
            (int) response.bodyLen,
            (char *) response.pBody
        );
    }

    if (status == HTTPSuccess) {
        if (response.statusCode >= 200 && response.statusCode < 300) {
            GGL_LOGI(
                "✓ Batch upload successful - %zu events processed", batch_size
            );
            return GGL_ERR_OK;
        } else {
            GGL_LOGE(
                "HTTP request failed - statusCode: %u", response.statusCode
            );
            return GGL_ERR_FAILURE;
        }
    } else {
        GGL_LOGE(
            "HTTPClient_Send failed with status: %d (1=Success, "
            "2=InvalidParameter, 3=InsufficientMemory, etc.)",
            status
        );
        return GGL_ERR_FAILURE;
    }
}

GglError upload_logs_to_cloud_watch(
    GglBufList log_lines, SigV4Details sigv4_details
) {
    uint64_t timestamp = get_current_time_millis();

    /* Build log events array */
    GglObject log_events[MAX_LOG_EVENTS];
    for (size_t i = 0; i < log_lines.len && i < MAX_LOG_EVENTS; i++) {
        GglKV event_kvs[]
            = { ggl_kv(
                    GGL_STR("timestamp"), ggl_obj_i64((int64_t) (timestamp + i))
                ),
                ggl_kv(GGL_STR("message"), ggl_obj_buf(log_lines.bufs[i])) };
        GglMap event_map = { .pairs = event_kvs, .len = 2 };
        log_events[i] = ggl_obj_map(event_map);
    }

    /* Send logs in batches */
    size_t start_idx = 0;
    while (start_idx < log_lines.len) {
        size_t batch_size = (log_lines.len - start_idx > 10)
            ? 10
            : (log_lines.len - start_idx);
        GGL_LOGI("Sending batch of %zu events", batch_size);

        /* Send this batch */
        GglError ret
            = send_batch(&log_events[start_idx], batch_size, sigv4_details);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        GGL_LOGI(
            "✓ Successfully uploaded batch %zu/%zu",
            (start_idx / 10) + 1,
            (log_lines.len + 9) / 10
        );

        start_idx += batch_size;
    }

    return GGL_ERR_OK;
}