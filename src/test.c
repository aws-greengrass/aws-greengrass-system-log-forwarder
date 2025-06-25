#include "test.h"
#include "aws_sigv4.h"
#include "core_http_client.h"
#include "ggl/log.h"
#include "system-log-forwarder.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <time.h>
#include <unistd.h>
#include <stdio.h>
#include <stdlib.h>

typedef struct {
    const char *host;
    const char *port;
    const char *path;
} HttpEndpoint;

typedef struct {
    const char **logs;
    size_t count;
} LogBatch;

/* Configuration */
#define AWS_REGION "us-west-2" /* Change to your region */
#define CLOUDWATCH_HOST "logs." AWS_REGION ".amazonaws.com"
#define CLOUDWATCH_SERVICE "logs"
#define LOG_GROUP_NAME "/aws/greengrass/LogBatchUploader"
#define LOG_STREAM_NAME "device-logs"

/* Buffer sizes */
#define MAX_URL_LENGTH 256
#define MAX_AUTH_HEADER_LENGTH 512
#define MAX_DATE_LENGTH 64
#define MAX_REQUEST_BODY_LENGTH 4096
#define MAX_RESPONSE_LENGTH 1024

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

static int create_connection(const HttpEndpoint *endpoint) {
    struct addrinfo hints = { 0 };
    struct addrinfo *result;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(endpoint->host, endpoint->port, &hints, &result) != 0) {
        return -1;
    }

    int sockfd
        = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd < 0) {
        freeaddrinfo(result);
        return -1;
    }

    if (connect(sockfd, result->ai_addr, result->ai_addrlen) < 0) {
        close(sockfd);
        freeaddrinfo(result);
        return -1;
    }
    freeaddrinfo(result);
    return sockfd;
}

static char *create_json_payload(const LogBatch *batch) {
    size_t total_size = 500;
    for (size_t i = 0; i < batch->count; i++) {
        total_size += strlen(batch->logs[i]) + 100;
    }

    char *payload = malloc(total_size);
    strcpy(
        payload,
        "{\"logGroupName\":\"test/"
        "logs\",\"logStreamName\":\"host-b0f1d8531b5f.ant.amazon.com-"
        "20250610\",\"logEvents\":["
    );

    for (size_t i = 0; i < batch->count; i++) {
        if (i > 0) strcat(payload, ",");
        strcat(payload, batch->logs[i]);
    }
    strcat(payload, "]}");

    GGL_LOGI("JSON Payload: %s", payload);
    return payload;
}

/* Function to format date for AWS request */
// static void format_aws_date(char *buffer, size_t buffer_size) {
//     time_t now;
//     struct tm *timeinfo;

//     time(&now);
//     timeinfo = gmtime(&now);

//     strftime(buffer, buffer_size, "%Y%m%dT%H%M%SZ", timeinfo);
// }

static int send_batch(
    const HttpEndpoint *endpoint,
    const LogBatch *batch,
    SigV4Details sigv4_details
) {
    GGL_LOGI("Creating connection");
    int sockfd = create_connection(endpoint);
    if (sockfd < 0) {
        GGL_LOGI("Failed to create connection");
        return -1;
    }

    TransportInterface_t transport
        = { .send = transport_send,
            .recv = transport_recv,
            .pNetworkContext = (NetworkContext_t *) &sockfd };

    HTTPRequestInfo_t request_info
        = { .pMethod = HTTP_METHOD_POST,
            .methodLen = sizeof(HTTP_METHOD_POST) - 1,
            .pPath = endpoint->path,
            .pathLen = strlen(endpoint->path),
            .pHost = endpoint->host,
            .hostLen = strlen(endpoint->host) };

    char header_buffer[4028];
    HTTPRequestHeaders_t request_headers
        = { .pBuffer = (uint8_t *) header_buffer,
            .bufferLen = sizeof(header_buffer) };

    GGL_LOGI("Creating json payload");
    char *payload_raw = create_json_payload(batch);
    size_t payload_raw_len = strlen(payload_raw);
    GglBuffer payload
        = { .data = (uint8_t *) payload_raw, .len = payload_raw_len };

    /* Initialize HTTP headers */
    HTTPStatus_t header_status
        = HTTPClient_InitializeRequestHeaders(&request_headers, &request_info);
    if (header_status != HTTPSuccess) {
        GGL_LOGI("Failed to initilize header");
        return -1;
    }

    char date_buffer[17];
    aws_sigv4_get_iso8601_time(date_buffer, sizeof(date_buffer));

    static uint8_t auth_buffer[1024];
    GglBuffer auth_header = { .data = auth_buffer, .len = sizeof(auth_buffer) };
    GglBuffer current_date = { .data = (uint8_t *) date_buffer, .len = 16 };

    GglError ret = aws_sigv4_cloudwatch_post_header(
        sigv4_details, payload, current_date, &auth_header
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("SigV4 header generation failed with error: %d", ret);
        return -1;
    }

    HTTPClient_AddHeader(
        &request_headers, "Content-Type", 12, "application/json", 16
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

    char content_length[32];
    snprintf(content_length, sizeof(content_length), "%zu", payload.len);
    HTTPClient_AddHeader(
        &request_headers,
        "Content-Length",
        14,
        content_length,
        strlen(content_length)
    );
    HTTPClient_AddHeader(
        &request_headers,
        "Authorization",
        strlen("Authorization"),
        (char *) auth_header.data,
        auth_header.len
    );

    uint8_t response_buffer[2048];
    HTTPResponse_t response
        = { .pBuffer = response_buffer, .bufferLen = sizeof(response_buffer) };

    GGL_LOGI(
        "Sending batch of %zu logs to %s%s",
        batch->count,
        endpoint->host,
        endpoint->path
    );
    HTTPStatus_t status = HTTPClient_Send(
        &transport, &request_headers, payload.data, payload.len, &response, 0
    );

    GGL_LOGI("HTTP Status: %d, Response Code: %u", status, response.statusCode);
    if (response.pBody && response.bodyLen > 0) {
        GGL_LOGI(
            "Response: %.*s", (int) response.bodyLen, (char *) response.pBody
        );
    }

    close(sockfd);
    return (status == HTTPSuccess && response.statusCode == 200) ? 0 : -1;
}

static int post_logs_batch(
    const HttpEndpoint *endpoint,
    const char **logs,
    size_t log_count,
    size_t batch_size,
    SigV4Details sigv4_details
) {
    for (size_t i = 0; i < log_count; i += batch_size) {
        size_t current_batch_size
            = (i + batch_size > log_count) ? log_count - i : batch_size;
        LogBatch batch = { .logs = &logs[i], .count = current_batch_size };

        if (send_batch(endpoint, &batch, sigv4_details) != 0) {
            GGL_LOGE("Failed to send batch starting at index %zu", i);
            return -1;
        }
    }
    return 0;
}

int post_logs_to_httpbin(SigV4Details sigv4_details) {
    HttpEndpoint endpoint = { .host = "logs.us-west-2.amazonaws.com",
                              .port = "443",
                              .path = "/post" };

    const char *sample_logs[] = {
        "{\"timestamp\":1749330977373,\"message\":\"2025-06-24T14:16:17."
        "373317Z DEBUG [scheduler] Connection pool status: active=72, idle=48, "
        "waiting=15\"}",
        "{\"timestamp\":1749330980288,\"message\":\"2025-06-24T14:16:20."
        "288317Z DEBUG [cache] Thread thread-69 state changed to blocked\"}",
        "{\"timestamp\":1749330982503,\"message\":\"2025-06-24T14:16:22."
        "503317Z INFO [order] Database connection established to "
        "db-primary-5.example.com\"}"
    };

    return post_logs_batch(&endpoint, sample_logs, 2, 2, sigv4_details);
}