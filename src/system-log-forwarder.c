// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "system-log-forwarder.h"
#include "core_http_client.h"
#include "ring_buffer.h"
#include "test.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/json_decode.h>
#include <ggl/log.h>
#include <ggl/map.h>
#include <ggl/sdk.h>
#include <ggl/utils.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

// static GglError fetch_tes_credentials(SigV4Details *sigv4_details) {
//     const char *credentials_uri =
//     getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI"); const char *auth_token =
//     getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");

//     if (!credentials_uri || !auth_token) {
//         GGL_LOGE("Missing Greengrass TES environment variables");
//         return GGL_ERR_FAILURE;
//     }

//     TransportInterface_t transport = {0};

//     static char header_buffer[1024];
//     HTTPRequestHeaders_t request_headers = {
//         .pBuffer = (uint8_t*)header_buffer,
//         .bufferLen = sizeof(header_buffer)
//     };

//     HTTPRequestInfo_t request_info = {
//         .pMethod = HTTP_METHOD_GET,
//         .methodLen = sizeof(HTTP_METHOD_GET) - 1,
//         .pPath = credentials_uri,
//         .pathLen = strlen(credentials_uri)
//     };

//     char auth_header[512];
//     snprintf(auth_header, sizeof(auth_header), "Authorization: %s",
//     auth_token);

//     HTTPStatus_t status = HTTPClient_AddHeader(&request_headers, auth_header,
//     strlen(auth_header)); if (status != HTTPSuccess) {
//         return GGL_ERR_FAILURE;
//     }

//     static uint8_t response_buffer[2048];
//     HTTPResponse_t response = {
//         .pBuffer = response_buffer,
//         .bufferLen = sizeof(response_buffer)
//     };

//     status = HTTPClient_Send(&transport, &request_headers, NULL, 0,
//     &response, 0); if (status != HTTPSuccess) {
//         return GGL_ERR_FAILURE;
//     }

//     GglBuffer json_buf = {.data = response.pBody, .len = response.bodyLen};
//     GglObject json_obj;
//     GglError ret = ggl_json_decode(json_buf, &json_obj);
//     if (ret != GGL_ERR_OK) {
//         return GGL_ERR_FAILURE;
//     }

//     GglObject access_key_obj, secret_key_obj, token_obj;
//     if (ggl_map_get(json_obj.map, GGL_STR("AccessKeyId"), &access_key_obj) !=
//     GGL_ERR_OK ||
//         ggl_map_get(json_obj.map, GGL_STR("SecretAccessKey"),
//         &secret_key_obj) != GGL_ERR_OK || ggl_map_get(json_obj.map,
//         GGL_STR("Token"), &token_obj) != GGL_ERR_OK) { return
//         GGL_ERR_FAILURE;
//     }

//     static char access_key_buf[128], secret_key_buf[128], token_buf[512];
//     memcpy(access_key_buf, access_key_obj.buf.data, access_key_obj.buf.len);
//     access_key_buf[access_key_obj.buf.len] = '\0';
//     memcpy(secret_key_buf, secret_key_obj.buf.data, secret_key_obj.buf.len);
//     secret_key_buf[secret_key_obj.buf.len] = '\0';
//     memcpy(token_buf, token_obj.buf.data, token_obj.buf.len);
//     token_buf[token_obj.buf.len] = '\0';

//     sigv4_details->access_key_id = (GglBuffer){.data =
//     (uint8_t*)access_key_buf, .len = access_key_obj.buf.len};
//     sigv4_details->secret_access_key = (GglBuffer){.data =
//     (uint8_t*)secret_key_buf, .len = secret_key_obj.buf.len};
//     sigv4_details->session_token = (GglBuffer){.data = (uint8_t*)token_buf,
//     .len = token_obj.buf.len}; return GGL_ERR_OK;
// }

static void *consumer_thread(void *arg) {
    (void) arg;

    (void) ggl_sleep(2);
    static uint8_t log_buffers[MAX_LOG_EVENTS][MAX_LINE_LENGTH];
    static GglBuffer buf_list[MAX_LOG_EVENTS];

    /* Set up SigV4 credentials */
    SigV4Details sigv4_details = {
        .aws_region = GGL_STR("us-west-2"),
        .aws_service = GGL_STR("logs"),
        .access_key_id = GGL_STR("REPLACE HERE"),
        .secret_access_key
        = GGL_STR("REPLACE HERE"),
        .session_token = GGL_STR(
            "REPLACE HERE"
        )
    };

    // /* Fetch credentials from Greengrass TES */
    // if (fetch_tes_credentials(&sigv4_details) != GGL_ERR_OK) {
    //     GGL_LOGE("Failed to fetch AWS credentials from TES");
    //     return NULL;
    // }

    while (1) {
        size_t log_count = 0;

        // Collect logs into buffer list without removing from ring buffer yet
        while (log_count < MAX_LOG_EVENTS) {
            GglBuffer log;
            uint64_t timestamp;
            if (log_store_get(&log, &timestamp)) {
                if (log.len > 0 && log.len < MAX_LINE_LENGTH) {
                    memcpy(log_buffers[log_count], log.data, log.len);
                    buf_list[log_count] = (GglBuffer
                    ) { .data = log_buffers[log_count], .len = log.len };
                    log_count++;
                    log_store_remove(); // Remove after copying to local buffer
                } else {
                    log_store_remove(); // Remove invalid entries
                }
            } else {
                break;
            }
        }

        // Upload logs if we have any
        if (log_count > 0) {
            // GGL_LOGI("Uploading %zu log events", log_count);
            for (size_t i = 0; i < log_count && i < 3; i++) {
                // GGL_LOGI("Log %zu length: %zu", i, buf_list[i].len);
            }
            GglBufList log_lines = { .bufs = buf_list, .len = log_count };
            // GglError ret = upload_logs_to_cloud_watch(log_lines,
            // sigv4_details); if (ret != GGL_ERR_OK) {
            //     GGL_LOGE("Failed to upload logs to CloudWatch");
            // }

            // Space is already released by log_store_remove() calls above
            post_logs_to_httpbin(sigv4_details);
        }

        (void) ggl_sleep_ms(1000);
    }
    return NULL;
}

static void *producer_thread(void *arg) {
    (void) arg;

    const char *cmd = "journalctl -mf --no-pager";

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        GGL_LOGE("popen failed\n");
        return NULL;
    }

    char buffer[MAX_LINE_LENGTH] = { 0 };
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        GGL_LOGI("Producer: %s", buffer);

        uint64_t timestamp = (uint64_t) time(NULL);
        GglBuffer log_buf
            = { .data = (uint8_t *) buffer, .len = strlen(buffer) };

        GglError ret = log_store_add(log_buf, timestamp);
        if (ret == GGL_ERR_NOMEM) {
            log_store_remove();
            ret = log_store_add(log_buf, timestamp);
            if (ret != GGL_ERR_OK) {
                GGL_LOGE("Failed to replace and add to the ring buffer.");
            }
            continue;
        }
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("Failed to add to the ring buffer. Sleeping for 10 seconds"
            );
            (void) ggl_sleep(10);
        }
    }

    return NULL;
}

int main(void) {
    ggl_sdk_init();

    pthread_t reader_tid;
    pthread_t consumer_tid;

    // Tell journalctl that fancy thing such as colour and paging aren't
    // required
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    setenv("TERM", "dumb", 1);

    pthread_create(&reader_tid, NULL, producer_thread, NULL);
    pthread_create(&consumer_tid, NULL, consumer_thread, NULL);

    pthread_join(reader_tid, NULL);
    pthread_join(consumer_tid, NULL);

    return 0;
}
