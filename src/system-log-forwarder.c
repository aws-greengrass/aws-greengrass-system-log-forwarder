// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "system-log-forwarder.h"
#include "ggl/vector.h"
#include "ring_buffer.h"
#include <argp.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/sdk.h>
#include <ggl/utils.h>
#include <inttypes.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define INVALID_UINT64 ((uint64_t) (-1)) // == 0xFFFFFFFFFFFFFFFF

static void get_timestamp_as_string(
    GglBuffer *timestamp_as_buffer, uint64_t timestamp
) {
    if (timestamp == INVALID_UINT64) {
        timestamp = (uint64_t) time(NULL);
    }

    memset(timestamp_as_buffer->data, 0, timestamp_as_buffer->len);

    int ret_check = snprintf(
        (char *) timestamp_as_buffer->data,
        timestamp_as_buffer->len,
        "%" PRId64,
        timestamp
    );
    if (ret_check > 0 && (size_t) ret_check < timestamp_as_buffer->len) {
        timestamp_as_buffer->len = (size_t) ret_check;
    }
}

static GglError upload_prefix_format(
    GglByteVec *upload_doc, const Config *config
) {
    // Max digits for int64_t + sign + null terminator
    static uint8_t timestamp_mem[21] = { 0 };
    GglBuffer timestamp_as_buffer = GGL_BUF(timestamp_mem);
    get_timestamp_as_string(&timestamp_as_buffer, INVALID_UINT64);

    GglError ret
        = ggl_byte_vec_append(upload_doc, GGL_STR("{\"logGroupName\":\""));
    ggl_byte_vec_chain_append(&ret, upload_doc, config->logGroup);
    ggl_byte_vec_chain_append(
        &ret, upload_doc, GGL_STR("\",\"logStreamName\":\"")
    );
    ggl_byte_vec_chain_append(&ret, upload_doc, config->thingName);
    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("-"));
    ggl_byte_vec_chain_append(&ret, upload_doc, timestamp_as_buffer);
    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("\", \"logEvents\":["));
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    return GGL_ERR_OK;
}

static GglError format_log_events(
    GglByteVec *upload_doc,
    GglBuffer log,
    uint64_t timestamp,
    GglBuffer timestamp_as_buffer,
    uint16_t number_of_logs_added
) {
    GglError ret = GGL_ERR_OK;
    if (number_of_logs_added > 0) {
        ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR(","));
    }

    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("{\"timestamp\":"));

    get_timestamp_as_string(&timestamp_as_buffer, timestamp);
    ggl_byte_vec_chain_append(&ret, upload_doc, timestamp_as_buffer);

    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR(",\"message\":\""));
    ggl_byte_vec_chain_append(&ret, upload_doc, log);
    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("\"}"));

    return ret;
}

// NOLINTNEXTLINE(readability-function-cognitive-complexity)
static void *consumer_thread(void *arg) {
    Config *config = (Config *) arg;
    uint8_t upload_mem[MAX_UPLOAD_SIZE] = { 0 };
    GglByteVec upload_doc = GGL_BYTE_VEC(upload_mem);
    (void) ggl_sleep(2);
    // Max digits for int64_t + sign + null terminator
    static uint8_t timestamp_mem[21] = { 0 };
    GglBuffer timestamp_as_buffer = GGL_BUF(timestamp_mem);

    GglError ret = upload_prefix_format(&upload_doc, config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE(
            "Failed to add prefix data to upload document. Error GGL code: %d",
            ret
        );
    }

    uint16_t number_of_logs_added = 0;
    while (1) {
        GglBuffer log;
        uint64_t timestamp;

        if (log_store_get(&log, &timestamp)) {
            if (log.len > 0) {
                GGL_LOGW("Consumer: %.*s", (int) log.len, log.data);
                if ((log.data[log.len - 1]) == '\n') {
                    log.len--;
                }

                if (upload_doc.capacity
                    > (upload_doc.buf.len + log.len + 43 + 2)) {
                    ret = format_log_events(
                        &upload_doc,
                        log,
                        timestamp,
                        timestamp_as_buffer,
                        number_of_logs_added
                    );
                    if (ret != GGL_ERR_OK) {
                        GGL_LOGE(
                            "Failed to create the upload document, Error: %d",
                            ret
                        );
                        break;
                    }
                } else {
                    ggl_byte_vec_chain_append(&ret, &upload_doc, GGL_STR("]}"));
                    if (ret != GGL_ERR_OK) {
                        GGL_LOGE(
                            "Failed to add json terminators, Error Code %d", ret
                        );
                        break;
                    }

                    GGL_LOGI("Upload document is full, uploading now..");

                    GGL_LOGW(
                        "Upload Document: %.*s",
                        (int) upload_doc.buf.len,
                        upload_doc.buf.data
                    );

                    // Reset the upload buffer memory
                    memset(upload_doc.buf.data, 0, upload_doc.buf.len);
                    upload_doc.buf.len = 0;
                    number_of_logs_added = 0;

                    // Read the required prefix
                    ret = upload_prefix_format(&upload_doc, config);
                    if (ret != GGL_ERR_OK) {
                        GGL_LOGE(
                            "Failed to add prefix data to upload document. "
                            "Error GGL code: "
                            "%d",
                            ret
                        );
                    }
                    GGL_LOGW(
                        "Consumer: %.*s, Capacity: %zu",
                        (int) upload_doc.buf.len,
                        upload_doc.buf.data,
                        upload_doc.capacity
                    );
                    continue;
                }

                log_store_remove();
                number_of_logs_added++;
                continue;
            }
        }
        (void) ggl_sleep(10);
    }
    return NULL;
}

static GglError producer_thread(void) {
    const char *cmd = "journalctl -mf --no-pager";

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        GGL_LOGE("popen failed\n");
        return GGL_ERR_FAILURE;
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

    return GGL_ERR_OK;
}

static char doc[] = "system-log-forwarder -- AWS Greengrass component for "
                    "forwarding logs to CloudWatch";

static struct argp_option opts[]
    = { { "maxUploadIntervalSec",
          'i',
          "integer",
          0,
          "Maximum upload interval in seconds",
          0 },
        { "maxRetriesCount", 'r', "integer", 0, "Maximum retry count", 0 },
        { "bufferCapacity", 'b', "integer", 0, "Buffer capacity", 0 },
        { "logGroup", 'g', "name", 0, "Log group name", 0 },
        { "thingName", 't', "name", 0, "Device/Thing name", 0 },
        { "region", 'R', "name", 0, "AWS region", 0 },
        { "port", 'p', "integer", 0, "Port number", 0 },
        { 0 } };

static error_t arg_parser(int key, char *arg, struct argp_state *state) {
    Config *config = state->input;
    switch (key) {
    case 'i':
        config->maxUploadIntervalSec = atoi(arg);
        break;
    case 'r':
        config->maxRetriesCount = atoi(arg);
        break;
    case 'b':
        config->bufferCapacity = atoi(arg);
        break;
    case 'g':
        config->logGroup = ggl_buffer_from_null_term(arg);
        break;
    case 't':
        config->thingName = ggl_buffer_from_null_term(arg);
        break;
    case 'R':
        config->region = ggl_buffer_from_null_term(arg);
        break;
    case 'p': {
        int port_val = atoi(arg);
        if (port_val <= 0 || port_val > 65535) {
            GGL_LOGW("Error: port must be between 1 and 65535");
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            argp_usage(state);
        }
        config->port = ggl_buffer_from_null_term(arg);
        break;
    }
    case ARGP_KEY_END:
        if (config->logGroup.len == 0 || config->thingName.len == 0) {
            GGL_LOGW("Error: logGroup and thingName are required");
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static struct argp argp = { opts, arg_parser, 0, doc, 0, 0, 0 };

int main(int argc, char *argv[]) {
    Config config = { .bufferCapacity = (1024 * 1024),
                      .maxRetriesCount = 3,
                      .maxUploadIntervalSec = 300,
                      .logGroup = NULL,
                      .region = NULL,
                      .port = GGL_STR("443") };
    ggl_sdk_init();

    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    argp_parse(&argp, argc, argv, 0, 0, &config);

    GGL_LOGI("Configuration:");
    GGL_LOGI("  maxUploadIntervalSec: %d", config.maxUploadIntervalSec);
    GGL_LOGI("  maxRetriesCount: %d", config.maxRetriesCount);
    GGL_LOGI("  bufferCapacity: %d", config.bufferCapacity);
    GGL_LOGI(
        "  logGroup: %.*s", (int) config.logGroup.len, config.logGroup.data
    );
    GGL_LOGI(
        "  thingName: %.*s", (int) config.thingName.len, config.thingName.data
    );

    pthread_t consumer_tid;

    // Tell journalctl that fancy thing such as colour and paging aren't
    // required
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    setenv("TERM", "dumb", 1);

    pthread_create(&consumer_tid, NULL, consumer_thread, &config);

    GglError ret = producer_thread();
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Producer thread failed.");
    }

    pthread_join(consumer_tid, NULL);
    GGL_LOGE("Should never reach this point");

    return 0;
}
