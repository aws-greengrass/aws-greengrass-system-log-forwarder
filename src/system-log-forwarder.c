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
#include <sys/time.h>
#include <sys/types.h>
#include <time.h>
#include <stdio.h>
#include <stdlib.h>

#define INVALID_UINT64 ((uint64_t) (-1)) // == 0xFFFFFFFFFFFFFFFF
#define MAX_TIMESTAMP_DIGITS (26) // Max digits for int64_t + null terminator

static GglError get_timestamp_as_string(
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
    } else {
        GGL_LOGE("Not enough memory to store timestamp.");
        return GGL_ERR_NOMEM;
    }
    return GGL_ERR_OK;
}

static GglError upload_prefix_format(
    GglByteVec *upload_doc, const Config *config
) {
    GglError ret
        = ggl_byte_vec_append(upload_doc, GGL_STR("{\"logGroupName\":\""));
    ggl_byte_vec_chain_append(&ret, upload_doc, config->logGroup);
    ggl_byte_vec_chain_append(
        &ret, upload_doc, GGL_STR("\",\"logStreamName\":\"")
    );

    if (config->logStream.len > 0) {
        ggl_byte_vec_chain_append(&ret, upload_doc, config->logStream);
    } else {
        static uint8_t timestamp_mem[MAX_TIMESTAMP_DIGITS] = { 0 };
        GglBuffer timestamp_as_buffer = GGL_BUF(timestamp_mem);
        ret = get_timestamp_as_string(&timestamp_as_buffer, INVALID_UINT64);
        if (ret != GGL_ERR_OK) {
            return ret;
        }
        ggl_byte_vec_chain_append(&ret, upload_doc, config->thingName);
        ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("-"));
        ggl_byte_vec_chain_append(&ret, upload_doc, timestamp_as_buffer);
    }

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

    ret = get_timestamp_as_string(&timestamp_as_buffer, timestamp);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    ggl_byte_vec_chain_append(&ret, upload_doc, timestamp_as_buffer);

    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR(",\"message\":\""));
    ggl_byte_vec_chain_append(&ret, upload_doc, log);
    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("\"}"));

    return ret;
}

static size_t json_format_size_calculator(
    uint64_t timestamp, GglBuffer timestamp_as_buffer
) {
    GglError ret = get_timestamp_as_string(&timestamp_as_buffer, timestamp);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    size_t header_size = strlen("{timestamp\": ")
        + strlen((char *) timestamp_as_buffer.data)
        + strlen("\", \"message\":\"\"},");
    return header_size;
}

static GglError upload_and_reset(
    GglByteVec *upload_doc, uint16_t *number_of_logs_added, const Config *config
) {
    GglError ret = GGL_ERR_OK;
    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("]}"));
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to add json terminators, Error Code %d", ret);
        return ret;
    }

    GGL_LOGI("Upload document is full, uploading now..");
    GGL_LOGT(
        "Upload Document: %.*s", (int) upload_doc->buf.len, upload_doc->buf.data
    );

    /* Set up SigV4 credentials */
    // All the values must be null terminated
    SigV4Details sigv4_details = { .aws_region = GGL_STR("us-west-2"),
                                   .aws_service = GGL_STR("logs"),
                                   .access_key_id = GGL_STR("here"),
                                   .secret_access_key = GGL_STR("here"),
                                   .session_token = GGL_STR("here") };

    ret = upload_logs_to_cloud_watch(*upload_doc, sigv4_details, *config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to upload to Cloudwatch, Error Code %d", ret);
        return ret;
    }

    // Reset the upload buffer memory
    memset(upload_doc->buf.data, 0, upload_doc->buf.len);
    upload_doc->buf.len = 0;
    *number_of_logs_added = 0;

    // Re-add the required prefix
    ret = upload_prefix_format(upload_doc, config);
    return ret;
}

static GglError process_log(
    GglByteVec *upload_doc,
    GglBuffer timestamp_as_buffer,
    uint16_t *number_of_logs_added,
    const Config *config
) {
    GglBuffer log;
    uint64_t timestamp;
    GglError ret = GGL_ERR_OK;

    if (slf_log_store_get(&log, &timestamp)) {
        if (log.len > 0) {
            GGL_LOGD("Consumer: %.*s", (int) log.len, log.data);
            // Remove the new line character from the logs
            if ((log.data[log.len - 1]) == '\n') {
                log.len--;
            }
            size_t json_format_size
                = json_format_size_calculator(timestamp, timestamp_as_buffer);

            if (upload_doc->capacity
                > (upload_doc->buf.len
                   + (log.len + json_format_size + strlen("]}")))) {
                ret = format_log_events(
                    upload_doc,
                    log,
                    timestamp,
                    timestamp_as_buffer,
                    *number_of_logs_added
                );
                if (ret != GGL_ERR_OK) {
                    GGL_LOGE(
                        "Failed to create the upload document, Error: %d", ret
                    );
                    return ret;
                }
            } else {
                ret = upload_and_reset(
                    upload_doc, number_of_logs_added, config
                );
                if (ret != GGL_ERR_OK) {
                    GGL_LOGE(
                        "Failed to upload logs to Cloudwatch and reset memory. "
                        "Error GGL code: "
                        "%d",
                        ret
                    );
                    return ret;
                }

                // Now process the current log entry with the reset buffer
                ret = format_log_events(
                    upload_doc,
                    log,
                    timestamp,
                    timestamp_as_buffer,
                    *number_of_logs_added
                );
                if (ret != GGL_ERR_OK) {
                    GGL_LOGE(
                        "Failed to create the upload document after reset, "
                        "Error: %d",
                        ret
                    );
                    return ret;
                }
            }

            slf_log_store_remove();
            (*number_of_logs_added)++;
            // TODO: Marker for future
            return GGL_ERR_EXPECTED;
        }
        // Got Empty Log
    }
    // Empty ring buffer
    return GGL_ERR_OK;
}

static void *consumer_thread(void *arg) {
    Config *config = (Config *) arg;
    uint8_t upload_mem[MAX_UPLOAD_SIZE] = { 0 };
    GglByteVec upload_doc = GGL_BYTE_VEC(upload_mem);
    (void) ggl_sleep(2);

    static uint8_t timestamp_mem[MAX_TIMESTAMP_DIGITS] = { 0 };
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
        ret = process_log(
            &upload_doc, timestamp_as_buffer, &number_of_logs_added, config
        );
        if (ret == GGL_ERR_EXPECTED) {
            continue;
        }
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("Failed to process log. Error GGL code: %d", ret);
            break;
        }
        (void) ggl_sleep(10);
    }
    return NULL;
}

static GglError producer_thread(void) {
    if (slf_initialize_ringbuf_state() != GGL_ERR_OK) {
        _Exit(1);
    }

    const char *cmd = "journalctl -mf --no-pager";

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        GGL_LOGE("popen failed\n");
        return GGL_ERR_FAILURE;
    }

    char buffer[MAX_LINE_LENGTH] = { 0 };
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        GGL_LOGD("Producer: %s", buffer);

        struct timeval tv;
        int time_status = gettimeofday(&tv, NULL);
        if (time_status != 0) {
            GGL_LOGE("Failed to get the current time.");
            return GGL_ERR_INVALID;
        }
        uint64_t timestamp
            = (uint64_t) ((tv.tv_sec * 1000) + (tv.tv_usec / 1000));
        GglBuffer log_buf
            = { .data = (uint8_t *) buffer, .len = strlen(buffer) };

        GglError ret = slf_log_store_add(log_buf, timestamp);
        if (ret == GGL_ERR_NOMEM) {
            slf_log_store_remove();
            ret = slf_log_store_add(log_buf, timestamp);
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
        { "logStream", 's', "name", 0, "Log stream name", 0 },
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
    case 's':
        config->logStream = ggl_buffer_from_null_term(arg);
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
                      .logStream = NULL,
                      .region = NULL,
                      .port = GGL_STR("443\0") };
    ggl_sdk_init();

    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    argp_parse(&argp, argc, argv, 0, 0, &config);

    GGL_LOGD(
        "Config: \n maxUploadIntervalSec=%ds \n maxRetriesCount=%d \n "
        "bufferCapacity=%d \n logGroup=%.*s \n logStream=%.*s \n "
        "thingName=%.*s \n region=%.*s \n port=%.*s \n",
        config.maxUploadIntervalSec,
        config.maxRetriesCount,
        config.bufferCapacity,
        (int) config.logGroup.len,
        config.logGroup.data,
        (int) config.logStream.len,
        config.logStream.data,
        (int) config.thingName.len,
        config.thingName.data,
        (int) config.region.len,
        config.region.data,
        (int) config.port.len,
        config.port.data
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
