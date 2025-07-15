// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "system-log-forwarder.h"
#include "log_processor.h"
#include "ring_buffer.h"
#include <argp.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/sdk.h>
#include <ggl/utils.h>
#include <ggl/vector.h>
#include <pthread.h>
#include <string.h>
#include <sys/time.h>
#include <sys/types.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TIMESTAMP_DIGITS (26) // Max digits for int64_t + null terminator

static void *consumer_thread(void *arg) {
    Config *config = (Config *) arg;
    uint8_t upload_mem[MAX_UPLOAD_SIZE] = { 0 };
    GglByteVec upload_doc = GGL_BYTE_VEC(upload_mem);
    (void) ggl_sleep(2);

    static uint8_t timestamp_mem[MAX_TIMESTAMP_DIGITS] = { 0 };
    GglBuffer timestamp_as_buffer = GGL_BUF(timestamp_mem);

    GglError ret = slf_upload_prefix_format(&upload_doc, config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE(
            "Failed to add prefix data to upload document. Error GGL code: %d",
            ret
        );
    }

    uint16_t number_of_logs_added = 0;
    while (1) {
        ret = slf_process_log(
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

static GglError producer_thread(Config config) {
    if (slf_initialize_ringbuf_state(config.bufferCapacity) != GGL_ERR_OK) {
        GGL_LOGE("Failed to initialize ring buffer. Exiting.");
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
        config->bufferCapacity = (size_t) strtoul(arg, NULL, 10);
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
    Config config = { .bufferCapacity = (size_t) (1024 * 1024),
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
        "bufferCapacity=%zu \n logGroup=%.*s \n logStream=%.*s \n "
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

    GglError ret = producer_thread(config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Producer thread failed.");
    }

    pthread_join(consumer_tid, NULL);
    GGL_LOGE("Should never reach this point");

    return 0;
}
