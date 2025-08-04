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
#include <ggl/json_encode.h>
#include <ggl/log.h>
#include <ggl/object.h>
#include <ggl/sdk.h>
#include <ggl/utils.h>
#include <ggl/vector.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <systemd/sd-journal.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TIMESTAMP_DIGITS (26) // Max digits for int64_t + null terminator
#define MAX_RING_BUFFER_RETRIES (3) // Max retries for ring buffer operations

static GglError escape_json_string_ggl(
    char *dest,
    size_t dest_size,
    const char *src,
    size_t src_len,
    size_t *escaped_len
) {
    GglBuffer src_buf = { .data = (uint8_t *) src, .len = src_len };
    GglObject str_obj = ggl_obj_buf(src_buf);

    GglBuffer dest_buf = { .data = (uint8_t *) dest, .len = dest_size };
    GglError ret = ggl_json_encode(str_obj, &dest_buf);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    // ggl_json_encode includes quotes, but we need the content without quotes
    // since we add quotes in the JSON structure manually
    if (dest_buf.len >= 2 && dest[0] == '"' && dest[dest_buf.len - 1] == '"') {
        // Remove surrounding quotes and shift content
        memmove(dest, dest + 1, dest_buf.len - 2);
        *escaped_len = dest_buf.len - 2;
        dest[*escaped_len] = '\0';
    } else {
        *escaped_len = dest_buf.len;
        dest[*escaped_len] = '\0';
    }

    return GGL_ERR_OK;
}

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

static GglError setup_journal(sd_journal **journal) {
    char errbuf[256];
    int ret = sd_journal_open(journal, SD_JOURNAL_ALL_NAMESPACES);
    if (ret < 0) {
        if (strerror_r(-ret, errbuf, sizeof(errbuf)) != 0) {
            snprintf(errbuf, sizeof(errbuf), "Error %d", -ret);
        }
        GGL_LOGE("Failed to open journal: %s", errbuf);
        return GGL_ERR_FAILURE;
    }

    ret = sd_journal_seek_tail(*journal);
    if (ret < 0) {
        if (strerror_r(-ret, errbuf, sizeof(errbuf)) != 0) {
            snprintf(errbuf, sizeof(errbuf), "Error %d", -ret);
        }
        GGL_LOGE("Failed to seek to journal tail: %s", errbuf);
        sd_journal_close(*journal);
        return GGL_ERR_FAILURE;
    }
    sd_journal_previous(*journal);
    return GGL_ERR_OK;
}

static void process_journal_entry(sd_journal *journal, char *buffer) {
    const void *data = NULL;
    size_t length = 0;
    uint64_t timestamp = 0;
    char errbuf[256] = { 0 };

    int ret = sd_journal_get_realtime_usec(journal, &timestamp);
    if (ret < 0) {
        if (strerror_r(-ret, errbuf, sizeof(errbuf)) != 0) {
            snprintf(errbuf, sizeof(errbuf), "Error %d", -ret);
        }
        GGL_LOGE("Failed to get timestamp: %s", errbuf);
        return;
    }

    // Convert microseconds to milliseconds for as per CloudWatch Requirements
    timestamp /= 1000;

    ret = sd_journal_get_data(journal, "MESSAGE", &data, &length);
    if ((ret < 0) || (length < 8U)) {
        if (length < 8U) {
            GGL_LOGE("Invalid journal data length: %zu", length);
        }
        return;
    }

    // Skip "MESSAGE=" prefix (8 bytes) to get actual log content
    const char *msg = &((const char *) data)[8];
    size_t msg_len = length - 8U;

    // Truncate message to half buffer size to allow for JSON escaping expansion
    if (msg_len >= (MAX_LOG_LINE_LENGTH / 2U)) {
        msg_len = (MAX_LOG_LINE_LENGTH / 2U) - 1U;
    }

    size_t escaped_len;
    if (escape_json_string_ggl(
            buffer, MAX_LOG_LINE_LENGTH, msg, msg_len, &escaped_len
        )
        != GGL_ERR_OK) {
        GGL_LOGE("Failed to escape JSON string");
        return;
    }

    GglBuffer log_buf = { .data = (uint8_t *) buffer, .len = escaped_len };

    GglError ggl_ret = slf_log_store_add(log_buf, timestamp);
    if (ggl_ret == GGL_ERR_NOMEM) {
        // Ring buffer full - remove entries until space is available
        uint8_t retry_count = 0;

        while (ggl_ret == GGL_ERR_NOMEM && retry_count < MAX_RING_BUFFER_RETRIES
        ) {
            slf_log_store_remove();
            ggl_ret = slf_log_store_add(log_buf, timestamp);
            retry_count++;
        }

        if (ggl_ret != GGL_ERR_OK) {
            GGL_LOGE(
                "Failed to add to ring buffer after %u retries", retry_count
            );
        }
        return;
    }
    if (ggl_ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to add to the ring buffer. Sleeping for 10 seconds");
        (void) ggl_sleep(10);
    }
}

static GglError producer_thread(Config config) {
    if (slf_initialize_ringbuf_state(config.bufferCapacity) != GGL_ERR_OK) {
        GGL_LOGE("Failed to initialize ring buffer. Exiting.");
        _Exit(1);
    }

    char buffer[MAX_LOG_LINE_LENGTH];
    char errbuf[256];
    sd_journal *journal;

    GglError setup_ret = setup_journal(&journal);
    if (setup_ret != GGL_ERR_OK) {
        return setup_ret;
    }

    while (true) {
        int ret = sd_journal_wait(journal, (uint64_t) -1);
        if (ret < 0) {
            if (strerror_r(-ret, errbuf, sizeof(errbuf)) != 0) {
                snprintf(errbuf, sizeof(errbuf), "Error %d", -ret);
            }
            GGL_LOGE("Failed to wait for journal changes: %s", errbuf);
            break;
        }

        while (sd_journal_next(journal) > 0) {
            process_journal_entry(journal, buffer);
        }
    }

    sd_journal_close(journal);
    return GGL_ERR_OK;
}

static char doc[] = "system-log-forwarder -- AWS Greengrass component for "
                    "forwarding logs to CloudWatch\n"
                    "Required arguments: --logGroup, --thingName";

static error_t safe_str_to_int(const char *str, int *result) {
    long temp_val = strtol(str, NULL, 10);
    if (temp_val < INT_MIN || temp_val > INT_MAX) {
        return ARGP_ERR_UNKNOWN;
    }
    *result = (int) temp_val;
    return 0;
}

static error_t safe_str_to_size_t(const char *str, size_t *result) {
    unsigned long temp_val = strtoul(str, NULL, 10);
    if (temp_val > SIZE_MAX) {
        return ARGP_ERR_UNKNOWN;
    }
    *result = (size_t) temp_val;
    return 0;
}

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
        { "port", 'p', "integer", 0, "Port number", 0 },
        { 0 } };

static error_t arg_parser(int key, char *arg, struct argp_state *state) {
    Config *config = state->input;
    switch (key) {
    case 'i': {
        error_t result = safe_str_to_int(arg, &config->maxUploadIntervalSec);
        if (result != 0) {
            return result;
        }
        break;
    }
    case 'r': {
        error_t result = safe_str_to_int(arg, &config->maxRetriesCount);
        if (result != 0) {
            return result;
        }
        break;
    }

    case 'b': {
        error_t result = safe_str_to_size_t(arg, &config->bufferCapacity);
        if (result != 0) {
            return result;
        }
        break;
    }
    case 'g':
        config->logGroup = ggl_buffer_from_null_term(arg);
        break;
    case 's':
        config->logStream = ggl_buffer_from_null_term(arg);
        break;
    case 't':
        config->thingName = ggl_buffer_from_null_term(arg);
        break;
    case 'p': {
        int port_val;
        error_t result = safe_str_to_int(arg, &port_val);
        if (result != 0) {
            return result;
        }
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
            GGL_LOGE("Error: logGroup and thingName are required");
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            argp_usage(state);
        }
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }

    return 0;
}

static GglError validate_slf_config(Config *config) {
    // maxUploadIntervalSec must not be greater than 24 hours, to ensure all log
    // events are within the same 24 hour period
    if (config->maxUploadIntervalSec > 86400) {
        GGL_LOGE("Configuration maxUploadIntervalSec must not be greater than "
                 "24 hours");
        return GGL_ERR_INVALID;
    }

    if (config->logStream.len == 0) {
        config->logStream = config->thingName;
        GGL_LOGI("logStream not provided, using thingName as logStream");
    }

    return GGL_ERR_OK;
}

static struct argp argp = { opts, arg_parser, 0, doc, 0, 0, 0 };

int main(int argc, char *argv[]) {
    Config config = { .bufferCapacity = (size_t) (1024 * 1024),
                      .maxRetriesCount = 3,
                      .maxUploadIntervalSec = 300,
                      .logGroup = { 0 },
                      .logStream = { 0 },
                      .port = GGL_STR("443") };
    ggl_sdk_init();

    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    argp_parse(&argp, argc, argv, 0, 0, &config);

    GglError ret = validate_slf_config(&config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error validating component configuration");
        return 1;
    }

    GGL_LOGD(
        "Config: \n maxUploadIntervalSec=%ds \n maxRetriesCount=%d \n "
        "bufferCapacity=%zu \n logGroup=%.*s \n logStream=%.*s \n "
        "thingName=%.*s \n port=%.*s \n",
        config.maxUploadIntervalSec,
        config.maxRetriesCount,
        config.bufferCapacity,
        (int) config.logGroup.len,
        config.logGroup.data,
        (int) config.logStream.len,
        config.logStream.data,
        (int) config.thingName.len,
        config.thingName.data,
        (int) config.port.len,
        config.port.data
    );

    pthread_t consumer_tid;

    pthread_create(&consumer_tid, NULL, consumer_thread, &config);

    ret = producer_thread(config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Producer thread failed.");
    }

    pthread_join(consumer_tid, NULL);
    GGL_LOGE("Should never reach this point");

    return 0;
}
