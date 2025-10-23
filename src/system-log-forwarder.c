// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "system-log-forwarder.h"
#include "log_processor.h"
#include "ring_buffer.h"
#include <argp.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/io.h>
#include <ggl/json_decode.h>
#include <ggl/json_encode.h>
#include <ggl/log.h>
#include <ggl/map.h>
#include <ggl/object.h>
#include <ggl/sdk.h>
#include <ggl/utils.h>
#include <ggl/vector.h>
#include <limits.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <systemd/sd-journal.h>
#include <time.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

#define MAX_TIMESTAMP_DIGITS (26) // Max digits for int64_t + null terminator
#define MAX_RING_BUFFER_RETRIES (3) // Max retries for ring buffer operations

typedef struct {
    Config *config;
    GglArena *config_arena;
} ArgData;

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
    GglByteVec dest_vec = ggl_byte_vec_init(dest_buf);
    GglWriter writer = ggl_byte_vec_writer(&dest_vec);
    GglError ret = ggl_json_encode(str_obj, writer);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    // ggl_json_encode includes quotes, but we need the content without quotes
    // since we add quotes in the JSON structure manually
    if (dest_vec.buf.len >= 2 && dest[0] == '"'
        && dest[dest_vec.buf.len - 1] == '"') {
        // Remove surrounding quotes and shift content
        memmove(dest, dest + 1, dest_vec.buf.len - 2);
        *escaped_len = dest_vec.buf.len - 2;
        dest[*escaped_len] = '\0';
    } else {
        *escaped_len = dest_vec.buf.len;
        dest[*escaped_len] = '\0';
    }

    return GGL_ERR_OK;
}

static GglError drain_ring_buf_and_upload(
    GglByteVec *upload_doc,
    GglBuffer timestamp_buf,
    uint16_t *logs_added,
    Config *config
) {
    GglError ret = GGL_ERR_OK;
    while (true) {
        ret = slf_fetch_and_format_log(upload_doc, timestamp_buf, logs_added);
        if (ret == GGL_ERR_EXPECTED) {
            GGL_LOGD(
                "Ring buffer empty, drain complete with %u logs", *logs_added
            );
            ret = GGL_ERR_OK; // Ring buffer is empty, exit
            break;
        }
        if (ret == GGL_ERR_NOMEM) {
            GGL_LOGD("Upload buffer full, uploading %u logs", *logs_added);
            // Buffer is full, upload and reset, then retry same log
            ret = slf_upload_and_reset(upload_doc, logs_added, config);
            if (ret != GGL_ERR_OK) {
                GGL_LOGE(
                    "Failed to upload logs to CloudWatch and reset buffer. "
                    "Error code: %d",
                    ret
                );
                break;
            }
            GGL_LOGD("Upload successful, continuing drain");
            // Continue to retry processing the same log with reset buffer
            continue;
        }
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("Error during drain: %d", ret);
            break;
        }
    }

    GGL_LOGD("Drain completed with result: %d", ret);
    return ret;
}

static void *consumer_thread(void *arg) {
    Config *config = (Config *) arg;
    static uint8_t upload_mem[MAX_UPLOAD_SIZE] = { 0 };
    GglByteVec upload_doc = GGL_BYTE_VEC(upload_mem);
    static uint8_t timestamp_mem[MAX_TIMESTAMP_DIGITS] = { 0 };
    GglBuffer timestamp_as_buffer = GGL_BUF(timestamp_mem);
    uint16_t number_of_logs_added = 0;
    static time_t last_uploaded = 0;

    GglError ret = slf_upload_prefix_format(&upload_doc, config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE(
            "Failed to add prefix data to upload document. Error GGL code: %d",
            ret
        );
    }

    // coverity[infinite_loop]
    while (true) {
        time_t now = time(NULL);
        if (last_uploaded == 0) {
            last_uploaded = now;
        }

        slf_log_store_wait_for_upload_trigger(
            last_uploaded + config->maxUploadIntervalSec
        );

        ret = drain_ring_buf_and_upload(
            &upload_doc, timestamp_as_buffer, &number_of_logs_added, config
        );

        // Upload any remaining logs after draining
        if (ret == GGL_ERR_OK && number_of_logs_added > 0) {
            ret = slf_upload_and_reset(
                &upload_doc, &number_of_logs_added, config
            );
        }

        last_uploaded = now;

        if (ret != GGL_ERR_OK) {
            GGL_LOGE(
                "Failed to process ring buffer logs. Error GGL code: %d", ret
            );
            // Reset upload document to clean state
            memset(upload_doc.buf.data, 0, upload_doc.buf.len);
            upload_doc.buf.len = 0;
            number_of_logs_added = 0;
            ret = slf_upload_prefix_format(&upload_doc, config);
            if (ret != GGL_ERR_OK) {
                GGL_LOGE(
                    "Failed to reinitialize upload prefix. Error GGL code: %d",
                    ret
                );
            }
        }
    }
    return NULL;
}

static bool matches_service_filters(
    const char *service_name, GglList service_filters
) {
    if (service_filters.len == 0) {
        return true;
    }

    if (service_name == NULL) {
        return false;
    }

    for (size_t filter_idx = 0; filter_idx < service_filters.len;
         filter_idx++) {
        if (ggl_obj_type(service_filters.items[filter_idx]) != GGL_TYPE_BUF) {
            GGL_LOGW("Service filter is not a buffer, skipping");
            continue;
        }

        GglBuffer filter = ggl_obj_into_buf(service_filters.items[filter_idx]);

        if (ggl_buffer_eq(filter, GGL_STR("*"))) {
            return true;
        }

        if (filter.len > 1 && filter.data[filter.len - 1] == '*') {
            if (strlen(service_name) >= filter.len - 1
                && strncmp(service_name, (char *) filter.data, filter.len - 1)
                    == 0) {
                return true;
            }
            continue;
        }

        if (strlen(service_name) >= filter.len
            && strncmp(service_name, (char *) filter.data, filter.len) == 0) {
            return true;
        }
    }

    return false;
}

static GglError setup_journal(sd_journal **journal) {
    char errbuf[256] = { 0 };
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

static void process_journal_entry(
    sd_journal *journal, char *buffer, GglList service_filters
) {
    const void *data = NULL;
    size_t length = 0;
    uint64_t timestamp = 0;
    char errbuf[256] = { 0 };

    int ret = sd_journal_get_data(journal, "_SYSTEMD_UNIT", &data, &length);
    const size_t PREFIX_LEN = strlen("_SYSTEMD_UNIT=");
    if (ret >= 0 && length > PREFIX_LEN) {
        const char *unit_name = &((const char *) data)[PREFIX_LEN];
        if (!matches_service_filters(unit_name, service_filters)) {
            GGL_LOGT("Skipping log entry that does not match filters.");
            return;
        }
    }

    ret = sd_journal_get_realtime_usec(journal, &timestamp);
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
        // Ring buffer full - drop new log to preserve older messages
        (void) ggl_sleep(10);
        return;
    }
    if (ggl_ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to add to the ring buffer");
    }
}

static GglError producer(Config config) {
    if (slf_initialize_ringbuf_state(config.bufferCapacity) != GGL_ERR_OK) {
        GGL_LOGE("Failed to initialize ring buffer. Exiting.");
        _Exit(1);
    }

    char buffer[MAX_LOG_LINE_LENGTH] = { 0 };
    char errbuf[256] = { 0 };
    sd_journal *journal = NULL;

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
            process_journal_entry(journal, buffer, config.serviceFilters);
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
#if ULONG_MAX > SIZE_MAX
    if (temp_val > SIZE_MAX) {
        return ARGP_ERR_UNKNOWN;
    }
#endif
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
        { "filters",
          'f',
          "json_obj",
          0,
          "JSON object of filters containing a list under the services key",
          0 },
        { 0 } };

static error_t arg_parser(int key, char *arg, struct argp_state *state) {
    ArgData *arg_data = (ArgData *) state->input;
    Config *config = arg_data->config;
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
    case 'f': {
        GglBuffer json_buf = ggl_buffer_from_null_term(arg);
        GglObject json_obj;

        GglError ret = ggl_json_decode_destructive(
            json_buf, arg_data->config_arena, &json_obj
        );
        if (ret != GGL_ERR_OK || ggl_obj_type(json_obj) != GGL_TYPE_MAP) {
            GGL_LOGE("Error: filters must be a JSON object. Error while "
                     "parsing.");
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            argp_usage(state);
        }

        GglObject *services_obj;
        bool found = ggl_map_get(
            ggl_obj_into_map(json_obj), GGL_STR("services"), &services_obj
        );
        if (!found || ggl_obj_type(*services_obj) != GGL_TYPE_LIST) {
            GGL_LOGE("Error: filters must contain a 'services' key with a list "
                     "value. Error while parsing.");
            // NOLINTNEXTLINE(concurrency-mt-unsafe)
            argp_usage(state);
        }

        config->serviceFilters = ggl_obj_into_list(*services_obj);
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
                      .port = GGL_STR("443"),
                      .serviceFilters = { 0 } };
    ggl_sdk_init();

    uint8_t config_arena_mem[1024];
    GglArena config_arena = ggl_arena_init(GGL_BUF(config_arena_mem));
    ArgData arg_data = { .config = &config, .config_arena = &config_arena };

    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    argp_parse(&argp, argc, argv, 0, 0, &arg_data);

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

    ret = producer(config);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Producer thread failed.");
    }

    pthread_join(consumer_tid, NULL);
    GGL_LOGE("Should never reach this point");

    return 0;
}
