// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "log_processor.h"
#include "aws_credentials_util.h"
#include "cloud_request.h"
#include "ring_buffer.h"
#include "system-log-forwarder.h"
#include <assert.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/vector.h>
#include <inttypes.h>
#include <string.h>
#include <stdio.h>

static GglError get_timestamp_as_string(
    GglBuffer *timestamp_as_buffer, uint64_t timestamp
) {
    int ret_check = snprintf(
        (char *) timestamp_as_buffer->data,
        timestamp_as_buffer->len,
        "%" PRId64,
        timestamp
    );
    if ((ret_check > 0) && ((size_t) ret_check < timestamp_as_buffer->len)) {
        timestamp_as_buffer->len = (size_t) ret_check;
    } else {
        GGL_LOGE("Not enough memory to store timestamp.");
        return GGL_ERR_NOMEM;
    }
    return GGL_ERR_OK;
}

GglError slf_upload_prefix_format(
    GglByteVec *upload_doc, const Config *config
) {
    assert(config->logStream.len > 0);

    GglError ret
        = ggl_byte_vec_append(upload_doc, GGL_STR("{\"logGroupName\":\""));
    ggl_byte_vec_chain_append(&ret, upload_doc, config->logGroup);
    ggl_byte_vec_chain_append(
        &ret, upload_doc, GGL_STR("\",\"logStreamName\":\"")
    );
    ggl_byte_vec_chain_append(&ret, upload_doc, config->logStream);
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

    uint16_t number_of_logs_added
) {
    GglError ret = GGL_ERR_OK;
    if (number_of_logs_added > 0) {
        ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR(","));
    }

    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("{\"timestamp\":"));

    GglBuffer tmp_timestamp = ggl_byte_vec_remaining_capacity(*upload_doc);
    ret = get_timestamp_as_string(&tmp_timestamp, timestamp);
    if (ret != GGL_ERR_OK) {
        return ret;
    }
    upload_doc->buf.len += tmp_timestamp.len;

    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR(",\"message\":\""));
    ggl_byte_vec_chain_append(&ret, upload_doc, log);
    ggl_byte_vec_chain_append(&ret, upload_doc, GGL_STR("\"}"));

    return ret;
}

static size_t calculate_json_message_overhead(
    uint64_t timestamp, GglBuffer timestamp_as_buffer
) {
    GglError ret = get_timestamp_as_string(&timestamp_as_buffer, timestamp);
    if (ret != GGL_ERR_OK) {
        return 0;
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

    GGL_LOGI("Upload document is full, uploading now.");
    GGL_LOGT(
        "Upload Document: %.*s", (int) upload_doc->buf.len, upload_doc->buf.data
    );

    /* Set up SigV4 credentials */
    // All the values must be null terminated
    SigV4Details sigv4_details = { .aws_service = GGL_STR("logs") };
    uint8_t credentials_mem[4096] = { 0 };
    GglArena cred_alloc = ggl_arena_init(GGL_BUF(credentials_mem));
    ret = get_credentials_chain_credentials(&sigv4_details, &cred_alloc);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error when retrieving AWS credentials.");
        return ret;
    }

    ret = slf_upload_logs_to_cloud_watch(
        upload_doc->buf, sigv4_details, *config
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to upload to Cloudwatch, Error Code %d", ret);
        return ret;
    }

    // Reset the upload buffer memory
    memset(upload_doc->buf.data, 0, upload_doc->buf.len);
    upload_doc->buf.len = 0;
    *number_of_logs_added = 0;

    // Re-add the required prefix
    ret = slf_upload_prefix_format(upload_doc, config);
    return ret;
}

GglError slf_process_log(
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
            size_t json_message_overhead_size = calculate_json_message_overhead(
                timestamp, timestamp_as_buffer
            );
            if (json_message_overhead_size == 0) {
                GGL_LOGE("Failed to calculate json message overhead.");
                return GGL_ERR_NOMEM;
            }

            if (upload_doc->capacity
                > (upload_doc->buf.len
                   + (log.len + json_message_overhead_size + strlen("]}")))) {
                ret = format_log_events(
                    upload_doc, log, timestamp, *number_of_logs_added
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
                    upload_doc, log, timestamp, *number_of_logs_added
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
