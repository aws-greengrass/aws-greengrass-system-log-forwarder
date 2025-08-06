// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef LOG_PROCESSOR_H
#define LOG_PROCESSOR_H

#include "system-log-forwarder.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/vector.h>
#include <stdbool.h>
#include <stdint.h>

/// @brief Processes a single log entry and adds it to the upload document.
/// This function formats a log entry with its timestamp and appends it to the
/// CloudWatch-compatible JSON document for batch upload.
/// @param[in|out] upload_doc Vector containing the JSON document being
/// constructed
/// @param[in] timestamp_as_buffer Buffer containing the formatted timestamp for
/// the log entry
/// @param[in|out] number_of_logs_added Pointer to counter tracking total logs
/// added to document
/// @param[in] config Configuration containing formatting and processing
/// settings
/// @param[out] uploaded Pointer to bool indicating if an upload occurred
/// @return GGL_ERR_OK on success, error code on failure
GglError slf_process_log(
    GglByteVec *upload_doc,
    GglBuffer timestamp_as_buffer,
    uint16_t *number_of_logs_added,
    const Config *config,
    bool *uploaded
);

/// @brief Formats the prefix section of the CloudWatch upload document.
/// This function initializes the JSON structure required for CloudWatch
/// PutLogEvents API calls, including log group and stream identification.
/// @param[in|out] upload_doc Vector to store the formatted JSON prefix
/// @param[in] config Configuration containing log group, stream, and formatting
/// settings
/// @return GGL_ERR_OK on success, error code on failure
GglError slf_upload_prefix_format(GglByteVec *upload_doc, const Config *config);

/// @brief Uploads the current log batch to CloudWatch and resets the upload
/// buffer. This function finalizes the JSON document, uploads it to CloudWatch
/// using AWS credentials, and resets the buffer for the next batch of logs.
/// @param[in|out] upload_doc Vector containing the JSON document to upload
/// @param[in|out] number_of_logs_added Pointer to counter that will be reset to
/// 0
/// @param[in] config Configuration containing upload settings and credentials
/// @return GGL_ERR_OK on success, error code on failure
GglError upload_and_reset(
    GglByteVec *upload_doc, uint16_t *number_of_logs_added, const Config *config
);

#endif
