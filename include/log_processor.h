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
#include <stdint.h>

/// @brief Processes a single log entry and adds it to the upload document.
/// This function formats a log entry with its timestamp and appends it to the
/// CloudWatch-compatible JSON document for batch upload.
/// @param[out] upload_doc Vector containing the JSON document being
/// constructed
/// @param[in] timestamp_as_buffer Buffer containing the formatted timestamp for
/// the log entry
/// @param[out] number_of_logs_added Pointer to counter tracking total logs
/// added to document
/// @return GGL_ERR_OK on success, GGL_ERR_NOMEM if buffer full,
/// GGL_ERR_EXPECTED if no logs
GglError slf_fetch_and_format_log(
    GglByteVec *upload_doc,
    GglBuffer timestamp_as_buffer,
    uint16_t *number_of_logs_added
);

/// @brief Formats the prefix section of the CloudWatch upload document.
/// This function initializes the JSON structure required for CloudWatch
/// PutLogEvents API calls, including log group and stream identification.
/// @param[out] upload_doc Vector to store the formatted JSON prefix
/// @param[in] config Configuration containing log group, stream, and formatting
/// settings
/// @return GGL_ERR_OK on success, error code on failure
GglError slf_upload_prefix_format(GglByteVec *upload_doc, const Config *config);

/// @brief Uploads the current log batch to CloudWatch and resets the buffer.
/// This function finalizes the JSON document, uploads it to CloudWatch using
/// SigV4 authentication, and resets the buffer for the next batch.
/// @param[in,out] upload_doc Vector containing the JSON document to upload
/// @param[in,out] number_of_logs_added Pointer to counter that will be reset
/// @param[in] config Configuration containing upload settings
/// @return GGL_ERR_OK on success, error code on failure
GglError slf_upload_and_reset(
    GglByteVec *upload_doc, uint16_t *number_of_logs_added, const Config *config
);

#endif
