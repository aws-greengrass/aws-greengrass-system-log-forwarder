// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef SYSTEM_LOG_FORWARDER_H
#define SYSTEM_LOG_FORWARDER_H

#include <ggl/buffer.h>
#include <ggl/error.h>
#define MAX_LINE_LENGTH (2048)
#define THING_NAME_MAX_LENGTH (128)
#define GGL_IPC_MAX_SVCUID_LEN (16)
// #define MAX_UPLOAD_SIZE (1048000)
#define MAX_UPLOAD_SIZE (1610)

/// AWS Service information and temporary credentials
///
/// Use fetch_token() to retrieve id, key, and token
typedef struct SigV4Details {
    /// AWS region code (e.g. "us-east-2")
    GglBuffer aws_region;
    /// AWS service endpoint name (e.g. "s3" or "lambda")
    GglBuffer aws_service;
    /// Temporary AWS ID
    GglBuffer access_key_id;
    /// Temporary AWS Key
    GglBuffer secret_access_key;
    /// Temporary AWS Token
    GglBuffer session_token;
} SigV4Details;

typedef struct {
    int maxUploadIntervalSec;
    int maxRetriesCount;
    int bufferCapacity;
    GglBuffer logGroup;
    GglBuffer thingName;
    GglBuffer region;
    GglBuffer port;
} Config;

// Function to upload logs to CloudWatch
GglError upload_logs_to_cloud_watch(
    GglBufList log_lines, SigV4Details sigv4_details
);

#endif
