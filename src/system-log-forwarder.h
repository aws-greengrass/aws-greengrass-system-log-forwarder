// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef SYSTEM_LOG_FORWARDER_H
#define SYSTEM_LOG_FORWARDER_H

#include <stddef.h>
/// Maximum length in bytes for a single log line including null terminator
#define MAX_LINE_LENGTH (2048)
/// Maximum length in bytes for AWS IoT Thing name including null terminator
#define THING_NAME_MAX_LENGTH (128)
/// Maximum length in bytes for GGL IPC service unique identifier
#define GGL_IPC_MAX_SVCUID_LEN (16)
/// Maximum size in bytes for CloudWatch log upload payload
/// Based on CloudWatch PutLogEvents API limits with 576 bytes buffer space
#define MAX_UPLOAD_SIZE (1048000)

#include <ggl/buffer.h>

/// @brief AWS Service information and temporary credentials for SigV4
/// authentication. This structure contains all the necessary AWS credentials
/// and service information required to perform AWS Signature Version 4
/// authentication for API requests. Use fetch_token() to retrieve id, key, and
/// token from the credential provider.
typedef struct SigV4Details {
    /// AWS region code where the service is located (e.g., "us-east-2")
    GglBuffer aws_region;
    /// AWS service endpoint name for the target service (e.g., "logs" for
    /// CloudWatch Logs)
    GglBuffer aws_service;
    /// Temporary AWS access key ID for authentication
    GglBuffer access_key_id;
    /// Temporary AWS secret access key for authentication
    GglBuffer secret_access_key;
    /// Temporary AWS session token for temporary credentials
    GglBuffer session_token;
} SigV4Details;

/// @brief Configuration structure for the system log forwarder component.
/// This structure contains all the configurable parameters that control the
/// behavior of the log forwarding system, including timing, retry logic, and
/// AWS settings.
typedef struct {
    /// Maximum interval in seconds between log uploads to CloudWatch
    int maxUploadIntervalSec;
    /// Maximum number of retry attempts for failed upload operations
    int maxRetriesCount;
    /// Capacity in bytes for the internal log buffer
    size_t bufferCapacity;
    /// CloudWatch log group name where logs will be sent
    GglBuffer logGroup;
    /// CloudWatch log stream name within the log group
    GglBuffer logStream;
    /// AWS IoT Thing name for this device
    GglBuffer thingName;
    /// Port number for CloudWatch API connections (typically "443")
    GglBuffer port;
} Config;

#endif
