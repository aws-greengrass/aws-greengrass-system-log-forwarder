// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef CLOUD_REQUEST_H
#define CLOUD_REQUEST_H

#include "system-log-forwarder.h"
#include <core_http_client.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <openssl/types.h>

/// Maximum size in bytes for HTTP header buffer allocation
#define MAX_HEADER_BUFFER_SIZE (4096)
/// Maximum size in bytes for HTTP response buffer allocation
#define MAX_RESPONSE_BUFFER_SIZE (4096)

/// @brief HTTP endpoint configuration for CloudWatch API requests.
/// Contains the necessary components to construct HTTP requests to AWS
/// services.
typedef struct {
    /// The hostname of the AWS service endpoint (e.g.,
    /// "logs.us-east-1.amazonaws.com")
    const char *host;
    /// The port number for the connection (typically "443" for HTTPS)
    const char *port;
    /// The API path for the specific service operation (e.g., "/")
    const char *path;
} HttpEndpoint;

/// @brief TLS connection context for secure HTTP communications.
/// Manages the SSL/TLS connection state and configuration for HTTPS requests.
typedef struct {
    /// Socket file descriptor for the network connection
    int sockfd;
    /// SSL connection object for the encrypted session
    SSL *ssl;
    /// SSL context containing configuration and certificates
    SSL_CTX *ctx;
} TLSContext;

const char *slf_http_status_to_string(HTTPStatus_t status);

/// @brief Uploads log lines to CloudWatch Logs service.
/// This function sends the provided log lines to CloudWatch using the
/// PutLogEvents API, handling the HTTP request construction and response
/// processing.
/// @param[in] log_lines Buffer containing the formatted log events to upload
/// @param[in] sigv4_details AWS credentials and service information for
/// authentication
/// @param[in] config Configuration containing target log group, stream, and
/// other settings
/// @return GGL_ERR_OK on success, error code on failure
GglError slf_upload_logs_to_cloud_watch(
    GglBuffer log_lines, SigV4Details sigv4_details, Config config
);

#endif
