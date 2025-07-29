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

#define MAX_HEADER_BUFFER_SIZE (4096)
#define MAX_RESPONSE_BUFFER_SIZE (4096)

typedef struct {
    const char *host;
    const char *port;
    const char *path;
} HttpEndpoint;

typedef struct {
    int sockfd;
    SSL *ssl;
    SSL_CTX *ctx;
} TLSContext;

const char *slf_http_status_to_string(HTTPStatus_t status);

// Function to upload logs to CloudWatch
GglError slf_upload_logs_to_cloud_watch(
    GglBuffer log_lines, SigV4Details sigv4_details, Config config
);

#endif
