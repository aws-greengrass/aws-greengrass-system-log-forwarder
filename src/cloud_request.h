// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef CLOUD_REQUEST_H
#define CLOUD_REQUEST_H

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

#endif
