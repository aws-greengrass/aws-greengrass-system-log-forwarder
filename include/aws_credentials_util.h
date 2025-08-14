// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef AWS_CREDENTIALS_UTIL_H
#define AWS_CREDENTIALS_UTIL_H

#include "system-log-forwarder.h"
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>

typedef struct ContainerCredentialsInfo {
    GglBuffer uri;
    GglBuffer token;
} ContainerCredentialsInfo;

/// @brief Retrieves AWS credentials using the default credential provider
/// chain. This function attempts to obtain AWS credentials by checking various
/// sources in order: environment variables, container credentials, and instance
/// profile.
/// @param[out] sigv4_details Pointer to structure that will be populated with
/// the retrieved AWS credentials and service information
/// @param[in] alloc Arena allocator for memory management during credential
/// retrieval
/// @return GGL_ERR_OK on success, error code on failure
GglError get_credentials_chain_credentials(
    SigV4Details *sigv4_details, GglArena *alloc
);

#endif
