// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef TES_HTTP_UTIL_H
#define TES_HTTP_UTIL_H

#include "system-log-forwarder.h"
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>

/// @brief Retrieves AWS credentials from ECS container credentials endpoint.
/// This function makes an HTTP request to the ECS container credentials
/// endpoint to obtain temporary AWS credentials for the running container.
/// @param[in] uri Buffer containing the credentials endpoint URI
/// @param[in] token Buffer containing the authorization token for the request
/// @param[out] response_credentials Pointer to structure that will be populated
/// with the retrieved AWS credentials
/// @param[in] alloc Arena allocator for memory management during the HTTP
/// request and response processing
/// @return GGL_ERR_OK on success, error code on failure
GglError ecs_http_get_credentials(
    GglBuffer uri,
    GglBuffer token,
    SigV4Details *response_credentials,
    GglArena *alloc
);

#endif
