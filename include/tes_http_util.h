// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef TES_HTTP_UTIL_H
#define TES_HTTP_UTIL_H

#include "system-log-forwarder.h"
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>

GglError ecs_http_get_credentials(
    GglBuffer uri,
    GglBuffer token,
    SigV4Details *response_credentials,
    GglArena *alloc
);

#endif
