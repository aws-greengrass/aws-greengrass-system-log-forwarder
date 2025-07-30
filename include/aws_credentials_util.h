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

GglError get_credentials_chain_credentials(
    SigV4Details *sigv4_details, GglArena *alloc
);

#endif
