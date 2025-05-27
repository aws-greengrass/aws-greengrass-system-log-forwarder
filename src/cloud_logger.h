// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef CLOUD_LOGGER_H
#define CLOUD_LOGGER_H

#include <ggl/arena.h>
#include <ggl/error.h>
#include <stdio.h>

#define MAX_LINE_LENGTH (2048)
#define THING_NAME_MAX_LENGTH (128)
#define GGL_IPC_MAX_SVCUID_LEN (16)

GglError read_log(FILE *fp, GglBuffer *filling, GglArena *alloc);

#endif
