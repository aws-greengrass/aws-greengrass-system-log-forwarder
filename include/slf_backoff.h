// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef SLF_BACKOFF_H
#define SLF_BACKOFF_H

// backoff util

#include <ggl/error.h>
#include <stdint.h>

GglError slf_backoff(
    uint32_t base_ms,
    uint32_t max_ms,
    uint32_t max_attempts,
    GglError (*fn)(void *ctx),
    void *ctx
);

void slf_backoff_indefinite(
    uint32_t base_ms, uint32_t max_ms, GglError (*fn)(void *ctx), void *ctx
);

#endif
