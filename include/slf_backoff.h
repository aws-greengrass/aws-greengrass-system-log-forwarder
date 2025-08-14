// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef SLF_BACKOFF_H
#define SLF_BACKOFF_H

// backoff util

#include <ggl/error.h>
#include <stdint.h>

/// @brief Executes a function with exponential backoff retry logic.
/// This function attempts to execute the provided function with exponential
/// backoff between retries, up to a maximum number of attempts.
/// @param[in] base_ms Base delay in milliseconds for the first retry
/// @param[in] max_ms Maximum delay in milliseconds between retries
/// @param[in] max_attempts Maximum number of retry attempts before giving up
/// @param[in] fn Function pointer to the operation to retry
/// @param[in] ctx Context pointer passed to the function being retried
/// @return GGL_ERR_OK if function succeeds within max_attempts, last error
/// code on failure
GglError slf_backoff(
    uint32_t base_ms,
    uint32_t max_ms,
    uint32_t max_attempts,
    GglError (*fn)(void *ctx),
    void *ctx
);

/// @brief Executes a function with exponential backoff retry logic
/// indefinitely. This function attempts to execute the provided function with
/// exponential backoff between retries, continuing indefinitely until success.
/// @param[in] base_ms Base delay in milliseconds for the first retry
/// @param[in] max_ms Maximum delay in milliseconds between retries
/// @param[in] fn Function pointer to the operation to retry
/// @param[in] ctx Context pointer passed to the function being retried
void slf_backoff_indefinite(
    uint32_t base_ms, uint32_t max_ms, GglError (*fn)(void *ctx), void *ctx
);

#endif
