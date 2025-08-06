// aws-greengrass-lite - AWS IoT Greengrass runtime for constrained devices
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "slf_backoff.h"
#include "stdlib.h"
#include <assert.h>
#include <backoff_algorithm.h>
#include <fcntl.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/utils.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

static GglError get_random_value(uint32_t *rand_val) {
    int fd = open("/dev/urandom", O_RDONLY);
    if (fd == -1) {
        GGL_LOGE("Failed to open /dev/urandom.");
        return GGL_ERR_FAILURE;
    }
    ssize_t bytes_read = read(fd, rand_val, sizeof(*rand_val));
    close(fd);
    if (bytes_read != sizeof(*rand_val)) {
        GGL_LOGE("Failed to read from /dev/urandom.");
        return GGL_ERR_FAILURE;
    }
    return GGL_ERR_OK;
}

static GglError backoff_wrapper(
    uint32_t base_ms,
    uint32_t max_ms,
    uint32_t max_attempts,
    GglError (*fn)(void *ctx),
    void *ctx
) {
    if (fn == NULL) {
        assert(false);
        return GGL_ERR_UNSUPPORTED;
    }

    if (base_ms > UINT16_MAX) {
        assert(false);
        return GGL_ERR_UNSUPPORTED;
    }

    if (max_ms > UINT16_MAX) {
        assert(false);
        return GGL_ERR_UNSUPPORTED;
    }

    BackoffAlgorithmContext_t retry_params;
    BackoffAlgorithm_InitializeParams(
        &retry_params, (uint16_t) base_ms, (uint16_t) max_ms, max_attempts
    );

    BackoffAlgorithmStatus_t retry_status = BackoffAlgorithmSuccess;

    while (true) {
        GglError ret = fn(ctx);

        if (ret == GGL_ERR_OK) {
            return GGL_ERR_OK;
        }

        uint32_t rand_val = 0;
        GglError rand_err = get_random_value(&rand_val);
        if (rand_err != GGL_ERR_OK) {
            return rand_err;
        }

        uint16_t backoff_time = 0;
        retry_status = BackoffAlgorithm_GetNextBackoff(
            &retry_params, rand_val, &backoff_time
        );

        if (retry_status == BackoffAlgorithmRetriesExhausted) {
            GGL_LOGE("Fatal error: backoff algorithm exhausted.");
            return GGL_ERR_FATAL;
        }

        GglError sleep_err = ggl_sleep_ms(backoff_time);
        if (sleep_err != GGL_ERR_OK) {
            // TODO: call proper panic function
            GGL_LOGE("Fatal error: unexpected sleep error during backoff.");
            _Exit(1);
        }
    }
}

GglError slf_backoff(
    uint32_t base_ms,
    uint32_t max_ms,
    uint32_t max_attempts,
    GglError (*fn)(void *ctx),
    void *ctx
) {
    assert(max_attempts != BACKOFF_ALGORITHM_RETRY_FOREVER);
    return backoff_wrapper(base_ms, max_ms, max_attempts, fn, ctx);
}

void slf_backoff_indefinite(
    uint32_t base_ms, uint32_t max_ms, GglError (*fn)(void *ctx), void *ctx
) {
    GglError ret = backoff_wrapper(
        base_ms, max_ms, BACKOFF_ALGORITHM_RETRY_FOREVER, fn, ctx
    );
    // TODO: Perhaps should panic/log/etc.
    assert(ret == GGL_ERR_OK);
}
