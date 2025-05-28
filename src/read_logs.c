// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
//
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "cloud_logger.h"
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/object.h>
#include <string.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>

GglError read_log(FILE *fp, GglBuffer *filling, GglArena *alloc) {
    time_t start;
    time_t now;
    double time_diff;

    // Get the start time
    time(&start);

    // Read the output line by line
    while (1) { // log_store_get(buffer, timestamp)
        time(&now);
        // Calculate the time difference in seconds
        time_diff = difftime(now, start);
        if (time_diff > 11.0) {
            break;
        }

        uint8_t *line = GGL_ARENA_ALLOCN(alloc, uint8_t, MAX_LINE_LENGTH);
        if (!line) {
            // This should never happen because the alloc memory is defined as
            // MAX_LINE_LENGTH * filling->capacity
            printf("Ran out of memory for allocation. Returning early to "
                   "swap memory buffers.");
            break;
        }

        if (fgets((char *) line, (int) MAX_LINE_LENGTH, fp) == NULL) {
            continue;
        }

        GglBuffer value;
        value.data = line;
        value.len = strnlen((char *) line, MAX_LINE_LENGTH);

        (void) value;
        // log_store_add(value, timestamp)
        (void) filling;
    }

    // TODO:: clean the resource when terminating
    // if (pclose(fp) == -1) {
    //     perror("pclose failed");
    //     return 1;
    // }

    return GGL_ERR_OK;
}
