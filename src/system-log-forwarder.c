// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "system-log-forwarder.h"
#include "ggl/log.h"
#include "ggl/utils.h"
#include "ring_buffer.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/sdk.h>
#include <pthread.h>
#include <string.h>
#include <sys/types.h>
#include <time.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>

static void *consumer_thread(void *arg) {
    (void) arg;

    (void) ggl_sleep(10);

    while (1) {
        GglBuffer log;
        uint64_t timestamp;
        if (log_store_get(&log, &timestamp)) {
            if (log.len > 0) {
                GGL_LOGW("Consumer: %.*s", (int) log.len, log.data);
                log_store_remove();
                continue;
            }
        }
        (void) ggl_sleep_ms(1000);
    }
    return NULL;
}

static void *producer_thread(void *arg) {
    (void) arg;

    const char *cmd = "journalctl -f --no-pager";

    FILE *fp = popen(cmd, "r");
    if (fp == NULL) {
        GGL_LOGE("popen failed\n");
        return NULL;
    }

    char buffer[MAX_LINE_LENGTH] = { 0 };
    while (fgets(buffer, sizeof(buffer), fp) != NULL) {
        GGL_LOGI("Producer: %s", buffer);

        uint64_t timestamp = (uint64_t) time(NULL);
        GglBuffer log_buf
            = { .data = (uint8_t *) buffer, .len = strlen(buffer) };

        GglError ret = log_store_add(log_buf, timestamp);
        if (ret == GGL_ERR_NOMEM) {
            log_store_remove();
            ret = log_store_add(log_buf, timestamp);
            if (ret != GGL_ERR_OK) {
                GGL_LOGE("Failed to replace and add to the ring buffer.");
            }
            continue;
        }
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("Failed to add to the ring buffer. Sleeping for 10 seconds"
            );
            (void) ggl_sleep(10);
        }
    }

    return NULL;
}

int main(void) {
    ggl_sdk_init();

    pthread_t reader_tid;
    pthread_t consumer_tid;

    // Tell journalctl that fancy thing such as colour and paging aren't
    // required
    // NOLINTNEXTLINE(concurrency-mt-unsafe)
    setenv("TERM", "dumb", 1);

    pthread_create(&reader_tid, NULL, producer_thread, NULL);
    pthread_create(&consumer_tid, NULL, consumer_thread, NULL);

    pthread_join(reader_tid, NULL);
    pthread_join(consumer_tid, NULL);

    return 0;
}
