// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ring_buffer.h"
#include <assert.h>
#include <errno.h>
#include <ggl/attr.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <string.h>
#include <sys/mman.h>
#include <sys/types.h>
#include <unistd.h>
#include <stdalign.h>
#include <stdatomic.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>
#include <stdlib.h>

typedef struct {
    uint64_t timestamp;
    uint16_t log_len;
    char log_line[] COUNTED_BY(log_len);
} LogEntry;

static size_t front = 0;
static size_t end = 0;
static atomic_size_t free_mem;
static char *backing_mem;

static const size_t TOTAL_MEM = (size_t) 1024 * 1024;
static const size_t MAX_LOG_LEN = 2048;

static GglError initialize_ringbuf_state(void) {
    size_t page_size = (size_t) sysconf(_SC_PAGESIZE);
    // TODO: sysconf error
    if (page_size <= offsetof(LogEntry, log_line) + MAX_LOG_LEN) {
        GGL_LOGE("Max log entry length cannot exceed system page size.");
        return GGL_ERR_INVALID;
    }

    if (TOTAL_MEM % page_size != 0) {
        GGL_LOGE("Ring buffer length is not a multiple of system page size.");
        return GGL_ERR_INVALID;
    }

    int fd = memfd_create("log_ring_buffer_mem", MFD_CLOEXEC);
    if (fd < 0) {
        GGL_LOGE("Failed to create memfd: %d.", errno);
        return GGL_ERR_FAILURE;
    }

    // Here ftruncate may enter a transient state so retry as needed
    while (1) {
        int ret = ftruncate(fd, (ssize_t) TOTAL_MEM);
        if (ret != 0) {
            if (errno == EINTR) {
                GGL_LOGW("ftruncate blocked with %d. Retrying..", errno);
                continue;
            }
            GGL_LOGE("ftruncate failed on memfd: %d.", errno);
            return GGL_ERR_FAILURE;
        }

        break;
    }

    void *mmap_ret = mmap(
        NULL,
        TOTAL_MEM + page_size,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    if (mmap_ret == MAP_FAILED) {
        GGL_LOGE("Failed to mmap backing memory space: %d.", errno);
        return GGL_ERR_FAILURE;
    }

    backing_mem = mmap_ret;

    mmap_ret = mmap(
        backing_mem,
        TOTAL_MEM,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED,
        fd,
        0
    );
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    if (mmap_ret == MAP_FAILED) {
        GGL_LOGE("Failed to mmap backing memory memfd: %d.", errno);
        return GGL_ERR_FAILURE;
    }

    mmap_ret = mmap(
        &backing_mem[TOTAL_MEM],
        page_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED,
        fd,
        0
    );
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    if (mmap_ret == MAP_FAILED) {
        GGL_LOGE("Failed to mmap wraparound page: %d.", errno);
        return GGL_ERR_FAILURE;
    }

    atomic_store_explicit(&free_mem, TOTAL_MEM, memory_order_relaxed);

    return GGL_ERR_OK;
}

__attribute__((constructor)) static void init_ring_buffer(void) {
    if (initialize_ringbuf_state() != GGL_ERR_OK) {
        _Exit(1);
    }
}

static size_t log_entry_len(size_t log_len) {
    size_t base_len = offsetof(LogEntry, log_line) + log_len;
    return (base_len + alignof(LogEntry) - 1) & ~(alignof(LogEntry) - 1);
}

GglError log_store_add(GglBuffer log, uint64_t timestamp) {
    GglBuffer truncated = log;
    if (truncated.len > MAX_LOG_LEN) {
        truncated.len = MAX_LOG_LEN;
    }

    size_t required_len = log_entry_len(truncated.len);
    if (required_len > atomic_load_explicit(&free_mem, memory_order_acquire)) {
        GGL_LOGW("Dropping log; insufficient space in ring buffer.");
        return GGL_ERR_NOMEM;
    }

    assert(end % alignof(LogEntry) == 0);

    LogEntry *entry = (LogEntry *) &backing_mem[end];
    entry->log_len = (uint16_t) truncated.len;
    memcpy(entry->log_line, log.data, log.len);
    entry->timestamp = timestamp;

    end = (end + required_len) % TOTAL_MEM;
    size_t prev_free = atomic_fetch_sub_explicit(
        &free_mem, required_len, memory_order_acq_rel
    );

    _Static_assert(
        MAX_LOG_LEN <= UINT16_MAX,
        "Max log entry length must be less than UINT16_MAX."
    );

    if (prev_free < TOTAL_MEM / 2) {
        // TODO: Trigger upload thread to flush
    }

    return GGL_ERR_OK;
}

bool log_store_get(GglBuffer *log, uint64_t *timestamp) {
    if (atomic_load_explicit(&free_mem, memory_order_acquire) == TOTAL_MEM) {
        return false;
    }

    LogEntry *entry = (LogEntry *) &backing_mem[front];

    *log = (GglBuffer) { .data = (uint8_t *) entry->log_line,
                         .len = entry->log_len };
    *timestamp = entry->timestamp;
    return true;
}

void log_store_remove(void) {
    LogEntry *entry = (LogEntry *) &backing_mem[front];
    size_t len = log_entry_len(entry->log_len);
    front = (front + len) % TOTAL_MEM;
    free_mem += len;
    atomic_fetch_add_explicit(&free_mem, len, memory_order_acq_rel);
}
