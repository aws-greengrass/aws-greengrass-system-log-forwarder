// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "ring_buffer.h"
#include "system-log-forwarder.h"
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

typedef struct {
    uint64_t timestamp;
    uint16_t log_len;
    char log_line[] COUNTED_BY(log_len);
} LogEntry;

static size_t front = 0;
static size_t end = 0;
static atomic_size_t free_mem;
static char *backing_mem;
static bool initialized = false;
static int backing_fd = -1;

static size_t total_ring_buff_mem = (size_t) 1024 * 1024;

GglError slf_initialize_ringbuf_state(size_t ring_buffer_memory) {
    if (initialized) {
        return GGL_ERR_OK;
    }

    total_ring_buff_mem = ring_buffer_memory;

    // The return from sysconf is long so using this as intermediatory
    long page_size_long = sysconf(_SC_PAGESIZE);
    if (page_size_long <= 0) {
        GGL_LOGE("Failed to get system page size.");
        return GGL_ERR_FAILURE;
    }

    size_t page_size = (size_t) page_size_long;
    if (page_size <= offsetof(LogEntry, log_line) + MAX_LOG_LINE_LENGTH) {
        GGL_LOGE("Max log entry length cannot exceed system page size.");
        return GGL_ERR_INVALID;
    }

    if (total_ring_buff_mem % page_size != 0) {
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
        int ret = ftruncate(fd, (ssize_t) total_ring_buff_mem);
        if (ret != 0) {
            if (errno == EINTR) {
                GGL_LOGW("ftruncate interrupted. Retrying.");
                continue;
            }
            GGL_LOGE("ftruncate failed on memfd: %d.", errno);
            close(fd);
            return GGL_ERR_FAILURE;
        }

        break;
    }

    void *mmap_ret = mmap(
        NULL,
        total_ring_buff_mem + page_size,
        PROT_NONE,
        MAP_PRIVATE | MAP_ANONYMOUS,
        -1,
        0
    );
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    if (mmap_ret == MAP_FAILED) {
        GGL_LOGE("Failed to mmap backing memory space: %d.", errno);
        close(fd);
        return GGL_ERR_FAILURE;
    }

    backing_mem = mmap_ret;

    mmap_ret = mmap(
        backing_mem,
        total_ring_buff_mem,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED,
        fd,
        0
    );
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    if (mmap_ret == MAP_FAILED) {
        GGL_LOGE("Failed to mmap backing memory memfd: %d.", errno);
        munmap(backing_mem, total_ring_buff_mem + page_size);
        close(fd);
        return GGL_ERR_FAILURE;
    }

    mmap_ret = mmap(
        &backing_mem[total_ring_buff_mem],
        page_size,
        PROT_READ | PROT_WRITE,
        MAP_SHARED | MAP_FIXED,
        fd,
        0
    );
    // NOLINTNEXTLINE(performance-no-int-to-ptr)
    if (mmap_ret == MAP_FAILED) {
        GGL_LOGE("Failed to mmap wraparound page: %d.", errno);
        munmap(backing_mem, total_ring_buff_mem);
        munmap(backing_mem, total_ring_buff_mem + page_size);
        close(fd);
        return GGL_ERR_FAILURE;
    }

    backing_fd = fd;
    atomic_store_explicit(&free_mem, total_ring_buff_mem, memory_order_relaxed);
    initialized = true;

    return GGL_ERR_OK;
}

static size_t log_entry_len(size_t log_len) {
    size_t base_len = offsetof(LogEntry, log_line) + log_len;
    return (base_len + alignof(LogEntry) - 1) & ~(alignof(LogEntry) - 1);
}

GglError slf_log_store_add(GglBuffer log, uint64_t timestamp) {
    GglBuffer truncated = log;
    if (truncated.len > MAX_LOG_LINE_LENGTH) {
        truncated.len = MAX_LOG_LINE_LENGTH;
    }

    size_t required_len = log_entry_len(truncated.len);
    if (required_len > atomic_load_explicit(&free_mem, memory_order_acquire)) {
        GGL_LOGW("Dropping log; insufficient space in ring buffer.");
        return GGL_ERR_NOMEM;
    }

    assert(end % alignof(LogEntry) == 0);

    LogEntry *entry = (LogEntry *) &backing_mem[end];
    entry->log_len = (uint16_t) truncated.len;
    memcpy(entry->log_line, truncated.data, truncated.len);
    entry->timestamp = timestamp;

    end = (end + required_len) % total_ring_buff_mem;
    size_t prev_free = atomic_fetch_sub_explicit(
        &free_mem, required_len, memory_order_acq_rel
    );

    _Static_assert(
        MAX_LOG_LINE_LENGTH <= UINT16_MAX,
        "Max log entry length must be less than UINT16_MAX."
    );

    if (prev_free < total_ring_buff_mem / 2) {
        // TODO: Trigger upload thread to flush
    }

    return GGL_ERR_OK;
}

bool slf_log_store_get(GglBuffer *log, uint64_t *timestamp) {
    if (atomic_load_explicit(&free_mem, memory_order_acquire)
        == total_ring_buff_mem) {
        return false;
    }

    LogEntry *entry = (LogEntry *) &backing_mem[front];

    *log = (GglBuffer) { .data = (uint8_t *) entry->log_line,
                         .len = entry->log_len };
    *timestamp = entry->timestamp;
    return true;
}

void slf_log_store_remove(void) {
    LogEntry *entry = (LogEntry *) &backing_mem[front];
    size_t len = log_entry_len(entry->log_len);
    front = (front + len) % total_ring_buff_mem;
    atomic_fetch_add_explicit(&free_mem, len, memory_order_acq_rel);
}

void slf_cleanup_ringbuf_state(void) {
    if (backing_fd >= 0) {
        close(backing_fd);
        backing_fd = -1;
    }
    if (backing_mem != NULL) {
        long page_size_long = sysconf(_SC_PAGESIZE);
        if (page_size_long > 0) {
            size_t page_size = (size_t) page_size_long;
            munmap(backing_mem, total_ring_buff_mem + page_size);
        }
        backing_mem = NULL;
    }
    initialized = false;
}
