// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

//! Implements a single-producer, single-consumer ring buffer for log messages.
//! Exactly one thread may call log_store_add to add entries, and exactly one
//! thread may call log_store_get/log_store_remove to remove entries.

#ifndef RING_BUFFER_H
#define RING_BUFFER_H

#include <ggl/buffer.h>
#include <ggl/error.h>
#include <stdbool.h>
#include <stddef.h>
#include <stdint.h>

/// @brief Initializes the ring buffer state with specified memory allocation.
/// This function sets up the internal data structures for the single-producer,
/// single-consumer ring buffer used for log message storage.
/// @param[in] ring_buffer_memory Size in bytes of memory to allocate for the
/// ring buffer
/// @return GGL_ERR_OK on success, error code on failure
GglError slf_initialize_ringbuf_state(size_t ring_buffer_memory);

/// @brief Adds a log entry to the ring buffer from the producer thread.
/// This function stores a log message with its timestamp in the ring buffer.
/// Only one thread should call this function (single-producer constraint).
/// @param[in] log Buffer containing the log message to store
/// @param[in] timestamp Unix timestamp in milliseconds for the log entry
/// @return GGL_ERR_OK on success, error code on failure (e.g., buffer full)
GglError slf_log_store_add(GglBuffer log, uint64_t timestamp);

/// @brief Retrieves the first log entry from the ring buffer for the consumer
/// thread. This function provides access to the oldest log entry without
/// removing it. Only one thread should call this function (single-consumer
/// constraint).
/// @param[out] log Pointer to buffer that will receive the log message
/// @param[out] timestamp Pointer to variable that will receive the log
/// timestamp
/// @return true if a log entry was retrieved, false if the queue is empty
/// @note If this function returns true, slf_log_store_remove must be called
/// afterward
bool slf_log_store_get(GglBuffer *log, uint64_t *timestamp);

/// @brief Removes the first log entry from the ring buffer for the consumer
/// thread. This function must be called after slf_log_store_get to complete the
/// removal of a log entry from the buffer. Only one thread should call this
/// function.
/// @note slf_log_store_get must be called first, and there must be exactly one
/// call to this function per call to slf_log_store_get
void slf_log_store_remove(void);

#endif
