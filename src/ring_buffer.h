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

// initialize the ring buffer
GglError slf_initialize_ringbuf_state(size_t ring_buffer_memory);

// Add a log entry from the producer thread
GglError slf_log_store_add(GglBuffer log, uint64_t timestamp);

// Get the first log entry from the consumer thread.
// Returns false if queue is empty.
// If returns true, must call log_store_remove after done with the entry.
bool slf_log_store_get(GglBuffer *log, uint64_t *timestamp);

// Remove the first log entry from the consumer thread.
// log_store_get must be called first. There must be only one call to
// log_store_remove per call to log_store_get.
void slf_log_store_remove(void);

#endif
