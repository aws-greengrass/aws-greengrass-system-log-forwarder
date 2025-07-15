// aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
// logs to CloudWatch.
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#ifndef LOG_PROCESSOR_H
#define LOG_PROCESSOR_H

#include "system-log-forwarder.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/vector.h>
#include <stdint.h>

GglError slf_process_log(
    GglByteVec *upload_doc,
    GglBuffer timestamp_as_buffer,
    uint16_t *number_of_logs_added,
    const Config *config
);

GglError slf_upload_prefix_format(GglByteVec *upload_doc, const Config *config);

#endif
