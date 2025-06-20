/* aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
 * logs to CloudWatch.
 * Copyright Amazon.com, Inc. or its affiliates. All Rights
 * Reserved. SPDX-License-Identifier: Apache-2.0
 */

#ifndef CORE_HTTP_CONFIG_H
#define CORE_HTTP_CONFIG_H

#ifdef CORE_HTTP_SOURCE

// Define the module name for GGL logging
#define GGL_MODULE "coreHTTP"

#include "ggl/log.h"

#define GGL_HTTP_LOGUNPACK(...) __VA_ARGS__

#define LogDebug(body) GGL_LOGD(GGL_HTTP_LOGUNPACK body)
#define LogInfo(body) GGL_LOGI(GGL_HTTP_LOGUNPACK body)
#define LogWarn(body) GGL_LOGW(GGL_HTTP_LOGUNPACK body)
#define LogError(body) GGL_LOGE(GGL_HTTP_LOGUNPACK body)

#endif

#endif
