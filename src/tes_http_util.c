// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "tes_http_util.h"
#include "cloud_request.h"
#include <assert.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <string.h>
#include <stdint.h>

#define DEFAULT_HTTP_PORT "80"
// Maximum path bound by uri length, subtracting 7 for http://, and adding 1 for
// null terminator and 1 for starting slash
#define URI_MEM_MAX (2048 - 5)

static GglError fix_path_structure(GglBuffer *path, GglArena *alloc) {
    uint8_t *mem = GGL_ARENA_ALLOCN(alloc, uint8_t, path->len + 2);
    if (mem == NULL) {
        GGL_LOGE("Failed to allocate memory for path buffer.");
        return GGL_ERR_NOMEM;
    }

    mem[0] = '/';
    memcpy(&mem[1], path->data, path->len);
    mem[path->len + 1] = '\0';

    path->data = mem;
    path->len = path->len + 1;

    return GGL_ERR_OK;
}

static GglError parse_container_credentials_uri(
    GglBuffer uri, GglArena *alloc, HttpEndpoint *details
) {
    assert(ggl_buffer_eq(ggl_buffer_substr(uri, 0, 8), GGL_STR("http://")));

    GGL_LOGT("Parsing the container credentials URI");
    GglError ret;

    size_t slashes_count = 0;
    size_t colon_count = 0;
    size_t path_separator_position = SIZE_MAX;
    size_t colon_position = SIZE_MAX;

    if (uri.len == 0) {
        GGL_LOGE("Container credentials URI length should not be zero.");
        return GGL_ERR_INVALID;
    }

    // Expecting either a http://host:port/path, or http://host/path format.
    for (size_t position = 0; position < uri.len; position++) {
        if (uri.data[position] == '/') {
            GGL_LOGT("Found slash while parsing container credentials URI.");
            slashes_count++;

            if (slashes_count == 3) {
                path_separator_position = position;
                uri.data[position] = '\0';
            }
        } else if (uri.data[position] == ':') {
            GGL_LOGT("Found colon while parsing container credentials URI.");
            colon_count++;
            if ((colon_count == 2) && (path_separator_position == SIZE_MAX)) {
                colon_position = position;
                uri.data[position] = '\0';
            }
        }
    }

    if (path_separator_position == SIZE_MAX) {
        GGL_LOGE("Incorrectly formatted URI does not have a path segment.");
        return GGL_ERR_INVALID;
    }

    if (colon_count > 0 && colon_position < path_separator_position) {
        GglBuffer host = ggl_buffer_substr(uri, 8, colon_position + 1);
        GglBuffer port = ggl_buffer_substr(
            uri, colon_position + 1, path_separator_position + 1
        );
        GglBuffer path
            = ggl_buffer_substr(uri, path_separator_position + 1, uri.len);

        details->host = (char *) host.data;
        details->port = (char *) port.data;

        ret = fix_path_structure(&path, alloc);
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("Error when manipulating path buffer.");
            return ret;
        }

        details->path = (char *) path.data;

        GGL_LOGD("Finished parsing container credentials URI and found port.");
        return GGL_ERR_OK;
    }

    GglBuffer host = ggl_buffer_substr(uri, 8, path_separator_position + 1);
    GglBuffer path
        = ggl_buffer_substr(uri, path_separator_position + 1, uri.len);

    details->host = (char *) host.data;
    details->port = DEFAULT_HTTP_PORT;

    ret = fix_path_structure(&path, alloc);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error when manipulating path buffer.");
        return ret;
    }

    details->path = (char *) path.data;

    GGL_LOGD("Finished parsing container credentials URI and using default "
             "port of " DEFAULT_HTTP_PORT);
    return GGL_ERR_OK;
}

GglError tes_http_get_credentials(
    GglBuffer uri,
    GglBuffer token,
    SigV4Details *response_credentials,
    GglArena *alloc
) {
    GGL_LOGT(
        "Making HTTP GET request to TES endpoint: %.*s", (int) uri.len, uri.data
    );

    HttpEndpoint uri_details = { 0 };

    uint8_t uri_mem[URI_MEM_MAX] = { 0 };
    GglArena uri_alloc = ggl_arena_init(GGL_BUF(uri_mem));

    GglError ret
        = parse_container_credentials_uri(uri, &uri_alloc, &uri_details);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to parse container credentials URI.");
        return ret;
    }

    // TODO: Make coreHTTP call to parsed URI
    (void) token;
    (void) response_credentials;
    (void) alloc;

    return GGL_ERR_UNSUPPORTED;
}
