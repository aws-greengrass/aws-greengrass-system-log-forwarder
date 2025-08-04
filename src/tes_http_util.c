// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "tes_http_util.h"
#include "cloud_request.h"
#include <assert.h>
#include <core_http_client.h>
#include <ggl/arena.h>
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/flags.h>
#include <ggl/json_decode.h>
#include <ggl/log.h>
#include <ggl/map.h>
#include <ggl/object.h>
#include <netdb.h>
#include <string.h>
#include <sys/socket.h>
#include <transport_interface.h>
#include <unistd.h>
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
    assert(ggl_buffer_eq(
        ggl_buffer_substr(uri, 0, strlen("http://")), GGL_STR("http://")
    ));

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
        GglBuffer host
            = ggl_buffer_substr(uri, strlen("http://"), colon_position + 1);
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

    GglBuffer host = ggl_buffer_substr(
        uri, strlen("http://"), path_separator_position + 1
    );
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

static int32_t transport_send(
    NetworkContext_t *network_context, const void *buffer, size_t bytes_to_send
) {
    int sockfd = *(int *) network_context;
    return (int32_t) send(sockfd, buffer, bytes_to_send, 0);
}

static int32_t transport_recv(
    NetworkContext_t *network_context, void *buffer, size_t bytes_to_recv
) {
    int sockfd = *(int *) network_context;
    return (int32_t) recv(sockfd, buffer, bytes_to_recv, 0);
}

static int create_connection(const HttpEndpoint *endpoint) {
    GGL_LOGI("Attempting to connect to %s:%s", endpoint->host, endpoint->port);
    struct addrinfo hints = { 0 };
    struct addrinfo *result;

    hints.ai_family = AF_INET;
    hints.ai_socktype = SOCK_STREAM;

    if (getaddrinfo(endpoint->host, endpoint->port, &hints, &result) != 0) {
        GGL_LOGE(
            "getaddrinfo failed for %s:%s", endpoint->host, endpoint->port
        );
        return -1;
    }

    int sockfd
        = socket(result->ai_family, result->ai_socktype, result->ai_protocol);
    if (sockfd < 0) {
        GGL_LOGE("socket creation failed");
        freeaddrinfo(result);
        return -1;
    }

    if (connect(sockfd, result->ai_addr, result->ai_addrlen) < 0) {
        GGL_LOGE("connect failed to %s:%s", endpoint->host, endpoint->port);
        close(sockfd);
        freeaddrinfo(result);
        return -1;
    }
    GGL_LOGI("Successfully connected to %s:%s", endpoint->host, endpoint->port);
    freeaddrinfo(result);
    return sockfd;
}

static GglError parse_credentials_from_response(
    SigV4Details *credentials, GglBuffer response_body, GglArena *alloc
) {
    GGL_LOGT("Parsing credentials from response body");

    GglObject body_obj;
    GglError ret = ggl_json_decode_destructive(response_body, alloc, &body_obj);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to parse HTTP response body.");
        return ret;
    }

    if (ggl_obj_type(body_obj) != GGL_TYPE_MAP) {
        GGL_LOGE("JSON response is not an object.");
        return GGL_ERR_PARSE;
    }

    GglObject *aws_access_key_id = NULL;
    GglObject *aws_secret_access_key = NULL;
    GglObject *aws_session_token = NULL;

    ret = ggl_map_validate(
        ggl_obj_into_map(body_obj),
        GGL_MAP_SCHEMA(
            { GGL_STR("AccessKeyId"),
              GGL_REQUIRED,
              GGL_TYPE_BUF,
              &aws_access_key_id },
            { GGL_STR("SecretAccessKey"),
              GGL_REQUIRED,
              GGL_TYPE_BUF,
              &aws_secret_access_key },
            { GGL_STR("Token"),
              GGL_REQUIRED,
              GGL_TYPE_BUF,
              &aws_session_token },
        )
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to validate keys from HTTP response body.");
        return ret;
    }

    credentials->access_key_id = ggl_obj_into_buf(*aws_access_key_id);
    credentials->secret_access_key = ggl_obj_into_buf(*aws_secret_access_key);
    credentials->session_token = ggl_obj_into_buf(*aws_session_token);

    GGL_LOGD("Finished parsing credentials from response body");
    return GGL_ERR_OK;
}

static GglError make_cred_call(
    HttpEndpoint *uri_details,
    GglBuffer token,
    SigV4Details *response_credentials,
    GglArena *alloc
) {
    GGL_LOGT("Creating TLS connection");
    int sockfd = create_connection(uri_details);
    if (sockfd < 0) {
        GGL_LOGE("Failed to create connection");
        return GGL_ERR_FAILURE;
    }

    TransportInterface_t transport
        = { .send = transport_send,
            .recv = transport_recv,
            .pNetworkContext = (NetworkContext_t *) &sockfd };

    HTTPRequestInfo_t request_info = { .pMethod = HTTP_METHOD_GET,
                                       .methodLen = sizeof(HTTP_METHOD_GET) - 1,
                                       .pPath = uri_details->path,
                                       .pathLen = strlen(uri_details->path),
                                       .pHost = uri_details->host,
                                       .hostLen = strlen(uri_details->host) };

    char header_buffer[MAX_HEADER_BUFFER_SIZE];
    HTTPRequestHeaders_t request_headers
        = { .pBuffer = (uint8_t *) header_buffer,
            .bufferLen = sizeof(header_buffer) };

    /* Initialize HTTP headers */
    GGL_LOGT("Initializing HTTP headers");
    HTTPStatus_t http_error
        = HTTPClient_InitializeRequestHeaders(&request_headers, &request_info);
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Failed to initialize header, coreHTTP error code: %d (%s)",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close(sockfd);
        return GGL_ERR_FAILURE;
    }
    GGL_LOGT(
        "After init the request header length is %zu",
        request_headers.headersLen
    );

    http_error = HTTPClient_AddHeader(
        &request_headers,
        "Authorization",
        strlen("Authorization"),
        (char *) token.data,
        token.len
    );
    if (http_error != HTTPSuccess) {
        GGL_LOGE(
            "Error adding header. coreHTTP error code: %d (%s).",
            http_error,
            slf_http_status_to_string(http_error)
        );
        close(sockfd);
        return GGL_ERR_FATAL;
    }

    uint8_t response_buffer[MAX_RESPONSE_BUFFER_SIZE];
    HTTPResponse_t response
        = { .pBuffer = response_buffer, .bufferLen = sizeof(response_buffer) };

    GGL_LOGT(
        "Request headers: %.*s",
        (int) request_headers.headersLen,
        (char *) request_headers.pBuffer
    );

    HTTPStatus_t status
        = HTTPClient_Send(&transport, &request_headers, NULL, 0, &response, 0);

    GGL_LOGI(
        "HTTP Status: %d (%s), Response Code: %u",
        status,
        slf_http_status_to_string(status),
        response.statusCode
    );

    close(sockfd);
    if (status != HTTPSuccess) {
        GGL_LOGE(
            "HTTP request failed with status: %d (%s)",
            status,
            slf_http_status_to_string(status)
        );
        return GGL_ERR_FAILURE;
    }
    if (response.statusCode != 200) {
        GGL_LOGE("HTTP response code not 200: %u", response.statusCode);
        return GGL_ERR_FAILURE;
    }

    if (response.pBody && response.bodyLen > 0) {
        GGL_LOGD("HTTP response body received.");

        // Copy response body into arena for in-place processing
        uint8_t *arena_body
            = GGL_ARENA_ALLOCN(alloc, uint8_t, response.bodyLen);
        if (arena_body == NULL) {
            GGL_LOGE("Failed to allocate arena memory for response body.");
            return GGL_ERR_NOMEM;
        }
        memcpy(arena_body, response.pBody, response.bodyLen);

        GglBuffer response_body
            = { .data = arena_body, .len = response.bodyLen };
        GglError ret = parse_credentials_from_response(
            response_credentials, response_body, alloc
        );
        if (ret != GGL_ERR_OK) {
            GGL_LOGE("Failed to parse credentials from response body.");
            return ret;
        }
        GGL_LOGD("Successfully parsed credentials from response body.");
        return GGL_ERR_OK;
    }
    // If it gets this far, then there was no body to parse.
    return GGL_ERR_PARSE;
}

GglError ecs_http_get_credentials(
    GglBuffer uri,
    GglBuffer token,
    SigV4Details *response_credentials,
    GglArena *alloc
) {
    GGL_LOGT(
        "Making HTTP GET request to credentials endpoint: %.*s",
        (int) uri.len,
        uri.data
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

    ret = make_cred_call(&uri_details, token, response_credentials, alloc);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Failed to retrieve credentials over HTTP to the container "
                 "credentials endpoint.");
        return ret;
    }
    return GGL_ERR_OK;
}
