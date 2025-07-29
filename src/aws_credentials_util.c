// aws-greengrass-system-log-forwarder - System log uploader for AWS Greengrass
// Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
// SPDX-License-Identifier: Apache-2.0

#include "aws_credentials_util.h"
#include "system-log-forwarder.h"
#include "tes_http_util.h"
#include <ggl/buffer.h>
#include <ggl/error.h>
#include <ggl/log.h>
#include <ggl/vector.h>
#include <stdint.h>
#include <stdlib.h>

// Default ECS hostname from
// https://docs.aws.amazon.com/sdkref/latest/guide/feature-container-credentials.html
#define DEFAULT_ECS_HOSTNAME "http://169.254.170.2"

static GglError set_aws_region(SigV4Details *sigv4_details) {
    GGL_LOGT("Searching for AWS region in environment variables.");
    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *region_env = getenv("AWS_REGION");
    if ((region_env == NULL) || (region_env[0] == '\0')) {
        GGL_LOGE("No value read for environment variable AWS_REGION.");
        return GGL_ERR_NOENTRY;
    }
    GglBuffer region = ggl_buffer_from_null_term(region_env);
    GGL_LOGT(
        "Read AWS region from environment variables as %.*s",
        (int) region.len,
        region.data
    );

    sigv4_details->aws_region = region;
    return GGL_ERR_OK;
}

static GglError set_env_var_credentials(SigV4Details *sigv4_details) {
    GGL_LOGT("Attempting to find full AWS credentials in environment variables."
    );

    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *access_key_id_env = getenv("AWS_ACCESS_KEY_ID");
    if ((access_key_id_env == NULL) || (access_key_id_env[0] == '\0')) {
        GGL_LOGT("Did not find AWS_ACCESS_KEY_ID in environment variables.");
        return GGL_ERR_NOENTRY;
    }
    GGL_LOGT("Found AWS_ACCESS_KEY_ID in environment variables.");
    GglBuffer access_key_id = ggl_buffer_from_null_term(access_key_id_env);

    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *secret_access_key_env = getenv("AWS_SECRET_ACCESS_KEY");
    if ((secret_access_key_env == NULL) || (secret_access_key_env[0] == '\0')) {
        GGL_LOGT("Did not find AWS_SECRET_ACCESS_KEY in environment variables."
        );
        return GGL_ERR_NOENTRY;
    }
    GGL_LOGT("Found AWS_SECRET_ACCESS_KEY in environment variables.");
    GglBuffer secret_access_key
        = ggl_buffer_from_null_term(secret_access_key_env);

    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *session_token_env = getenv("AWS_SESSION_TOKEN");
    if ((session_token_env == NULL) || (session_token_env[0] == '\0')) {
        GGL_LOGT("Did not find AWS_SESSION_TOKEN in environment variables.");
        return GGL_ERR_NOENTRY;
    }
    GGL_LOGT("Found AWS_SESSION_TOKEN in environment variables.");
    GglBuffer session_token = ggl_buffer_from_null_term(session_token_env);

    sigv4_details->access_key_id = access_key_id;
    sigv4_details->secret_access_key = secret_access_key;
    sigv4_details->session_token = session_token;

    return GGL_ERR_OK;
}

static GglError get_ecs_provider_uri(GglByteVec *full_uri) {
    GGL_LOGT("Getting ECS credentials URI from environment.");
    GglError ret;

    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *rel_uri_env = getenv("AWS_CONTAINER_CREDENTIALS_RELATIVE_URI");
    if ((rel_uri_env == NULL) || (rel_uri_env[0] == '\0')) {
        GGL_LOGT("Did not find AWS_CONTAINER_CREDENTIALS_RELATIVE_URI in "
                 "environment variables.");
    } else {
        GGL_LOGT("Found AWS_CONTAINER_CREDENTIALS_RELATIVE_URI in environment "
                 "variables.");

        ret = ggl_byte_vec_append(full_uri, GGL_STR(DEFAULT_ECS_HOSTNAME));
        ggl_byte_vec_chain_append(
            &ret, full_uri, ggl_buffer_from_null_term(rel_uri_env)
        );
        if (ret != GGL_ERR_OK) {
            GGL_LOGE(
                "Error when appending ECS credentials URI from relative URI."
            );
            return ret;
        }

        GGL_LOGT(
            "Extrapolated full URI as %.*s from the relative URI environment "
            "variable",
            (int) full_uri->buf.len,
            full_uri->buf.data
        );
        return GGL_ERR_OK;
    }

    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *full_uri_env = getenv("AWS_CONTAINER_CREDENTIALS_FULL_URI");
    if ((full_uri_env == NULL) || (full_uri_env[0] == '\0')) {
        GGL_LOGT("Did not find AWS_CONTAINER_CREDENTIALS_FULL_URI in "
                 "environment variables.");
        return GGL_ERR_NOENTRY;
    }
    GGL_LOGT(
        "Found AWS_CONTAINER_CREDENTIALS_FULL_URI in environment variables."
    );
    GglBuffer full_uri_from_env_buf = ggl_buffer_from_null_term(full_uri_env);
    if (!ggl_buffer_eq(
            ggl_buffer_substr(full_uri_from_env_buf, 0, 8), GGL_STR("http://")
        )) {
        GGL_LOGE(
            "AWS_CONTAINER_CREDENTIALS_FULL_URI does not start with http://"
        );
        return GGL_ERR_INVALID;
    }

    ret = ggl_byte_vec_append(full_uri, full_uri_from_env_buf);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error when appending ECS credentials URI from full URI.");
        return ret;
    }
    GGL_LOGT(
        "Read full URI from environment variable as %.*s",
        (int) full_uri->buf.len,
        full_uri->buf.data
    );
    return GGL_ERR_OK;
}

static GglError get_ecs_provider_token(GglBuffer *token) {
    GGL_LOGT("Getting ECS credentials provider token from environment variables"
    );

    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *token_file_env = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE");
    if ((token_file_env == NULL) || (token_file_env[0] == '\0')) {
        GGL_LOGT("Did not find AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE in "
                 "environment variables.");
    } else {
        GGL_LOGT("Found AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE in environment "
                 "variables.");
        // TODO: Support for AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE variable. GG
        // does not use this.
        GGL_LOGW("AWS_CONTAINER_AUTHORIZATION_TOKEN_FILE is not yet supported. "
                 "Failing credentials lookup.");
        return GGL_ERR_UNSUPPORTED;
    }

    // NOLINTNEXTLINE(concurrency-mt-unsafe) safe on glibc; not calling setenv
    char *token_env = getenv("AWS_CONTAINER_AUTHORIZATION_TOKEN");
    if ((token_env == NULL) || (token_env[0] == '\0')) {
        GGL_LOGT("Did not find AWS_CONTAINER_AUTHORIZATION_TOKEN in "
                 "environment variables.");
        return GGL_ERR_NOENTRY;
    }
    GGL_LOGT("Found AWS_CONTAINER_AUTHORIZATION_TOKEN in environment variables."
    );
    *token = ggl_buffer_from_null_term(token_env);
    return GGL_ERR_OK;
}

static GglError get_ecs_provider_info(ContainerCredentialsInfo *cred_info) {
    GGL_LOGT(
        "Getting ECS credentials provider variables from environment variables."
    );

    static uint8_t ecs_uri_arr[2048] = { 0 };
    GglByteVec ecs_uri_vec = GGL_BYTE_VEC(ecs_uri_arr);
    GglError ret = get_ecs_provider_uri(&ecs_uri_vec);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error when getting ECS provider URI.");
        return ret;
    }
    cred_info->uri = ecs_uri_vec.buf;

    GglBuffer ecs_token = { 0 };
    ret = get_ecs_provider_token(&ecs_token);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error when getting ECS provider token.");
        return ret;
    }
    cred_info->token = ecs_token;

    return GGL_ERR_OK;
}

static GglError set_credentials_from_ecs_provider(
    SigV4Details *sigv4_details, GglArena *alloc
) {
    ContainerCredentialsInfo cred_info = { 0 };
    GglError ret = get_ecs_provider_info(&cred_info);
    if (ret != GGL_ERR_OK) {
        return ret;
    }

    ret = tes_http_get_credentials(
        cred_info.uri, cred_info.token, sigv4_details, alloc
    );
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error when getting ECS credentials over HTTP.");
        return ret;
    }

    return GGL_ERR_OK;
}

GglError get_credentials_chain_credentials(
    SigV4Details *sigv4_details, GglArena *alloc
) {
    GglError ret = set_aws_region(sigv4_details);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Error when getting AWS region.");
        return ret;
    }

    ret = set_env_var_credentials(sigv4_details);
    if (ret == GGL_ERR_NOENTRY) {
        GGL_LOGD("Did not find full AWS credentials in environment variables. "
                 "Moving onto next method in credentials chain.");
    } else if (ret != GGL_ERR_OK) {
        GGL_LOGW("Unknown error when getting full AWS credentials. Moving onto "
                 "next method in credentials chain.");
    } else {
        GGL_LOGI("Found full AWS credentials in environment variables.");
        return GGL_ERR_OK;
    }

    ret = set_credentials_from_ecs_provider(sigv4_details, alloc);
    if (ret != GGL_ERR_OK) {
        GGL_LOGE("Was not able to retrieve AWS credentials.");
        return ret;
    }

    GGL_LOGI("Retrieved AWS credentials from ECS credentials provider method.");

    return GGL_ERR_OK;
}
