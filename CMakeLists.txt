# aws-greengrass-system-log-forwarder - AWS Greengrass component for forwarding
# logs to CloudWatch.
# Copyright Amazon.com, Inc. or its affiliates. All Rights Reserved.
# SPDX-License-Identifier: Apache-2.0

cmake_minimum_required(VERSION 3.22)
project(aws-greengrass-system-log-forwarder C)

option(ENABLE_WERROR "Compile warnings as errors")
set(MAX_UPLOAD_SIZE
    CACHE STRING "Maximum size in bytes for CloudWatch log upload payload")

set(CMAKE_EXPORT_COMPILE_COMMANDS ON)

include(GNUInstallDirs)

# Put outputs in build/bin and build/lib
set(CMAKE_RUNTIME_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_BINDIR}")
set(CMAKE_LIBRARY_OUTPUT_DIRECTORY
    "${CMAKE_BINARY_DIR}/${CMAKE_INSTALL_LIBDIR}")

if(NOT CMAKE_BUILD_TYPE AND NOT CMAKE_CONFIGURATION_TYPES)
  message(WARNING "CMAKE_BUILD_TYPE not set, using MinSizeRel.")
  set(CMAKE_BUILD_TYPE MinSizeRel)
endif()

# Enable a compiler option for compile and link
macro(add_cflags)
  add_compile_options(${ARGN})
  add_link_options(${ARGN})
endmacro()

include(CheckCCompilerFlag)
include(CheckLinkerFlag)

# Enable a compiler/linker option if supported with a condition
macro(try_add_cflag_if name cond option)
  check_c_compiler_flag("${option}" compiler_has_${name})
  if(compiler_has_${name})
    add_cflags("$<${cond}:${option}>")
  endif()
endmacro()

# Enable a compiler/linker option if supported
macro(try_add_cflag name option)
  try_add_cflag_if(${name} 1 ${option})
endmacro()

# Enable a linker option if supported with a condition
macro(try_add_link_option_if name cond option)
  check_linker_flag(C "${option}" linker_has_${name})
  if(linker_has_${name})
    add_link_options("$<${cond}:${option}>")
  endif()
endmacro()

# Enable a linker option if supported
macro(try_add_link_option name option)
  try_add_link_option_if(${name} 1 ${option})
endmacro()

# Clear CMake defaults
set(CMAKE_C_FLAGS_DEBUG "")
set(CMAKE_C_FLAGS_RELEASE "")
set(CMAKE_C_FLAGS_RELWITHDEBINFO "")
set(CMAKE_C_FLAGS_MINSIZEREL "")

set(CMAKE_COLOR_DIAGNOSTICS ON)

add_cflags($<$<CONFIG:Debug>:-O0>)
add_cflags($<$<CONFIG:Release,RelWithDebInfo>:-O3>)
try_add_cflag_if(Oz $<CONFIG:MinSizeRel> -Oz)
if(NOT compiler_has_Oz)
  add_cflags($<$<CONFIG:MinSizeRel>:-Os>)
endif()

add_cflags($<$<CONFIG:Debug,RelWithDebInfo>:-ggdb3>)

add_cflags($<$<NOT:$<CONFIG:Debug>>:-fPIE>)

# These flags are required
add_cflags(-pthread -fno-strict-aliasing)

# Following flags are optional
add_cflags(-std=gnu11 -fvisibility=hidden -fno-semantic-interposition
           -fno-common)

# This stops GCC from generating unstrippable inline DWARF debug info
add_cflags(-fno-unwind-tables -fno-asynchronous-unwind-tables)

try_add_cflag(strict-flex-arrays -fstrict-flex-arrays=3)

try_add_cflag(macro-prefix-map "-fmacro-prefix-map=${CMAKE_CURRENT_LIST_DIR}/=")

add_cflags($<$<CONFIG:Debug>:-fno-omit-frame-pointer>)
try_add_cflag_if(trivial-auto-var-init-pattern $<CONFIG:Debug>
                 -ftrivial-auto-var-init=pattern)

try_add_cflag_if(function-sections $<NOT:$<CONFIG:Debug>> -ffunction-sections)
try_add_cflag_if(data-sections $<NOT:$<CONFIG:Debug>> -fdata-sections)

if(ENABLE_WERROR)
  add_cflags(-Werror)
endif()

add_cflags(
  -Wall
  -Wextra
  -Wwrite-strings
  -Wno-missing-braces
  -Wvla
  -Wshadow
  -Wformat
  -Wformat=2
  -Wmissing-prototypes
  -Wstrict-prototypes
  -Wold-style-definition
  -Wunused
  -Wundef
  -Wconversion
  -Wsign-conversion
  -Wimplicit-fallthrough
  -Wredundant-decls
  -Wdate-time
  -Wstack-protector)

try_add_cflag(Wenum-int-mismatch -Wenum-int-mismatch)
try_add_cflag(Wtrampolines -Wtrampolines)
try_add_cflag(Wbidi-chars -Wbidi-chars=any,ucn)

add_cflags(-Werror=format-security -Werror=implicit
           -Werror=incompatible-pointer-types -Werror=int-conversion)

add_compile_definitions(_GNU_SOURCE)
add_compile_definitions($<$<NOT:$<CONFIG:Debug>>:_FORTIFY_SOURCE=3>)

add_link_options($<$<NOT:$<CONFIG:Debug>>:-pie>)

add_link_options(
  LINKER:-z,relro,-z,now,-z,noexecstack,-z,nodlopen LINKER:--as-needed
  LINKER:--no-copy-dt-needed-entries LINKER:--enable-new-dtags,--hash-style=gnu)
try_add_link_option(compress-debug-sections-zlib
                    LINKER:--compress-debug-sections=zlib)

try_add_link_option_if(gc-sections $<NOT:$<CONFIG:Debug>> LINKER:--gc-sections)

try_add_link_option_if(strip-all $<CONFIG:Release,MinSizeRel> LINKER:-s)

set(CMAKE_INTERPROCEDURAL_OPTIMIZATION_DEBUG FALSE)
set(CMAKE_INTERPROCEDURAL_OPTIMIZATION TRUE)

set(CMAKE_BUILD_WITH_INSTALL_RPATH TRUE)
set(CMAKE_INSTALL_RPATH "\$ORIGIN/../${CMAKE_INSTALL_LIBDIR}")

set(ENV{SOURCE_DATE_EPOCH} "0")
set(ENV{ZERO_AR_DATE} "1")

#
# FetchContent deps
#

set(FETCHCONTENT_QUIET FALSE)
include(FetchContent)

file(READ fc_deps.json FC_DEPS_JSON)
string(JSON FC_DEPS_COUNT LENGTH "${FC_DEPS_JSON}")
math(EXPR FC_DEPS_INDEX_MAX "${FC_DEPS_COUNT} - 1")

foreach(index RANGE ${FC_DEPS_INDEX_MAX})
  string(JSON dep_name MEMBER "${FC_DEPS_JSON}" ${index})
  string(JSON dep_url GET "${FC_DEPS_JSON}" "${dep_name}" url)
  string(JSON dep_rev GET "${FC_DEPS_JSON}" "${dep_name}" rev)
  fetchcontent_declare(
    "${dep_name}"
    GIT_REPOSITORY "${dep_url}"
    GIT_TAG "${dep_rev}")
  fetchcontent_makeavailable(${dep_name})
endforeach()

#
# System deps
#
find_package(PkgConfig REQUIRED)

pkg_search_module(openssl REQUIRED IMPORTED_TARGET openssl)
pkg_search_module(libsystemd REQUIRED IMPORTED_TARGET libsystemd)

include(CheckCSourceCompiles)

check_c_source_compiles(
  "
  #include <argp.h>
  int main(void) { argp_parse(0, 0, 0, 0, 0, 0); }
  "
  has_argp)

#
# Add Dependencies
#

# Add ggl-sdk
target_include_directories(ggl-sdk INTERFACE ${ggl_sdk_SOURCE_DIR}/priv_include)

# Add coreHTTP
include("${core_http_SOURCE_DIR}/httpFilePaths.cmake")
add_library(coreHTTP ${HTTP_SOURCES})
# Supress warning coming coreHTTP
target_compile_options(
  coreHTTP
  PRIVATE -Wno-sign-conversion
          -Wno-conversion
          -Wno-unused-parameter
          -Wno-missing-prototypes
          -Wno-redundant-decls
          -Wno-undef
          -Wno-implicit-fallthrough)
# Add all directories to include paths
target_include_directories(coreHTTP PUBLIC ${HTTP_INCLUDE_PUBLIC_DIRS})
target_include_directories(coreHTTP PUBLIC dep_modules/coreHTTP/)
target_link_libraries(coreHTTP PUBLIC ggl-sdk)

# Add sigV4
include("${aws_sigv4_SOURCE_DIR}/sigv4FilePaths.cmake")
add_library(aws_sigv4 ${SIGV4_SOURCES})
target_include_directories(aws_sigv4 PUBLIC ${SIGV4_INCLUDE_PUBLIC_DIRS})
target_include_directories(aws_sigv4 PUBLIC dep_modules/aws-sigv4/)

# Add backoff_algorithm
include("${backoff_algorithm_SOURCE_DIR}/backoffAlgorithmFilePaths.cmake")
add_library(backoff_algorithm ${BACKOFF_ALGORITHM_SOURCES})
target_include_directories(backoff_algorithm
                           PUBLIC ${BACKOFF_ALGORITHM_INCLUDE_PUBLIC_DIRS})

#
# Build Executable
#

file(GLOB_RECURSE SRCS CONFIGURE_DEPENDS "src/*.c")
list(LENGTH SRCS SRCS_LEN)

foreach(src ${SRCS})
  set_property(
    SOURCE ${src}
    APPEND_STRING
    PROPERTY COMPILE_FLAGS "-frandom-seed=${src}")
endforeach()

add_executable(system-log-forwarder ${SRCS})

target_compile_definitions(system-log-forwarder
                           PRIVATE "GGL_MODULE=(\"system-log-forwarder\")")

if(MAX_UPLOAD_SIZE)
  target_compile_definitions(system-log-forwarder
                             PRIVATE "MAX_UPLOAD_SIZE=${MAX_UPLOAD_SIZE}")
endif()

target_include_directories(system-log-forwarder PRIVATE include)

target_link_libraries(
  system-log-forwarder PRIVATE ggl-sdk coreHTTP aws_sigv4 backoff_algorithm
                               PkgConfig::openssl PkgConfig::libsystemd)

if(NOT has_argp)
  target_link_libraries(system-log-forwarder PRIVATE argp)
endif()

install(TARGETS system-log-forwarder)
