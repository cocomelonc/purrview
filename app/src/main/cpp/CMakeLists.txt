cmake_minimum_required(VERSION 3.22.1)
project(purrview C)
set(WEBP_BUILD_ANIM_UTILS OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_CWEBP OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_DWEBP OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_GIF2WEBP OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_IMG2WEBP OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_VWEBP OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_WEBPINFO OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_LIBWEBPMUX OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_WEBPMUX OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_EXTRAS OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_TESTS OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_FUZZTEST OFF CACHE BOOL "" FORCE)
set(WEBP_BUILD_WEBP_JS OFF CACHE BOOL "" FORCE)

add_subdirectory(third_party/libwebp-1.3.1 EXCLUDE_FROM_ALL)

# Keep the old JPEG reader in a separate lab target.  This is the PPM/PGM
# input path from libjpeg-turbo 2.0.4 (CVE-2020-13790), not the platform JPEG
# decoder.  Only the static library is linked into our native worker, and the
# worker itself runs in a dedicated Android process.
set(ENABLE_SHARED OFF CACHE BOOL "" FORCE)
set(ENABLE_STATIC ON CACHE BOOL "" FORCE)
set(WITH_TURBOJPEG OFF CACHE BOOL "" FORCE)
set(WITH_SIMD OFF CACHE BOOL "" FORCE)
set(WITH_ARITH_ENC OFF CACHE BOOL "" FORCE)
set(WITH_ARITH_DEC OFF CACHE BOOL "" FORCE)
set(WITH_MEM_SRCDST OFF CACHE BOOL "" FORCE)
set(CMAKE_INSTALL_DOCDIR share/doc/libjpeg-turbo CACHE PATH "" FORCE)
set(CMAKE_INSTALL_MANDIR share/man CACHE PATH "" FORCE)
add_subdirectory(third_party/libjpeg-turbo-2.0.4 EXCLUDE_FROM_ALL)
target_sources(jpeg-static PRIVATE third_party/libjpeg-turbo-2.0.4/rdppm.c)
target_compile_definitions(jpeg-static PRIVATE PPM_SUPPORTED)
set_property(TARGET jpeg-static PROPERTY POSITION_INDEPENDENT_CODE ON)

add_library(purrview SHARED parser.c bridge.c png_jni.c sms_parser.c sms_jni.c webp_bridge.c webp_jni.c)
target_sources(purrview PRIVATE jpeg_jni.c jpeg_bridge.c)
target_compile_options(purrview PRIVATE -Wall -Wextra -Werror)
target_include_directories(purrview PRIVATE
    third_party/libwebp-1.3.1/src
    third_party/libjpeg-turbo-2.0.4
    ${CMAKE_CURRENT_BINARY_DIR}/third_party/libjpeg-turbo-2.0.4)
target_link_libraries(purrview webp jpeg-static z log dl)
