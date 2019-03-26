/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2017 Daniel Pittman and Christian Grothoff
  Copyright (C) 2018 Maru Berezin

  This library is free software; you can redistribute it and/or
  modify it under the terms of the GNU Lesser General Public
  License as published by the Free Software Foundation; either
  version 2.1 of the License, or (at your option) any later version.

  This library is distributed in the hope that it will be useful,
  but WITHOUT ANY WARRANTY; without even the implied warranty of
  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
  Lesser General Public License for more details.

  You should have received a copy of the GNU Lesser General Public
  License along with this library; if not, write to the Free Software
  Foundation, Inc., 51 Franklin Street, Fifth Floor, Boston, MA  02110-1301  USA

*/

/**
 * @file microhttpd/http2/h2_internal.h
 * @brief Methods for managing HTTP/2 connections
 * @author Maru Berezin
 */

#ifndef H2_INTERNAL_H
#define H2_INTERNAL_H

#include "microhttpd_http2.h"
#include "internal.h"
#include "http2/h2.h"
#include "http2/h2_session.h"
#include "http2/h2_stream.h"

#ifdef HTTP2_SUPPORT

void print_flags(const nghttp2_frame_hd hd);

#if HTTP2_DEBUG
struct timeval h2_util_tm_start;
#define ENTER_COLOR "31;1m"
#define do_color(code) (color ? code : "")
#define h2_debug_vprintf(format, args...) {if (HTTP2_DEBUG) {\
    int color = isatty(fileno(stderr));\
    struct timeval now; gettimeofday(&now, NULL);\
    long int milli = (now.tv_sec-h2_util_tm_start.tv_sec)*1000000+(now.tv_usec-h2_util_tm_start.tv_usec);\
    fprintf(stderr, "%s[%3ld.%03ld]%s ", do_color("\033[33m"), milli/1000000, (milli%1000000)/1000, do_color("\033[0m"));\
    fprintf(stderr, "%s[%s]%s " format "\n", do_color("\033["ENTER_COLOR), __FUNCTION__, do_color("\033[0m"), ##args);\
  }}
#endif /* HTTP2_DEBUG */

#endif /* HTTP2_SUPPORT */

#endif
