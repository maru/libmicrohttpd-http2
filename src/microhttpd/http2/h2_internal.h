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

#include "http2/h2_session.h"
#include "http2/h2_stream.h"
#include "http2/h2_callbacks.h"

char* FRAME_TYPE (int type);
void print_flags (const nghttp2_frame_hd hd);

#if HTTP2_DEBUG

struct timeval h2_util_tm_start;

struct MHD_Daemon *daemon_;

#define COLOR_RED    "\033[31;1m"
#define COLOR_WHITE  "\033[0m"
#define COLOR_YELLOW "\033[33m"
#define PRINT_RECV "\033[1;36m"
#define do_color(code) (color ? code : "")
#define ENTER(format, args...) { \
  int color = isatty(fileno(stderr)); \
  struct timeval now; \
  gettimeofday(&now, NULL); \
  time_t usec = (now.tv_sec - h2_util_tm_start.tv_sec)*1000000 + (now.tv_usec - h2_util_tm_start.tv_usec); \
  time_t sec = usec/1000000; \
  time_t msec = (usec % 1000000)/1000; \
  fprintf(stderr, "%s[%3ld.%03ld]", do_color(COLOR_YELLOW), sec, msec); \
  fprintf(stderr, "%s ", do_color(COLOR_WHITE)); \
  fprintf(stderr, "%s[%s]", do_color(COLOR_RED), __FUNCTION__); \
  fprintf(stderr, "%s ", do_color(COLOR_WHITE)); \
  fprintf(stderr, format "\n", ##args); \
}
#endif /* HTTP2_DEBUG */

#endif
