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

struct MHD_Daemon *daemon_;

#if HTTP2_DEBUG

enum {PRINT_SEND, PRINT_RECV};

#define COLOR_RED    "\033[1;31m"
#define COLOR_GREEN  "\033[0;32m"
#define COLOR_LGREEN "\033[1;32m"
#define COLOR_LBLUE  "\033[1;34m"
#define COLOR_MGNT   "\033[0;35m"
#define COLOR_WHITE  "\033[0m"
#define COLOR_YELLOW "\033[33m"
#define COLOR_SEND   "\033[1;35m"
#define COLOR_RECV   "\033[1;36m"

void set_timer ();

void set_color_output (bool f);

const char *
do_color(const char *code);

void
h2_debug_print_time ();

void
h2_debug_print_header (size_t session_id, size_t stream_id, const uint8_t *name, const uint8_t *value);

void
h2_debug_print_frame (size_t session_id, int action, const nghttp2_frame *frame);

#define ENTER(format, args...) { \
  h2_debug_print_time (); \
  fprintf(stderr, "%s[%s]%s ", do_color (COLOR_RED), __FUNCTION__, do_color (COLOR_WHITE)); \
  fprintf(stderr, format "\n", ##args); \
}
#endif /* HTTP2_DEBUG */

#endif
