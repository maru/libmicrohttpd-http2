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
 * @file microhttpd/http2/h2.h
 * @brief Methods for managing HTTP/2 connections
 * @author Maru Berezin
 */

#ifndef H2_H
#define H2_H

#include "microhttpd_http2.h"
#include "internal.h"
#include "http2/h2_config.h"
#include "http2/h2_connection.h"
#include "http2/h2_upgrade.h"

#ifdef HTTP2_SUPPORT

#define HTTP2_DEBUG DEBUG_STATES

#define MHD_HTTP_VERSION_2_0 "HTTP/2"

#define ALPN_HTTP_2_0_LENGTH  NGHTTP2_PROTO_VERSION_ID_LEN
#define ALPN_HTTP_2_0         NGHTTP2_PROTO_VERSION_ID

struct h2_session_t;

#endif /* HTTP2_SUPPORT */

#endif
