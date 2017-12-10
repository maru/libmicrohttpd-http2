/*
  This file is part of libmicrohttpd
  Copyright (C) 2007-2017 Daniel Pittman and Christian Grothoff
  Copyright (C) 2017 Maru Berezin

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
 * @file microhttpd/connection_http2.h
 * @brief Methods for managing HTTP/2 connections
 * @author maru (Maru Berezin)
 */

#ifndef HTTP2_H
#define HTTP2_H

#include "internal.h"

#ifdef HTTP2_SUPPORT
#ifdef USE_NGHTTP2
#include <nghttp2/nghttp2.h>
#endif /* USE_NGHTTP2 */

struct http2_conn {

};


/**
 * Initialize HTTP2 structures.
 *
 * @param connection connection to handle
 */
int
MHD_http2_session_init (struct MHD_Connection *connection);


/**
 * Set HTTP/2 read/idle/write callbacks for this connection.
 * Handle data from/to socket.
 *
 * @param connection connection to initialize
 */
void
MHD_set_http2_callbacks (struct MHD_Connection *connection);

#endif /* HTTP2_SUPPORT */

#endif
