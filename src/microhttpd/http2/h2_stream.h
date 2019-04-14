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
 * @file microhttpd/http2/h2_stream.h
 * @brief Methods for managing HTTP/2 connections
 * @author Maru Berezin
 */

#ifndef H2_STREAM_H
#define H2_STREAM_H

/**
 * HTTP/2 stream.
 */
struct h2_stream_t
{
  /**
   * Due to current design of MHD, each stream needs a MHD_Connection for itself.
   */
  struct MHD_Connection c;

  /**
   * Next stream in the streams list.
   */
  struct h2_stream_t *next;

  /**
   * Previous stream in the streams list.
   */
  struct h2_stream_t *prev;

  /**
   * Identifier.
   */
  size_t stream_id;

  /**
   * Scheme (e.g., http).
   * https://tools.ietf.org/html/rfc3986#section-3.1
   */
  char *scheme;

  /**
   * Authority (e.g., host).
   * https://tools.ietf.org/html/rfc3986#section-3.2
   */
  char *authority;
};

struct h2_stream_t*
h2_stream_create (int32_t stream_id, struct MHD_Connection *connection);

void
h2_stream_destroy (struct h2_stream_t *stream);

int
h2_stream_add_recv_header (struct h2_stream_t *stream,
                           const uint8_t *name, const size_t namelen,
                           const uint8_t *value, const size_t valuelen);

int
h2_stream_call_connection_handler (struct h2_stream_t *stream,
                                   char *upload_data, size_t *upload_data_size);

#endif
