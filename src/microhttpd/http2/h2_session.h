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
 * @file microhttpd/http2/h2_session.h
 * @brief Methods for managing HTTP/2 connections
 * @author Maru Berezin
 */

#ifndef H2_SESSION_H
#define H2_SESSION_H

/**
 * Session for an HTTP/2 connection.
 */
struct h2_session_t
{
  /**
   * HTTP/2 session.
   */
  nghttp2_session *session;

  /**
   * Identifier (for debugging purposes).
   */
  size_t session_id;

  /**
   * Pointer to connection.
   */
  struct MHD_Connection *connection;

  /**
   * Session settings.
   */
  h2_settings_entry *settings;

  /**
   * Number of entries in settings.
   */
  size_t settings_len;

  /**
   * Head of doubly linked list of current streams.
   */
  struct h2_stream_t *streams;

  /**
   * Tail of doubly linked list of current streams.
   */
  struct h2_stream_t *streams_tail;

  /**
   * Number of streams in a session.
   */
  size_t num_streams;

  /**
   * Current processing stream identifier.
   */
  size_t current_stream_id;

  /**
   * Highest remote stream identifier was handled.
   */
  size_t accepted_max;

  /**
   * Data pending to write in the write_buffer.
   */
  const uint8_t *data_pending; //?

  /**
   * Length of data pending.
   */
  size_t data_pending_len; //?
};

int
h2_fill_write_buffer (nghttp2_session *session, void *user_data);

int
h2_session_build_stream_headers (struct h2_session_t *h2,
                    struct h2_stream_t *stream, struct MHD_Response *response);

struct h2_session_t *
h2_session_create (struct MHD_Connection *connection);

void
h2_session_destroy (struct h2_session_t *h2);

#endif
