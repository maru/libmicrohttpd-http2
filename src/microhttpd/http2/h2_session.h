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
   * Pointer to the MHD_Connection.
   */
  struct MHD_Connection *c;

  /**
   * HTTP/2 session.
   */
  nghttp2_session *session;

  /**
   * Identifier (for debugging purposes).
   */
  size_t session_id;

  /**
   * Session settings.
   */
  h2_settings_entry *settings;

  /**
   * Number of entries in settings.
   */
  size_t settings_len;

  /**
   * Dummy head of doubly linked list of current streams.
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
  size_t last_stream_id;

  /**
   * Data pending to write in the write_buffer.
   */
  const uint8_t *pending_write_data;

  /**
   * Length of data pending.
   */
  size_t pending_write_data_len;

  /**
   * Thread handle for this connection (if we are using
   * one thread per connection).
   */
  MHD_thread_handle_ID_ pid;
};

struct h2_stream_t *
h2_session_get_stream (struct h2_session_t *h2, uint32_t stream_id);

void
h2_session_add_stream (struct h2_session_t *h2, struct h2_stream_t *stream);

void
h2_session_remove_stream (struct h2_session_t *h2,
			  struct h2_stream_t *stream);

ssize_t
h2_session_read_data (struct h2_session_t *h2, const uint8_t * in,
		      size_t inlen);

ssize_t
h2_session_write_data (struct h2_session_t *h2, uint8_t * out, size_t outlen,
		       size_t * append_offset);

struct h2_session_t *h2_session_create (struct MHD_Connection *connection);

void h2_session_destroy (struct h2_session_t *h2);

int
h2_session_upgrade (struct h2_session_t *h2,
		    const char *settings, const char *method);

int
h2_session_create_stream (struct h2_session_t *h2, int32_t stream_id);

#endif
