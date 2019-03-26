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
   * Linked list of parsed headers.
   */
  struct MHD_HTTP_Header *headers_received;

  /**
   * Tail of linked list of parsed headers.
   */
  struct MHD_HTTP_Header *headers_received_tail;

  /**
   * Response to transmit (initially NULL).
   */
  struct MHD_Response *response;

  /**
   * The memory pool is created when a stream is created and destroyed
   * at the end of each stream.
   * The pool is used for all stream-related data (except for the
   * response).
   */
  struct MemoryPool *pool;

  /**
   * We allow the main application to associate some pointer with the
   * HTTP request, which is passed to each #MHD_AccessHandlerCallback
   * and some other API calls.  Here is where we store it.  (MHD does
   * not know or care what it is).
   */
  void *client_context;

  /**
   * Request method.  Should be GET/POST/etc.
   */
  char *method;

  /**
   * Requested absolute path.
   */
  char *path;

  /**
   * Requested URL.
   */
  char *url;

  /**
   * Requested query in URL.
   */
  char *query;

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

  /**
   * Number of bytes we had in the HTTP header, set once we
   * pass #MHD_CONNECTION_HEADERS_RECEIVED.
   */
  size_t header_size;

  /**
   * Did we ever call the "default_handler" on this stream?  (this
   * flag will determine if we call the #MHD_OPTION_NOTIFY_COMPLETED
   * handler when the connection closes down).
   */
  bool client_aware;

  /**
   * HTTP response code.  Only valid if response object
   * is already set.
   */
  unsigned int response_code;

  /**
   * How many more bytes of the body do we expect
   * to read? #MHD_SIZE_UNKNOWN for unknown.
   */
  uint64_t remaining_upload_size;

  /**
   * Current write position in the actual response
   * (excluding headers, content only; should be 0
   * while sending headers).
   */
  uint64_t response_write_position;
};

struct h2_stream_t*
h2_stream_create (int32_t stream_id, size_t pool_size);

void
h2_stream_destroy (struct h2_stream_t *stream);

int
h2_stream_parse_cookie_header (struct MHD_Connection *connection,
                               struct h2_stream_t *stream,
                               const char *value, size_t valuelen);

#endif
