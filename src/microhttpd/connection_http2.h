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

#define H2_HEADER_METHOD     ":method"
#define H2_HEADER_METHOD_LEN 7
#define H2_HEADER_SCHEME     ":scheme"
#define H2_HEADER_SCHEME_LEN 7
#define H2_HEADER_AUTH       ":authority"
#define H2_HEADER_AUTH_LEN   10
#define H2_HEADER_PATH       ":path"
#define H2_HEADER_PATH_LEN   5

/**
 * HTTP/2 stream.
 */
struct http2_stream
{

  /**
   * Next stream in the streams list.
   */
  struct http2_stream *next;

  /**
   * Previous stream in the streams list.
   */
  struct http2_stream *prev;

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
   * The memory pool is created whenever we first read from the TCP
   * stream and destroyed at the end of each request (and re-created
   * for the next request).  In the meantime, this pointer is NULL.
   * The pool is used for all connection-related data except for the
   * response (which maybe shared between connections) and the IP
   * address (which persists across individual requests).
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
   * Requested URL.
   */
  char *path;

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
   * Buffer for reading requests.  Allocated in pool.  Actually one
   * byte larger than @e read_buffer_size (if non-NULL) to allow for
   * 0-termination.
   */
  char *read_buffer;

  /**
   * Buffer for writing response (headers only).  Allocated
   * in pool.
   */
  char *write_buffer;

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
  unsigned int responseCode;

  /**
   * Are we receiving with chunked encoding?  This will be set to
   * #MHD_YES after we parse the headers and are processing the body
   * with chunks.  After we are done with the body and we are
   * processing the footers; once the footers are also done, this will
   * be set to #MHD_NO again (before the final call to the handler).
   */
  bool have_chunked_upload;

  /**
   * If we are receiving with chunked encoding, where are we right
   * now?  Set to 0 if we are waiting to receive the chunk size;
   * otherwise, this is the size of the current chunk.  A value of
   * zero is also used when we're at the end of the chunks.
   */
  uint64_t current_chunk_size;

  /**
   * If we are receiving with chunked encoding, where are we currently
   * with respect to the current chunk (at what offset / position)?
   */
  uint64_t current_chunk_offset;

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

/**
 * Session for an HTTP/2 connection.
 */
struct http2_conn
{
  /**
   * Pointer to connection.
   */
  nghttp2_session *session;

  /**
   * Identifier.
   */
  size_t session_id;

  /**
   * Pointer to connection.
   */
  struct MHD_Connection *connection;

  /**
   * Session settings.
   */
  nghttp2_settings_entry *settings;

  /**
   * Number of entries in settings.
   */
  size_t settings_len;

  /**
   * Head of doubly linked list of current, active streams.
   */
  struct http2_stream *streams;

  /**
   * Tail of doubly linked list of current, active streams.
   */
  struct http2_stream *streams_tail;

  /**
   * Number of streams in a session.
   */
  size_t num_streams;

  /**
   * Current processing stream identifier.
   */
  size_t current_stream_id;

};


/**
 * Initialize HTTP2 structures, set the initial local settings for the session,
 * and send server preface.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_session_start (struct MHD_Connection *connection);


/**
 * Read data from the connection.
 *
 * @param conn the connection struct
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_handle_read (struct MHD_Connection *connection);


/**
 * Write data to the connection.
 *
 * @param conn the connection struct
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_handle_write (struct MHD_Connection *connection);


/**
 * Process data.
 *
 * @param conn the connection struct
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_handle_idle (struct MHD_Connection *connection);


/**
 * Delete HTTP2 structures.
 *
 * @param connection connection to handle
 */
void
MHD_http2_session_delete (struct MHD_Connection *connection);


/**
 * Queue a response to be transmitted to the client (as soon as
 * possible but after #MHD_AccessHandlerCallback returns).
 *
 * @param connection the connection identifying the client
 * @param status_code HTTP status code (i.e. #MHD_HTTP_OK)
 * @param response response to transmit
 * @return #MHD_NO on error (i.e. reply already sent),
 *         #MHD_YES on success or if message has been queued
 * @ingroup response
 */
int
MHD_http2_queue_response (struct MHD_Connection *connection,
                          unsigned int status_code,
                          struct MHD_Response *response);

#endif /* HTTP2_SUPPORT */

#endif
