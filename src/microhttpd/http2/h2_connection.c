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
 * @file microhttpd/http2/h2_connection.c
 * @brief Methods for managing HTTP/2 connections
 * @author Maru Berezin
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"
#include "connection.h"
#include "memorypool.h"
#include "mhd_mono_clock.h"
#include "mhd_str.h"
#include "response.h"

#undef COLOR_RED
#define COLOR_RED    "\033[32;1m"

#define H2_MAGIC_TOKEN "PRI * HTTP/2.0\r\n\r\nSM\r\n\r\n"
#define H2_MAGIC_TOKEN_LEN_MIN 16
#define H2_MAGIC_TOKEN_LEN 24

/**
 * Read data from the connection.
 *
 * @param connection connection to handle
 */
void
h2_connection_handle_read (struct MHD_Connection *connection)
{
  ssize_t bytes_read;
  struct MHD_Daemon *daemon = connection->daemon;

  if (MHD_CONNECTION_CLOSED == connection->state)
    return;

#ifdef HTTPS_SUPPORT
  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
    { /* HTTPS connection. */
      mhd_assert (MHD_TLS_CONN_CONNECTED == connection->tls_state);
    }
#endif /* HTTPS_SUPPORT */

  /* make sure "read" has a reasonable number of bytes
     in buffer to use per system call (if possible) */
  if (connection->read_buffer_offset + daemon->pool_increment >
      connection->read_buffer_size)
    try_grow_read_buffer (connection);

  if (connection->read_buffer_size == connection->read_buffer_offset)
    return; /* No space for receiving data. */

  struct h2_session_t *h2 = connection->h2;

  mhd_assert (NULL != h2);

  bytes_read = connection->recv_cls (connection,
                                     &connection->read_buffer
                                     [connection->read_buffer_offset],
                                     connection->read_buffer_size -
                                     connection->read_buffer_offset);

  // ENTER ("recv(): %zd", bytes_read);

  if (bytes_read < 0)
    {
      if (MHD_ERR_AGAIN_ == bytes_read)
          return; /* No new data to process. */
      if (MHD_ERR_CONNRESET_ == bytes_read)
        {
           connection_close_error (connection,
                                   _("Socket is unexpectedly disconnected when reading request.\n"));
           return;
        }
      connection_close_error (connection,
                                _("Connection socket is closed due to error when reading request.\n"));
      return;
    }

  if (0 == bytes_read)
    { /* Remote side closed connection. */
      connection->read_closed = true;
      MHD_connection_close_ (connection,
                             MHD_REQUEST_TERMINATED_CLIENT_ABORT);
      return;
    }
  connection->read_buffer_offset += bytes_read;
  MHD_update_last_activity_ (connection);

  mhd_assert(connection->read_closed == 0);
}


/**
 * Write data to the connection.
 *
 * @param connection connection to handle
 */
void
h2_connection_handle_write (struct MHD_Connection *connection)
{
  struct h2_session_t *h2 = connection->h2;
  mhd_assert (NULL != h2);

  if (MHD_CONNECTION_CLOSED == connection->state)
    return;

#ifdef HTTPS_SUPPORT
  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
    { /* HTTPS connection. */
      mhd_assert (MHD_TLS_CONN_CONNECTED == connection->tls_state);
    }
#endif /* HTTPS_SUPPORT */

  size_t bytes_to_send = connection->write_buffer_append_offset - connection->write_buffer_send_offset;

  if (bytes_to_send > 0)
    {
      ssize_t bytes_sent;
      const char *write_buffer = &connection->write_buffer[connection->write_buffer_send_offset];

      bytes_sent = connection->send_cls (connection, write_buffer, bytes_to_send);
      ENTER ("send(): %zd / %zd", bytes_sent, bytes_to_send);

      if (bytes_sent < 0)
        {
          if (MHD_ERR_AGAIN_ == bytes_sent)
            {
              /* Transmission could not be accomplished. Try again. */
              return;
            }
          MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
          return;
        }

      connection->write_buffer_send_offset += bytes_sent;
      MHD_update_last_activity_ (connection);

      if (bytes_sent == bytes_to_send)
        {
          /* Reset offsets */
          connection->write_buffer_append_offset = 0;
          connection->write_buffer_send_offset = 0;
        }
    }
}


/**
 * Process data.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
h2_connection_handle_idle (struct MHD_Connection *connection)
{
  struct h2_session_t *h2 = connection->h2;

  connection->in_idle = true;

  if ((connection->state == MHD_CONNECTION_CLOSED) || (NULL == h2))
    {
      cleanup_connection (connection);
      connection->in_idle = false;
      return MHD_NO;
    }

  size_t bytes_to_read = connection->read_buffer_offset - connection->read_buffer_start_offset;
  if (bytes_to_read > 0)
    {
      ssize_t rv;
      rv = h2_session_read_data (h2,
                &connection->read_buffer[connection->read_buffer_start_offset],
                bytes_to_read);

      if (rv < 0)
        {
          MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
          connection->in_idle = false;
          return MHD_NO;
        }

      /* Update read_buffer offsets */
      connection->read_buffer_start_offset += rv;
      if (connection->read_buffer_offset == connection->read_buffer_start_offset)
        {
          connection->read_buffer_offset = 0;
          connection->read_buffer_start_offset = 0;
        }
    }

  /* Fill write buffer */
  size_t left = connection->write_buffer_size - connection->write_buffer_append_offset;
  // ENTER("%d / %d / %d", connection->write_buffer_size, connection->write_buffer_send_offset, connection->write_buffer_append_offset);
  size_t bytes_to_send = h2_session_write_data (h2, connection->write_buffer, left, &connection->write_buffer_append_offset);
  // ENTER("bytes to write = %d/%d", bytes_to_send, left);
  if (bytes_to_send < 0)
    {
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
      connection->in_idle = false;
      return MHD_NO;
    }

  if (bytes_to_send > 0)
    {
      /* Next event is write */
      connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
    }
  else
    {
      /* Next event is read */
      connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
    }

#ifdef EPOLL_SUPPORT
  /* Update epoll event if we are ready to recv or send any bytes */
  if ( ((bytes_to_read > 0) || (bytes_to_send > 0)) &&
       (MHD_YES != MHD_connection_epoll_update_ (connection)) )
    {
      return MHD_NO;
    }
#endif /* EPOLL_SUPPORT */

  if ( (nghttp2_session_want_read (h2->session) == 0) &&
       (nghttp2_session_want_write (h2->session) == 0) )
    {
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
      connection->in_idle = false;
      return MHD_YES;
    }

  time_t timeout = connection->connection_timeout;
  if ( (bytes_to_send <= 0) && (0 != timeout) &&
       (timeout <= (MHD_monotonic_sec_counter() - connection->last_activity)) )
    {
      MHD_connection_close_ (connection,
                             MHD_REQUEST_TERMINATED_TIMEOUT_REACHED);
    }

  connection->in_idle = false;
  return MHD_YES;
}

/**
 *
 */
void
h2_stream_resume (struct MHD_Connection *connection)
{
}


/**
 * Suspend handling of network data for the current stream.
 * @param connection connection to handle
 */
void
h2_stream_suspend (struct MHD_Connection *connection)
{
}

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
h2_queue_response (struct MHD_Connection *connection,
                   unsigned int status_code,
                   struct MHD_Response *response)
{
  MHD_increment_response_rc (response);
  connection->response = response;
  connection->responseCode = status_code;

  if ( ( (NULL != connection->method) &&
         (MHD_str_equal_caseless_ (connection->method,
                                   MHD_HTTP_METHOD_HEAD)) ) ||
       (MHD_HTTP_OK > status_code) ||
       (MHD_HTTP_NO_CONTENT == status_code) ||
       (MHD_HTTP_NOT_MODIFIED == status_code) )
    {
      /* if this is a "HEAD" request, or a status code for
         which a body is not allowed, pretend that we
         have already sent the full message body. */
      connection->response_write_position = response->total_size;
    }

  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */
  if (! connection->in_idle)
    h2_connection_handle_idle (connection);
  MHD_update_last_activity_ (connection);
  return MHD_YES;
}

/**
 * Close http2 connection and free variables.
 * @param connection connection to close
 */
void
h2_connection_close (struct MHD_Connection *connection)
{
  // ENTER("");
  if (NULL == connection->h2) return;
  h2_session_destroy (connection->h2);
  connection->h2 = NULL;

  connection->state = MHD_CONNECTION_CLOSED;
  MHD_pool_destroy (connection->pool);
  connection->pool = NULL;
  connection->read_buffer = NULL;
  connection->read_buffer_size = 0;
  connection->write_buffer = NULL;
  connection->write_buffer_size = 0;
}

/**
 * Set HTTP/1 read/idle/write callbacks for this connection.
 * Handle data from/to socket.
 *
 * @param connection connection to initialize
 */
void
h2_set_h1_callbacks (struct MHD_Connection *connection)
{
  connection->version = MHD_HTTP_VERSION_1_1;
  connection->http_version = HTTP_VERSION(1, 1);

  connection->handle_read_cls = &MHD_connection_handle_read;
  connection->handle_idle_cls = &MHD_connection_handle_idle;
  connection->handle_write_cls = &MHD_connection_handle_write;
}


/**
 * Set HTTP/2 read/idle/write callbacks for this connection.
 * Handle data from/to socket.
 * Create HTTP/2 session.
 *
 * @param connection connection to initialize
 */
void
h2_set_h2_callbacks (struct MHD_Connection *connection)
{
  ENTER();
#ifdef HTTPS_SUPPORT
  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
    { /* HTTPS connection. */
      mhd_assert (MHD_TLS_CONN_CONNECTED == connection->tls_state);
    }
#endif /* HTTPS_SUPPORT */

  connection->version = MHD_HTTP_VERSION_2_0;
  connection->http_version = HTTP_VERSION(2, 0);
  connection->keepalive = MHD_CONN_USE_KEEPALIVE;

  connection->handle_read_cls = &h2_connection_handle_read;
  connection->handle_idle_cls = &h2_connection_handle_idle;
  connection->handle_write_cls = &h2_connection_handle_write;

  mhd_assert (NULL == connection->h2);
  connection->h2 = h2_session_create (connection);
  if (NULL == connection->h2)
    {
      /* Error, close connection */
      MHD_connection_close_ (connection,
                             MHD_REQUEST_TERMINATED_WITH_ERROR);
      return;
    }

  /* Allocate read and write buffers for the connection */
  size_t size = connection->daemon->pool_size / 2;
  char *data;
  if (NULL == connection->read_buffer)
    {
      // ENTER("Allocate read_buffer size=%zu", size);
      data = MHD_pool_allocate (connection->pool, size, MHD_YES);
      if (NULL == data)
        {
          MHD_connection_close_ (connection,
                                 MHD_REQUEST_TERMINATED_WITH_ERROR);
          return;
        }
      connection->read_buffer = data;
      connection->read_buffer_start_offset = 0;
      connection->read_buffer_offset = 0;
      connection->read_buffer_size = size;
    }

  size_t wsz = 1024;
  while (size > wsz)
  {
    ENTER("Trying write_buffer size=%zu", size);
    data = MHD_pool_allocate (connection->pool, size, MHD_YES);
    if (NULL == data)
      {
        size -= wsz;
        wsz <<= 1;
        continue;
      }
    connection->write_buffer = data;
    connection->write_buffer_append_offset = 0;
    connection->write_buffer_send_offset = 0;
    connection->write_buffer_size = size;
    break;
  }
  if (NULL == data)
    {
      MHD_connection_close_ (connection,
                             MHD_REQUEST_TERMINATED_WITH_ERROR);
      return;
    }
}


/**
 * Check if first bytes are the h2 preface.
 * If the buffer has at least H2_MAGIC_TOKEN_LEN bytes, check full preface.
 * Otherwise, just check the first H2_MAGIC_TOKEN_LEN_MIN bytes, because
 * MHD_connection_handle_idle will find the first "\r\n" and believe it is an
 * HTTP/1 request.
 *
 * @param connection connection
 * @return #MHD_YES for success, #MHD_NO for failure
 */
int
h2_is_h2_preface (struct MHD_Connection *connection)
{
  int ret = MHD_NO;
  if (connection->read_buffer_offset >= H2_MAGIC_TOKEN_LEN)
    {
      ret = !memcmp(H2_MAGIC_TOKEN, connection->read_buffer, H2_MAGIC_TOKEN_LEN) ?
            MHD_YES : MHD_NO;
    }
  else if (connection->read_buffer_offset >= H2_MAGIC_TOKEN_LEN_MIN)
    {
      ret = !memcmp(H2_MAGIC_TOKEN, connection->read_buffer, H2_MAGIC_TOKEN_LEN_MIN) ?
            MHD_YES : MHD_NO;
    }
  ENTER("ret=%d", ret);
  return ret;
}

/* end of h2_connection.c */
