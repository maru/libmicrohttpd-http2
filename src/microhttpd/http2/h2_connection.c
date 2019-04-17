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
  struct MHD_Daemon *daemon = connection->daemon;

  if (MHD_CONNECTION_CLOSED == connection->state)
    return;

#ifdef HTTPS_SUPPORT
  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
    {				/* HTTPS connection. */
      mhd_assert (MHD_TLS_CONN_CONNECTED == connection->tls_state);
    }
#endif /* HTTPS_SUPPORT */

  /* make sure "read" has a reasonable number of bytes
     in buffer to use per system call (if possible) */
  if (connection->read_buffer_offset + daemon->pool_increment >
      connection->read_buffer_size)
    try_grow_read_buffer (connection);

  if (connection->read_buffer_size == connection->read_buffer_offset)
    return;			/* No space for receiving data. */

  struct h2_session_t *h2 = connection->h2;

  mhd_assert (NULL != h2);

  ssize_t nread;
  nread = connection->recv_cls (connection,
				&connection->read_buffer[connection->
							 read_buffer_offset],
				connection->read_buffer_size -
				connection->read_buffer_offset);

  ENTER ("recv(): %zd", nread);

  if (nread < 0)
    {
      if (MHD_ERR_AGAIN_ == nread)
	return;			/* No new data to process. */
      if (MHD_ERR_CONNRESET_ == nread)
	{
	  connection_close_error (connection,
				  _
				  ("Socket is unexpectedly disconnected when reading request.\n"));
	  return;
	}
      connection_close_error (connection,
			      _
			      ("Connection socket is closed due to error when reading request.\n"));
      return;
    }

  if (0 == nread)
    {				/* Remote side closed connection. */
      connection->read_closed = true;
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_CLIENT_ABORT);
      return;
    }
  connection->read_buffer_offset += nread;
  MHD_update_last_activity_ (connection);

  mhd_assert (connection->read_closed == 0);
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
    {				/* HTTPS connection. */
      mhd_assert (MHD_TLS_CONN_CONNECTED == connection->tls_state);
    }
#endif /* HTTPS_SUPPORT */

  size_t nwrite;
  nwrite =
    connection->write_buffer_append_offset -
    connection->write_buffer_send_offset;
  if (nwrite > 0)
    {
      ssize_t nsent;
      nsent =
	connection->send_cls (connection,
			      &connection->write_buffer[connection->
							write_buffer_send_offset],
			      nwrite);
      ENTER ("send(): %zd / %zd", nsent, nwrite);

      if (nsent < 0)
	{
	  if (MHD_ERR_AGAIN_ == nsent)
	    {
	      /* Transmission could not be accomplished. Try again. */
	      return;
	    }
	  MHD_connection_close_ (connection,
				 MHD_REQUEST_TERMINATED_WITH_ERROR);
	  return;
	}

      connection->write_buffer_send_offset += nsent;
      MHD_update_last_activity_ (connection);

      if (nsent == nwrite)
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
  ENTER ();
  struct h2_session_t *h2 = connection->h2;

  connection->in_idle = true;

  if ((connection->state == MHD_CONNECTION_CLOSED) || (NULL == h2))
    {
      cleanup_connection (connection);
      connection->in_idle = false;
      return MHD_NO;
    }

  size_t nread;
  nread =
    connection->read_buffer_offset - connection->read_buffer_start_offset;
  if (nread > 0)
    {
      ssize_t rv;
      rv = h2_session_read_data (h2,
				 &connection->read_buffer
				 [connection->read_buffer_start_offset],
				 nread);

      if (rv < 0)
	{
	  MHD_connection_close_ (connection,
				 MHD_REQUEST_TERMINATED_WITH_ERROR);
	  connection->in_idle = false;
	  return MHD_NO;
	}

      /* Update read_buffer offsets */
      connection->read_buffer_start_offset += rv;
      if (connection->read_buffer_offset ==
	  connection->read_buffer_start_offset)
	{
	  connection->read_buffer_offset = 0;
	  connection->read_buffer_start_offset = 0;
	}
    }

  /* Fill write buffer */
  size_t left;
  ssize_t ret;

  left =
    connection->write_buffer_size - connection->write_buffer_append_offset;
  ret =
    h2_session_write_data (h2, connection->write_buffer, left,
			   &connection->write_buffer_append_offset);
  if (ret < 0)
    {
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
      connection->in_idle = false;
      return MHD_NO;
    }
  size_t nwrite =
    connection->write_buffer_append_offset -
    connection->write_buffer_send_offset;
  ENTER ("bytes to write = %d/%d", nwrite, left);
  if (nwrite > 0)
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
  if (((nread > 0) || (nwrite > 0)) &&
      (MHD_YES != MHD_connection_epoll_update_ (connection)))
    {
      return MHD_NO;
    }
#endif /* EPOLL_SUPPORT */

  if ((nghttp2_session_want_read (h2->session) == 0) &&
      (nghttp2_session_want_write (h2->session) == 0))
    {
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
      connection->in_idle = false;
      return MHD_YES;
    }

  time_t timeout = connection->connection_timeout;
  if ((nwrite <= 0) && (0 != timeout) &&
      (timeout <= (MHD_monotonic_sec_counter () - connection->last_activity)))
    {
      ENTER ("timeout");
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
 * Close http2 connection and free variables.
 * @param connection connection to close
 */
void
h2_connection_close (struct MHD_Connection *connection)
{
  ENTER ("");
  if (NULL == connection->h2)
    return;

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
  connection->http_version = HTTP_VERSION (1, 1);

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
#ifdef HTTPS_SUPPORT
  if (MHD_TLS_CONN_NO_TLS != connection->tls_state)
    {				/* HTTPS connection. */
      mhd_assert (MHD_TLS_CONN_CONNECTED == connection->tls_state);
    }
#endif /* HTTPS_SUPPORT */

  connection->version = MHD_HTTP_VERSION_2_0;
  connection->http_version = HTTP_VERSION (2, 0);
  connection->keepalive = MHD_CONN_USE_KEEPALIVE;

  connection->handle_read_cls = &h2_connection_handle_read;
  connection->handle_idle_cls = &h2_connection_handle_idle;
  connection->handle_write_cls = &h2_connection_handle_write;

  mhd_assert (NULL == connection->h2);
  connection->h2 = h2_session_create (connection);
  if (NULL == connection->h2)
    {
      /* Error, close connection */
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
      return;
    }

  /* Allocate read and write buffers for the connection */
  size_t size = connection->daemon->pool_size / 2;
  char *data;
  if (NULL == connection->read_buffer)
    {
      ENTER ("Allocate read_buffer size=%zu", size);
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
  do
    {
      ENTER ("Trying write_buffer size=%zu", size);
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
  while (size > wsz);

  if (NULL == data)
    {
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
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
  int ret = -1;
  if (connection->read_buffer_offset >= H2_MAGIC_TOKEN_LEN)
    {
      ret = memcmp (H2_MAGIC_TOKEN, connection->read_buffer,
		    H2_MAGIC_TOKEN_LEN);
    }
  else if (connection->read_buffer_offset >= H2_MAGIC_TOKEN_LEN_MIN)
    {
      ret = memcmp (H2_MAGIC_TOKEN, connection->read_buffer,
		    H2_MAGIC_TOKEN_LEN_MIN);
    }
  return (ret == 0) ? MHD_YES : MHD_NO;
}

/* end of h2_connection.c */
