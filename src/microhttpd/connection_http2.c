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
 * @file microhttpd/connection_http2.c
 * @brief Methods for managing HTTP/2 connections
 * @author maru (Maru Berezin)
 */

#include "connection_http2.h"

#ifdef HTTP2_SUPPORT

#define ENTER(format, args...) fprintf(stderr, "\e[31;1m[%s]\e[0m " format "\n", __FUNCTION__, ##args)

static ssize_t
send_callback(nghttp2_session *session, const uint8_t *data,
                             size_t length, int flags, void *user_data)
{
  struct MHD_Connection *connection = (struct MHD_Connection *) user_data;
  (void)session;
  (void)flags;
  ENTER();

  connection->send_cls (connection, data, length);
  return (ssize_t)length;
}

/**
 *
 *
 * @param h2
 */
static int
http2_init_session (struct MHD_Connection *connection)
{
  int rv;
  struct http2_conn *h2 = connection->h2;
  nghttp2_session_callbacks *callbacks;

  rv = nghttp2_session_callbacks_new (&callbacks);
  if (rv != 0)
  {
    return rv;
  }

  nghttp2_session_callbacks_set_send_callback (callbacks, send_callback);

  // nghttp2_session_callbacks_set_on_frame_recv_callback (callbacks,
  //                                                      on_frame_recv_callback);

  // nghttp2_session_callbacks_set_on_stream_close_callback (
  //     callbacks, on_stream_close_callback);

  // nghttp2_session_callbacks_set_on_header_callback (callbacks,
  //                                                  on_header_callback);

  // nghttp2_session_callbacks_set_on_begin_headers_callback (
  //     callbacks, on_begin_headers_callback);

  rv = nghttp2_session_server_new (&h2->session, callbacks, connection);
  if (rv != 0)
  {
    return rv;
  }

  nghttp2_session_callbacks_del (callbacks);
  return 0;
}


/* Send HTTP/2 client connection header, which includes 24 bytes
   magic octets and SETTINGS frame */
static int
http2_send_server_connection_header(struct http2_conn *h2,
                                const nghttp2_settings_entry *iv, size_t niv)
{
  int rv;
  ENTER();

  rv = nghttp2_submit_settings(h2->session, NGHTTP2_FLAG_NONE, iv, niv);
  if (rv != 0)
  {
    ENTER("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}


/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int
http2_session_send(struct http2_conn *h2)
{
  ENTER();
  int rv;
  rv = nghttp2_session_send(h2->session);
  if (rv != 0) {
    ENTER("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/**
 *
 *
 * @param stream_data
 */
static void
delete_http2_stream_data (struct http2_stream_data *stream_data)
{
  free (stream_data);
}

/**
 * Delete HTTP2 structures.
 *
 * @param connection connection to handle
 */
void
http2_session_delete (struct MHD_Connection *connection)
{
  struct http2_conn *h2 = connection->h2;
  struct http2_stream_data *stream_data;

  nghttp2_session_del (h2->session);

  for (stream_data = h2->head.next; stream_data; )
  {
      struct http2_stream_data *next = stream_data->next;
      delete_http2_stream_data (stream_data);
      stream_data = next;
  }
  free (h2);
}




/**
 * Initialize HTTP2 structures.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise
 */
int
MHD_http2_session_init (struct MHD_Connection *connection)
{
  int rv;
  connection->h2 = malloc (sizeof (struct http2_conn));
  if (connection->h2 == NULL)
  {
    return MHD_NO;
  }
  memset (connection->h2, 0, sizeof (struct http2_conn));

  rv = http2_init_session (connection);
  if (rv != 0)
  {
    return MHD_NO;
  }
  return MHD_YES;
}


/**
 * Send HTTP/2 preface.
 *
 * @param connection connection to handle
 * @param iv http2 settings array
 * @param niv number of entries
 */
int
MHD_http2_send_preface (struct MHD_Connection *connection,
                        const nghttp2_settings_entry *iv, size_t niv)
{
  struct http2_conn *h2 = connection->h2;
  if (http2_send_server_connection_header (h2, iv, niv) != 0 ||
      http2_session_send (h2) != 0)
  {
    http2_session_delete (connection);
    return MHD_NO;
  }
  return MHD_YES;
}


/**
 * There is data to be read off a socket.
 *
 * @param connection connection to handle
 */
void
http2_handle_read (struct MHD_Connection *connection)
{
  ENTER();
}


/**
 * Handle writes to sockets.
 *
 * @param connection connection to handle
 */
void
http2_handle_write (struct MHD_Connection *connection)
{
  ENTER();
}


/**
 * Handle per-connection processing.
 *
 * @param connection connection to handle
 * @return #MHD_YES if we should continue to process the
 *         connection (not dead yet), #MHD_NO if it died
 */
int
http2_handle_idle (struct MHD_Connection *connection)
{
  int ret;
  ENTER();
  return ret;
}


/**
 * Set HTTP/2 read/idle/write callbacks for this connection.
 * Handle data from/to socket.
 *
 * @param connection connection to initialize
 */
void
MHD_set_http2_callbacks (struct MHD_Connection *connection)
{
  connection->read_cls = &http2_handle_read;
  connection->idle_cls = &http2_handle_idle;
  connection->write_cls = &http2_handle_write;
}

#endif /* HTTP2_SUPPORT */

/* end of connection_http2.c */
