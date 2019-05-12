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
 * @file microhttpd/http2/h2_upgrade.c
 * @brief Methods for upgrading HTTP/1 connections
 * @author Maru Berezin
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"
#include "connection.h"
#include "mhd_str.h"
#include "memorypool.h"

/**
 * Check if HTTP/1 request asks for an HTTP/2 upgrade.
 *
 * @param connection connection we are processing
 * @return If succeeds, returns MHD_YES. Otherwise, returns MHD_NO.
 */
int
h2_is_h2_upgrade (struct MHD_Connection *connection)
{
  bool is_tls = (connection->tls_state == MHD_TLS_CONN_CONNECTED);
  const char *protocol = is_tls ? "h2" : "h2c";
  const char *upgrade, *conn, *settings;

  /* Is an upgrade to http2? */
  if (NULL == (upgrade = MHD_lookup_connection_value (connection,
						      MHD_HEADER_KIND,
						      MHD_HTTP_HEADER_UPGRADE)))
    {
      return MHD_NO;
    }

  /* Is a connection for upgrade? */
  if ((NULL == (conn = MHD_lookup_connection_value (connection,
						    MHD_HEADER_KIND, MHD_HTTP_HEADER_CONNECTION))) ||
      (!MHD_str_has_s_token_caseless_ (conn, MHD_HTTP_HEADER_UPGRADE)) ||
      (!MHD_str_has_s_token_caseless_ (conn, MHD_HTTP_HEADER_HTTP2_SETTINGS)))
    {
      return MHD_NO;
    }

  /* Has the HTTP2 settings? */
  if (NULL == (settings = MHD_lookup_connection_value (connection,
						     MHD_HEADER_KIND, MHD_HTTP_HEADER_HTTP2_SETTINGS)))
    {
      return MHD_NO;
    }

  /* Is protocol proposed? (h2/h2c) */
  if (0 != strcmp (upgrade, protocol))
    {
      return MHD_NO;
    }
  return MHD_YES;
}


/**
 * Do HTTP/2 upgrade.
 *
 * @param connection        connection we are processing
 * @return If succeeds, returns MHD_YES. Otherwise, returns MHD_NO.
 */
int
h2_do_h2_upgrade (struct MHD_Connection *connection)
{
  struct h2_stream_t *stream;
  struct MHD_Response *response;
  bool is_tls = (connection->tls_state == MHD_TLS_CONN_CONNECTED);
  const char *protocol = is_tls ? "h2" : "h2c";
  const char *settings;
  int ret;

  /* Get base64 decoded settings from client */
  settings = MHD_lookup_connection_value (connection,
					  MHD_HEADER_KIND, MHD_HTTP_HEADER_HTTP2_SETTINGS);

  /***************************************************************************/
  int i = 1;
  ENTER("%d) Create 101 response", i++);
  /* Create HTTP/1 response */
  response =
    MHD_create_response_from_buffer (0, NULL, MHD_RESPMEM_PERSISTENT);

  /* Connection: Upgrade */
  MHD_add_response_header (response,
             MHD_HTTP_HEADER_CONNECTION,
             MHD_HTTP_HEADER_UPGRADE);
  /* Upgrade: h2c or h2 */
  MHD_add_response_header (response, MHD_HTTP_HEADER_UPGRADE, protocol);
  /* HTTP/1.1 101 Switching Protocols */
  if (MHD_YES != MHD_queue_response (connection,
                                   MHD_HTTP_SWITCHING_PROTOCOLS, response))
    {
      return MHD_NO;
    }
  MHD_destroy_response (response);
  if (MHD_YES != build_header_response (connection))
    {
      connection_close_error (connection,
             _("Closing connection (failed to create response header)\n"));
      return MHD_NO;
    }
ENTER("[%d] build_header_response: write_size=%d offset=%d", __LINE__, connection->write_buffer_size, connection->write_buffer_append_offset);

  /***************************************************************************/
  struct MHD_Connection tmp_conn;
  util_copy_connection_buffers (&tmp_conn, connection);
  util_reset_connection_buffers (connection);

  /***************************************************************************/
  ENTER("%d) Create h2 session and set h2 callbacks", i++);

  h2_set_h2_callbacks (connection);
  if (NULL == connection->h2)
    {
      return MHD_NO;
    }
// ENTER("connection->write_buffer %p", connection->write_buffer);
// ENTER("tmp_conn.write_buffer %p", tmp_conn.write_buffer);
  memcpy (connection->write_buffer, tmp_conn.write_buffer, tmp_conn.write_buffer_append_offset);
  connection->write_buffer_append_offset += tmp_conn.write_buffer_append_offset;

  /* Upgrade to HTTP/2 connection */
  ret = h2_session_upgrade (connection->h2, settings, connection->method);

  ENTER("[%d] h2_set_h2_callbacks: write_size=%d offset=%d", __LINE__, connection->write_buffer_size, connection->write_buffer_append_offset);

  /***************************************************************************/
  ENTER("%d) h2_stream_create", i++);
  if ((0 != h2_session_create_stream (connection->h2, 1)) ||
      (NULL == (stream = h2_session_get_stream (connection->h2, 1))))
    {
      return MHD_NO;
    }
ENTER("stream_id=%d", stream->stream_id);
  /* Assign pool memory */
  MHD_pool_destroy (stream->c.pool);
  util_copy_connection_buffers (&stream->c, &tmp_conn);
  //   connection->state = MHD_CONNECTION_HEADERS_SENDING;
  // ENTER("[%d] handle_write_cls: write_size=%d offset=%d", __LINE__, connection->write_buffer_size, connection->write_buffer_append_offset);

  process_request_final (connection->h2, stream);
  // h2_session_remove_stream (connection->h2, stream);
  return connection->handle_idle_cls (connection);
}

/* end of h2_upgrade.c */
