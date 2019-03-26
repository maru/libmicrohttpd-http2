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
#include "base64.h"
#include "mhd_str.h"

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
                           MHD_HEADER_KIND, MHD_HTTP_HEADER_UPGRADE)))
    {
      return MHD_NO;
    }

  /* Is a connection for upgrade? */
  if ( (NULL == (conn = MHD_lookup_connection_value (connection,
                         MHD_HEADER_KIND, MHD_HTTP_HEADER_CONNECTION))) ||
       (!MHD_str_has_s_token_caseless_ (conn, MHD_HTTP_HEADER_UPGRADE)) ||
       (!MHD_str_has_s_token_caseless_ (conn, MHD_HTTP_HEADER_HTTP2_SETTINGS)) )
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
  if (strcmp (upgrade, protocol) != 0)
    {
      return MHD_NO;
    }
  h2_debug_vprintf ("yes");
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
  struct MHD_Response *response;
  bool is_tls = (connection->tls_state == MHD_TLS_CONN_CONNECTED);
  const char *protocol = is_tls ? "h2" : "h2c";
  const char *settings;
  char *settings_payload;
  int head_request = 0, ret;
  size_t len;

  /* Get base64 decoded settings from client */
  settings = MHD_lookup_connection_value (connection,
                MHD_HEADER_KIND, MHD_HTTP_HEADER_HTTP2_SETTINGS);
  settings_payload = BASE64Decode (settings);
  len = strlen (settings_payload);

  /* Is it a HEAD request? */
  if (MHD_str_equal_caseless_ (connection->method, MHD_HTTP_METHOD_HEAD))
    {
      head_request = 1;
    }

  /* Create HTTP/1 response */
  response = MHD_create_response_from_buffer (0, NULL, MHD_RESPMEM_PERSISTENT);

  /* Connection: Upgrade */
  MHD_add_response_header (response,
                           MHD_HTTP_HEADER_CONNECTION, MHD_HTTP_HEADER_UPGRADE);
  /* Upgrade: h2c or h2 */
  MHD_add_response_header (response,
                           MHD_HTTP_HEADER_UPGRADE, protocol);
  /* HTTP/1.1 101 Switching Protocols */
  ret = MHD_queue_response (connection,
                            MHD_HTTP_SWITCHING_PROTOCOLS,
                            response);
  if (MHD_NO == ret)
    {
      return MHD_NO;
    }

  MHD_destroy_response (response);

  if (MHD_NO == build_header_response (connection))
    {
      connection_close_error (connection,
            _("Closing connection (failed to create response header)\n"));
      return MHD_NO;
    }

  h2_set_h2_callbacks (connection);
  if (NULL == connection->h2)
    {
      return MHD_NO;
    }

  /* Upgrade to HTTP/2 connection */
  ret = nghttp2_session_upgrade2 (connection->h2->session,
                                  settings_payload, len, head_request, NULL);
  free (settings_payload);
  if (ret)
    {
      /* Cannot perform upgrade */
      return MHD_NO;
    }

  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */

  return MHD_YES;
}

/* end of h2_upgrade.c */
