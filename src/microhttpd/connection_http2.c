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

/**
 * Initialize HTTP2 structures.
 *
 * @param connection connection to handle
 * @return #MHD_YES if
 *         , #MHD_NO otherwise
 */
int
MHD_http2_session_init (struct MHD_Connection *connection)
{
  int rv;
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
