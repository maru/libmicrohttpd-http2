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
 * @file microhttpd/http2/h2_util.c
 * @brief Utility methods
 * @author Maru Berezin
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"
#include "http2/h2_util.h"
#include "connection.h"
#include "memorypool.h"

void
util_reset_connection_buffers (struct MHD_Connection *connection)
{
  connection->pool = MHD_pool_create (connection->daemon->pool_size);

  connection->read_buffer = NULL;
  connection->read_buffer_size = 0;
  connection->read_buffer_offset = 0;

  connection->write_buffer = NULL;
  connection->write_buffer_size = 0;
  connection->write_buffer_append_offset = 0;

  connection->headers_received = NULL;
  connection->headers_received_tail = NULL;

  connection->method = NULL;
  connection->url = NULL;
  connection->client_context = NULL;

  connection->response = 0;
  connection->responseCode = 0;
}

void
util_copy_connection_buffers (struct MHD_Connection *src, struct MHD_Connection *dst)
{
  dst->pool = src->pool;

  /* Assign read_buffer to stream */
  dst->read_buffer = src->read_buffer;
  dst->read_buffer_size = src->read_buffer_size;
  dst->read_buffer_offset = src->read_buffer_offset;

  /* Assign write_buffer to stream */
  dst->write_buffer = src->write_buffer;
  dst->write_buffer_size = src->write_buffer_size;
  dst->write_buffer_append_offset = src->write_buffer_append_offset;

  /* Assign headers_received to stream */
  dst->headers_received = src->headers_received;
  dst->headers_received_tail = src->headers_received_tail;

  dst->method = src->method;
  dst->url = src->url;
  dst->client_context = src->client_context;
}

void
util_copy_connection_response (struct MHD_Connection *src, struct MHD_Connection *dst)
{
  dst->response = src->response;
  dst->responseCode = src->responseCode;
}
