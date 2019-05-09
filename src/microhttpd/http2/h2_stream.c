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
 * @file microhttpd/http2/h2_stream.c
 * @brief Methods for managing HTTP/2 streams
 * @author Maru Berezin
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"
#include "connection.h"
#include "memorypool.h"

#define H2_HEADER_COOKIE     "cookie"
#define H2_HEADER_COOKIE_LEN  6
#define H2_HEADER_CONTENT_LENGTH     "content-length"
#define H2_HEADER_CONTENT_LENGTH_LEN 14

#undef COLOR_RED
#define COLOR_RED    "\033[36;1m"

/**
 * Create a new stream structure and add it to the session.
 *
 * @param h2 HTTP/2 session
 * @param stream_id stream identifier
 * @return new stream, NULL if error.
 */
struct h2_stream_t *
h2_stream_create (int32_t stream_id, struct MHD_Connection *connection)
{
  struct h2_stream_t *stream;
  stream = calloc (1, sizeof (struct h2_stream_t));
  if (NULL == stream)
    {
      return NULL;
    }
  ENTER("(stream_id=%d)", stream_id);
  stream->stream_id = stream_id;

  char *data;
  stream->c.pool = MHD_pool_create (connection->daemon->pool_size);
  if (NULL == stream->c.pool)
    {
      free (stream);
      return NULL;
    }
  stream->c.daemon = connection->daemon;
  stream->c.pid = connection->pid;
  stream->c.version = MHD_HTTP_VERSION_2_0;
  stream->c.tls_session = connection->tls_session;
  return stream;
}


/**
 * Delete a stream from HTTP/2 session.
 *
 * @param h2 HTTP/2 session
 * @param stream stream to remove from the session
 */
void
h2_stream_destroy (struct h2_stream_t *stream)
{
  struct MHD_Daemon *daemon = stream->c.daemon;

  if (stream->c.response)
    {
      MHD_destroy_response (stream->c.response);
      stream->c.response = NULL;

      if ((NULL != daemon->notify_completed) && (stream->c.client_aware))
	{
	  stream->c.client_aware = false;
	  /* FIXME: test_quiesce_http2 */
	  fprintf(stderr, "[%s:%d] &connection->client_context %p\n", __FILE__, __LINE__, &stream->c.client_context);
	  daemon->notify_completed (daemon->notify_completed_cls,
				    &stream->c, &stream->c.client_context,
				    MHD_REQUEST_TERMINATED_COMPLETED_OK);
	}
    }
  MHD_pool_destroy (stream->c.pool);
  free (stream);
}


/**
 * Add an entry to the HTTP headers of a stream.
 *
 * @param connection connection to handle
 * @param h2       HTTP/2 session
 * @param stream     current stream
 * @param name       header name
 * @param namelen    length of header name
 * @param value      header value
 * @param valuelen   length of header value
 * @return If succeeds, returns 0.
 *         Otherwise, returns an error (NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE).
 */
int
h2_stream_add_recv_header (struct h2_stream_t *stream,
			   const uint8_t * name, const size_t namelen,
			   const uint8_t * value, const size_t valuelen)
{
  struct MHD_Daemon *daemon = stream->c.daemon;

  if ((namelen == H2_HEADER_CONTENT_LENGTH_LEN) &&
      (0 ==
       memcmp (H2_HEADER_CONTENT_LENGTH, name, H2_HEADER_CONTENT_LENGTH_LEN)))
    {
      stream->c.remaining_upload_size = atol (value);
      return 0;
    }

  char *key = MHD_pool_allocate (stream->c.pool, namelen + 1, MHD_YES);
  char *val = MHD_pool_allocate (stream->c.pool, valuelen + 1, MHD_YES);

  if ((NULL == key) || (NULL == val))
    {
      stream->c.responseCode = MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
      return 0;
    }

  memcpy (key, name, namelen + 1);
  memcpy (val, value, valuelen + 1);

  int r;
  if ((namelen == H2_HEADER_COOKIE_LEN) &&
      (0 == memcmp (H2_HEADER_COOKIE, name, H2_HEADER_COOKIE_LEN)))
    {
      r = MHD_set_connection_value (&stream->c, MHD_HEADER_KIND, key, val);
      r = (r == MHD_YES) ? parse_cookie_header (&stream->c) : r;
    }
  else
    {
      /* Other headers */
      r = MHD_set_connection_value (&stream->c, MHD_HEADER_KIND, key, val);
    }

  if (MHD_YES != r)
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon,
		_("Not enough memory in pool to allocate header record!\n"));
#endif
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

  return 0;
}


/**
 * Call the handler of the application for this connection.
 * Handles chunking of the upload as well as normal uploads.
 *
 * @param stream            stream we are processing
 * @param upload_data       the data being uploaded
 * @param upload_data_size  the size of the upload_data provided
 * @return If succeeds, returns MHD_YES.
 *         Otherwise, resets the stream and returns MHD_NO.
 */
int
h2_stream_call_connection_handler (struct h2_stream_t *stream,
				   char *upload_data,
				   size_t * upload_data_size)
{
  struct MHD_Daemon *daemon = stream->c.daemon;
  ENTER("(stream_id=%d)", stream->stream_id);
  if ((NULL != stream->c.response) || (0 != stream->c.responseCode))
    return MHD_YES;		/* already queued a response */

  stream->c.in_idle = true;
  stream->c.client_aware = true;
  int ret = daemon->default_handler (daemon->default_handler_cls,
				     &stream->c, stream->c.url,
				     stream->c.method, MHD_HTTP_VERSION_2_0,
				     upload_data, upload_data_size,
				     &stream->c.client_context);
  stream->c.in_idle = false;
  return ret;
}


/* end of h2_stream.c */
