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

extern struct MHD_Daemon *daemon_;

#define H2_HEADER_COOKIE     "cookie"
#define H2_HEADER_COOKIE_LEN  6
#define H2_HEADER_CONTENT_LENGTH     "content-length"
#define H2_HEADER_CONTENT_LENGTH_LEN 14

/**
 * Create a new stream structure and add it to the session.
 *
 * @param h2 HTTP/2 session
 * @param stream_id stream identifier
 * @return new stream, NULL if error.
 */
struct h2_stream_t*
h2_stream_create (int32_t stream_id, size_t pool_size)
{
  struct h2_stream_t *stream;
  stream = calloc (1, sizeof (struct h2_stream_t));
  if (NULL == stream)
    {
      return NULL;
    }

  stream->stream_id = stream_id;

  char *data;
  size_t size = pool_size/2;
  stream->c.pool = MHD_pool_create (pool_size);
  if ( (NULL == stream->c.pool) ||
       (NULL == (data = MHD_pool_allocate (stream->c.pool, size, MHD_YES))) )
    {
      free (stream);
      return NULL;
    }

  stream->c.write_buffer = data;
  stream->c.write_buffer_append_offset = 0;
  stream->c.write_buffer_send_offset = 0;
  stream->c.write_buffer_size = size;
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
  ENTER ("stream_id=%zu", stream->stream_id);
  if (stream->c.response)
    {
      MHD_destroy_response (stream->c.response);
      stream->c.response = NULL;

      if ((NULL != daemon_->notify_completed) && (stream->c.client_aware))
        {
          stream->c.client_aware = false;
          daemon_->notify_completed (daemon_->notify_completed_cls,
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
h2_stream_add_header (struct h2_stream_t *stream,
                      const uint8_t *name, const size_t namelen,
                      const uint8_t *value, const size_t valuelen)
{
  if ( (namelen == H2_HEADER_CONTENT_LENGTH_LEN) &&
            (0 == strcmp (H2_HEADER_CONTENT_LENGTH, name)) )
    {
      stream->c.remaining_upload_size = atol(value);
      return 0;
    }

  char *key = MHD_pool_allocate (stream->c.pool, namelen + 1, MHD_YES);
  char *val = MHD_pool_allocate (stream->c.pool, valuelen + 1, MHD_YES);

  if ((NULL == key) || (NULL == val))
    {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

  strncpy (key, name, namelen + 1);
  strncpy (val, value, valuelen + 1);

  int r;
  if ( (namelen == H2_HEADER_COOKIE_LEN) &&
       (0 == strcmp (H2_HEADER_COOKIE, name)) )
    {
      r = MHD_set_connection_value (&stream->c, MHD_COOKIE_KIND, key, val);
      r = (r == MHD_YES) ? parse_cookie_header (&stream->c) : r;
    }
  else
  {
    /* Other headers */
    r = MHD_set_connection_value (&stream->c, MHD_HEADER_KIND, key, val);
  }

  if (MHD_NO == r)
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon_,
                  _("Not enough memory in pool to allocate header record!\n"));
#endif
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

  return 0;
}


/* end of h2_stream.c */
