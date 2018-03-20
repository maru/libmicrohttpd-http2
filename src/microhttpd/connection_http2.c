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
#include "connection_http2_helper.h"
#include "mhd_mono_clock.h"
#include "connection.h"
#include "memorypool.h"
#include "response.h"
#include "mhd_str.h"

#ifdef HTTP2_SUPPORT

/* ================================================================ */
/*                        Stream operations                         */
/* ================================================================ */

/**
 * Add a stream to the end of the stream list.
 *
 * @param h2 HTTP/2 session
 * @param stream new stream to add to the session
 */
static void
add_stream (struct http2_conn *h2,
            struct http2_stream *stream)
{
  mhd_assert (h2 != NULL && stream != NULL);

  // First element
  if (h2->streams == NULL)
  {
    h2->streams = stream;
    stream->prev = NULL;
  }
  else
  {
    mhd_assert (h2->streams != NULL);
    mhd_assert (h2->streams_tail != NULL);

    h2->streams_tail->next = stream;
    stream->prev = h2->streams_tail;
  }

  h2->streams_tail = stream;
  stream->next = NULL;
}


/**
 * Remove a stream from the stream list.
 *
 * @param h2 HTTP/2 session
 * @param stream stream to remove from the session
 */
static void
remove_stream (struct http2_conn *h2,
               struct http2_stream *stream)
{
  mhd_assert (h2 != NULL && stream != NULL);

  // Only one element
  if (h2->streams == h2->streams_tail)
  {
    mhd_assert (h2->streams != NULL);
    h2->streams = NULL;
    h2->streams_tail = NULL;
  }
  else
  {
    if (stream->prev != NULL)
    {
      stream->prev->next = stream->next;
    }
    if (stream->next != NULL)
    {
      stream->next->prev = stream->prev;
    }
  }

  if (h2->streams == stream)
  {
    h2->streams = stream->next;
  }

  if (h2->streams_tail == stream)
  {
    h2->streams_tail = stream->prev;
  }
}


/**
 * Create a new stream structure and add it to the session.
 *
 * @param h2 HTTP/2 session
 * @param stream_id stream identifier
 * @return new stream, NULL if error.
 */
static struct http2_stream*
http2_stream_create (struct http2_conn *h2,
                     int32_t stream_id)
{
  struct http2_stream *stream;
  stream = calloc (1, sizeof (struct http2_stream));
  if (stream == NULL)
  {
    return NULL;
  }

  stream->stream_id = stream_id;

  h2->num_streams++;
  h2->accepted_max = stream_id;

  add_stream (h2, stream);
  // ENTER("id=%zu stream_id=%zu", h2->session_id, stream->stream_id);
  return stream;
}


/**
 * Delete a stream from HTTP/2 session.
 *
 * @param h2 HTTP/2 session
 * @param stream stream to remove from the session
 */
static void
http2_stream_delete (struct http2_conn *h2,
                     struct http2_stream *stream)
{
  mhd_assert (h2->num_streams > 0);
  h2->num_streams--;
  // ENTER("id=%zu stream_id=%zu", h2->session_id, stream->stream_id);
  if (stream->response)
  {
    MHD_destroy_response (stream->response);
    stream->response = NULL;

    struct MHD_Connection *connection = h2->connection;
    if ((NULL != connection->daemon->notify_completed) && (stream->client_aware))
    {
      stream->client_aware = false;
      connection->daemon->notify_completed (connection->daemon->notify_completed_cls,
        connection, &stream->client_context,
        MHD_REQUEST_TERMINATED_COMPLETED_OK);
    }
  }
  MHD_pool_destroy (stream->pool);
  stream->pool = NULL;
  remove_stream (h2, stream);
  free (stream);
}


/* ================================================================ */
/*                      Callbacks for nghttp2                       */
/* ================================================================ */

/**
 * Fill header name/value pair.
 *
 * @param nv    name/value pair
 * @param key   name of header
 * @param value value of header
 */
static void
add_header (nghttp2_nv *nv, const char *key, const char *value)
{
  nv->name = (uint8_t*)key;
  nv->namelen = strlen(key);
  nv->value = (uint8_t*)value;
  nv->valuelen = strlen(value);
  nv->flags = NGHTTP2_NV_FLAG_NONE;
}


/**
 * Callback function invoked when the nghttp2 library wants to
 * read data from the source.
 * Determines the number of bytes that will be in the next DATA frame.
 * Sets NGHTTP2_DATA_FLAG_NO_COPY flag, so data will be read in
 * send_data_callback function (copied directly to connection->write_buffer).
 *
 * @param session    current http2 session
 * @param stream_id  id of stream
 * @param buf        buffer to store the
 * @param length     size of buffer
 * @param data_flags flags of the DATA frame
 * @param source     nghttp2_data_source struct set in build_header_response
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns the number of bytes to read.
 *         Otherwise, returns an error:
 *        - NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE: closes stream by issuing an
 *          RST_STREAM frame with NGHTTP2_INTERNAL_ERROR.
 *        - NGHTTP2_ERR_CALLBACK_FAILURE: session failure.
 */
static ssize_t
response_read_callback (nghttp2_session *session, int32_t stream_id,
                        uint8_t *buf, size_t length, uint32_t *data_flags,
                        nghttp2_data_source *source, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  struct MHD_Response *response;
  ssize_t nread;

  // ENTER("[id=%zu]", h2->session_id);
  /* Get current stream */
  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (stream == NULL)
  {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  response = stream->response;

  /* Check: the DATA frame has to enter in the write_buffer - 10 bytes
     (frame header + padding) */
  length = MHD_MIN (length, h2->connection->write_buffer_size - 10);

  /* Determine number of bytes to read */
  if (response->data_size > 0)
  {
    /* Response in data buffer */
    size_t data_write_offset;
    data_write_offset = (size_t) stream->response_write_position - response->data_start;
    nread = MHD_MIN (length, (ssize_t) (response->data_size - data_write_offset));
  }
  else if (response->total_size == MHD_SIZE_UNKNOWN)
  {
    /* Response size unknown, call the MHD_ContentReaderCallback function */
    mhd_assert (response->crc != NULL);
    MHD_mutex_lock_chk_ (&response->mutex);
    ssize_t ret = response->crc (response->crc_cls,
                                 stream->response_write_position,
                                 response->data, response->data_buffer_size);

    MHD_mutex_unlock_chk_ (&response->mutex);
    if (((ssize_t) MHD_CONTENT_READER_END_WITH_ERROR) == ret)
    {
      /* Error, reset stream */
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    else if (((ssize_t) MHD_CONTENT_READER_END_OF_STREAM) == ret)
    {
      nread = 0;
    }
    else if (0 == ret)
    {
      h2->deferred_stream = stream_id;
      return NGHTTP2_ERR_DEFERRED;
    }
    else
    {
      response->data_size = ret;
      nread = MHD_MIN (length, ret);
    }
  }
  else
  {
    nread = MHD_MIN (length, (ssize_t) (response->total_size - stream->response_write_position));
  }

  /* We will write the complete DATA frame into the write_buffer in function send_data_callback. */
  *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;

  if ((nread == 0) || (response->total_size == stream->response_write_position + nread))
  {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;

    nghttp2_nv *nva;
    size_t nvlen = 0, i = 0;

    /* Count the number of trailers to send */
    struct MHD_HTTP_Header *pos;
    for (pos = response->first_header; NULL != pos; pos = pos->next)
    {
      if (pos->kind == MHD_FOOTER_KIND)
      {
        nvlen++;
      }
    }
    if (nvlen > 0)
    {
      nva = MHD_pool_allocate (stream->pool, sizeof (nghttp2_nv)*nvlen, MHD_YES);
      if (nva == NULL)
        return nread;

      /* Add trailers */
      for (pos = response->first_header; NULL != pos; pos = pos->next)
      {
        if (pos->kind == MHD_FOOTER_KIND)
        {
          add_header(&nva[i++], pos->header, pos->value);
        }
      }
      int rv = nghttp2_submit_trailer(session, stream_id, nva, nvlen);
      if (rv != 0)
      {
        if (nghttp2_is_fatal(rv))
        {
          return NGHTTP2_ERR_CALLBACK_FAILURE;
        }
      }
      else
      {
        *data_flags |= NGHTTP2_DATA_FLAG_NO_END_STREAM;
      }
    }

    if (nghttp2_session_get_stream_remote_close(session, stream_id) == 0)
    {
      nghttp2_submit_rst_stream (session, NGHTTP2_FLAG_NONE,
                                 stream_id, NGHTTP2_NO_ERROR);
    }
  }

  return nread;
}


/**
 * Allocate the stream's name/value headers buffer and fill it with all of the
 * headers (or footers, if we have already sent the body) from the
 * HTTPd's response.
 *
 * @param h2       HTTP/2 session
 * @param stream   current stream
 * @param response response to transmit
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
http2_build_headers (struct http2_conn *h2, struct http2_stream *stream,
                     struct MHD_Response *response)
{
  nghttp2_nv *nva;
  size_t nvlen = 2;
  // ENTER("[id=%zu]", h2->session_id);

  /* Count the number of headers to send */
  struct MHD_HTTP_Header *pos;
  for (pos = response->first_header; NULL != pos; pos = pos->next)
  {
    if (pos->kind == MHD_HEADER_KIND)
    {
      nvlen++;
    }
  }

  /* content-length header */
  if (response->total_size != MHD_SIZE_UNKNOWN)
  {
    nvlen++;
  }

  /* Allocate memory; check if there is enough in the pool */
  nva = MHD_pool_allocate (stream->pool, sizeof (nghttp2_nv)*nvlen, MHD_YES);
  if (nva == NULL)
  {
#ifdef HAVE_MESSAGES
      MHD_DLOG (h2->connection->daemon,
                _("Not enough memory in pool for headers!\n"));
#endif
      return NGHTTP2_ERR_NOMEM;
  }
  size_t i = 0;
  /* Check status code value, to detect programming errors */
  mhd_assert(stream->response_code < sizeof(status_string)/sizeof(status_string[100]));

  /* :status */
  add_header(&nva[i++], ":status", status_string[stream->response_code]);

  /* date */
  char date[128];
  get_date_string (date, sizeof (date), "", "");
  add_header(&nva[i++], "date", date);

  /* content-length */
  char clen[32];
  if (response->total_size != MHD_SIZE_UNKNOWN)
  {
    snprintf(clen, sizeof(clen), "%" PRIu64, response->total_size);
    add_header(&nva[i++], "content-length", clen);
  }

  /* Additional headers */
  for (pos = response->first_header; NULL != pos; pos = pos->next)
  {
    if (pos->kind == MHD_HEADER_KIND)
    {
      add_header(&nva[i++], pos->header, pos->value);
    }
  }

  int r;
  /* Submits response HEADERS frame */
  if (strcmp(MHD_HTTP_METHOD_HEAD, stream->method) == 0)
  {
    r = nghttp2_submit_response(h2->session, stream->stream_id, nva, nvlen, NULL);
  }
  /* HEADERS + DATA frames */
  else
  {
    nghttp2_data_provider data_prd;
    data_prd.source.fd = response->fd;
    data_prd.read_callback = response_read_callback;
    r = nghttp2_submit_response(h2->session, stream->stream_id, nva, nvlen, &data_prd);
  }
  return r;
}


/**
 * Call the handler of the application for this connection.
 * Handles chunking of the upload as well as normal uploads.
 *
 * @param connection        connection we are processing
 * @param stream            stream we are processing
 * @param upload_data       the data being uploaded
 * @param upload_data_size  the size of the upload_data provided
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
http2_call_connection_handler (struct MHD_Connection *connection,
                               struct http2_stream *stream,
                               char *upload_data, size_t *upload_data_size)
{
  if (NULL != stream->response)
    return 0;                     /* already queued a response */
  // ENTER("[id=%zu] method %s url %s", connection->h2->session_id, stream->method, stream->url);
  connection->h2->current_stream_id = stream->stream_id;
  stream->client_aware = true;
  connection->headers_received = stream->headers_received;
  connection->headers_received_tail = stream->headers_received_tail;
  connection->method = stream->method;
  connection->url = stream->url;
  if (MHD_NO ==
      connection->daemon->default_handler (connection->daemon->default_handler_cls,
					   connection, connection->url, connection->method, MHD_HTTP_VERSION_2_0,
					   upload_data, upload_data_size,
					   &stream->client_context))
  {
    /* serious internal error, close stream */
    nghttp2_submit_rst_stream (connection->h2->session, NGHTTP2_FLAG_NONE,
                              stream->stream_id, NGHTTP2_INTERNAL_ERROR);
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }
  return 0;
}


/**
 * Copy the application data to send in the DATA frame into the write_buffer
 * of the connection of the session.
 * Callback function invoked when NGHTTP2_DATA_FLAG_NO_COPY is used in
 * response_read_callback to send complete DATA frame.
 *
 * @param session    current http2 session
 * @param frame      DATA frame to send
 * @param framehd    serialized frame header (9 bytes)
 * @param length     length of application data to send
 * @param source     same pointer passed to response_read_callback
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error:
 *        - NGHTTP2_ERR_WOULDBLOCK: cannot send DATA frame now
 *          (write_buffer doesn't have enough space).
 *        - NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE: closes stream by issuing an
 *          RST_STREAM frame with NGHTTP2_INTERNAL_ERROR.
 *        - NGHTTP2_ERR_CALLBACK_FAILURE: session failure.
 */
static int
send_data_callback (nghttp2_session *session, nghttp2_frame *frame,
                    const uint8_t *framehd, size_t length,
                    nghttp2_data_source *source, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  struct MHD_Connection *connection;
  struct MHD_Response *response;
  char *buffer;
  size_t padlen;
  size_t left;
  size_t pos;
  mhd_assert (h2 != NULL);

  // ENTER("[id=%zu]", h2->session_id);
  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (stream == NULL)
  {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  connection = h2->connection;
  response = stream->response;
  mhd_assert (connection != NULL);
  mhd_assert (response != NULL);

  padlen = frame->data.padlen;

  left = connection->write_buffer_size - connection->write_buffer_append_offset;

  if ((connection->suspended) || (left < 9 + length + padlen)  /* 9 = frame header */)
  {
    return NGHTTP2_ERR_WOULDBLOCK;
  }

  buffer = &connection->write_buffer[connection->write_buffer_append_offset];

  /* Copy header */
  memcpy(buffer, framehd, 9);
  buffer += 9;

  /* Copy padding length */
  if (padlen > 0)
  {
    *buffer = padlen - 1;
    buffer++;
  }

  if (response->data_size > 0)
  {
    /* Buffer response */
    pos = (size_t) stream->response_write_position - response->data_start;
    memcpy(buffer, &response->data[pos], length);
    // ENTER("pos %d len %d", pos, length);
  }
  else if ((response->crc != NULL) && (length > 0))
  {
    /* File or response size known */
    MHD_mutex_lock_chk_ (&response->mutex);
    ssize_t ret = response->crc (response->crc_cls,
                                 stream->response_write_position,
                                 buffer, length);
    MHD_mutex_unlock_chk_ (&response->mutex);
    if ((((ssize_t) MHD_CONTENT_READER_END_OF_STREAM) == ret) ||
        (((ssize_t) MHD_CONTENT_READER_END_WITH_ERROR) == ret))
    {
      response->total_size = stream->response_write_position;

      /* error, close stream */
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
  }

  *(buffer + length) = 0;
  ENTER("%s", buffer);

  /* Set padding */
  if (padlen > 0)
  {
    buffer += length;
    memset(buffer, 0, padlen - 1);
  }

  // ENTER("size:%d pos %d len %d", connection->write_buffer_size, stream->response_write_position, length);
  stream->response_write_position += length;

  /* Reset data buffer */
  if ((response->total_size == MHD_SIZE_UNKNOWN) &&
      ((stream->response_write_position - response->data_start) == response->data_size))
  {
    response->data_size = 0;
    response->data_start = stream->response_write_position;
  }

  connection->write_buffer_append_offset += 9 + (padlen > 0) + length;
  return 0;
}


/**
 * A chunk of data in a DATA frame is received.
 * Call the handler of the application for this stream.
 * Handles chunking of the upload as well as normal uploads.
 *
 * @param session    current http2 session
 * @param flags      flags of the DATA frame
 * @param stream_id  id of stream
 * @param data       data
 * @param len        length of data
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_data_chunk_recv_callback (nghttp2_session *session, uint8_t flags,
                             int32_t stream_id, const uint8_t *data,
                             size_t len, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  mhd_assert (h2 != NULL);
  // ENTER("[id=%zu] len: %zu", h2->session_id, len);

  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (stream == NULL)
    return 0;

  return http2_call_connection_handler (h2->connection, stream,
                                        (char *)data, &len);
}


/**
 * A frame was received. If it is a DATA or HEADERS frame,
 * we pass the request to the MHD application.
 *
 * @param session    current http2 session
 * @param frame      frame received
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_frame_recv_callback (nghttp2_session *session,
                        const nghttp2_frame *frame, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  ENTER("[id=%zu] recv %s frame <length=%zu, flags=0x%02X, stream_id=%u>", h2->session_id, FRAME_TYPE (frame->hd.type), frame->hd.length, frame->hd.flags, frame->hd.stream_id);
  if (frame->hd.flags) print_flags(frame->hd);

  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (stream == NULL)
    return 0;

  switch (frame->hd.type)
  {
    case NGHTTP2_HEADERS:
      if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
      {
        /* First call */
        size_t unused = 0;
        int ret = http2_call_connection_handler (h2->connection, stream, NULL, &unused);
        if (ret != 0)
          return ret;
        if (need_100_continue (h2->connection))
        {
          nghttp2_nv nva;
          add_header(&nva, ":status", status_string[100]);
          nghttp2_submit_headers (session, NGHTTP2_FLAG_NONE, stream->stream_id,
                                  NULL, &nva, 1, NULL);
        }
      }
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      {
        /* Final call to application handler: GET, HEAD requests */

        size_t unused = 0;
        return http2_call_connection_handler (h2->connection, stream, NULL, &unused);
      }
      break;
    case NGHTTP2_DATA:
      /* Check that the client request has finished */
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      {
        /* Final call to application handler: POST, PUT requests */
        size_t unused = 0;
        return http2_call_connection_handler (h2->connection, stream, NULL, &unused);
      }
      break;
  }
  return 0;
}


/**
 * Frame was sent. Only for debugging purposes.
 *
 * @param session    current http2 session
 * @param frame      frame sent
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
int
on_frame_send_callback (nghttp2_session *session,
                        const nghttp2_frame *frame, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  ENTER("[id=%zu] send %s frame <length=%zu, flags=0x%02X, stream_id=%u>", h2->session_id, FRAME_TYPE (frame->hd.type), frame->hd.length, frame->hd.flags, frame->hd.stream_id);

  MHD_update_last_activity_ (h2->connection);
  return 0;
}


/**
 * The reception of a header block in HEADERS or PUSH_PROMISE is started.
 *
 * @param session    current http2 session
 * @param frame      frame received
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_begin_headers_callback (nghttp2_session *session,
                           const nghttp2_frame *frame, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  // ENTER("[id=%zu]", h2->session_id);

  if ((frame->hd.type != NGHTTP2_HEADERS) ||
      (frame->headers.cat != NGHTTP2_HCAT_REQUEST))
  {
    return 0;
  }

  stream = http2_stream_create (h2, frame->hd.stream_id);
  if (stream == NULL)
  {
    // Out of memory.
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  stream->pool = MHD_pool_create (h2->connection->daemon->pool_size);
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id, stream);
  return 0;
}


/**
 * Library provides the error message. Only for debugging purposes.
 *
 * @param session  current http2 session
 * @param msg  error message
 * @param len  length of msg
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
error_callback (nghttp2_session *session,
                const char *msg, size_t len,
                void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  mhd_assert (h2 != NULL);
  ENTER("[id=%zu] %s", h2->session_id, msg);
  return 0;
}


/**
 * Invalid frame received. Only for debugging purposes.
 *
 * @param session    current http2 session
 * @param frame      frame sent
 * @param error_code reason of closure
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_invalid_frame_recv_callback (nghttp2_session *session,
                                const nghttp2_frame *frame,
                                int error_code,
                                void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  mhd_assert (h2 != NULL);
  ENTER("[id=%zu] INVALID: %s", h2->session_id, nghttp2_strerror(error_code));
  return 0;
}


/**
 * Add an entry to the HTTP headers of a connection.
 *
 * @param connection the connection for which a value should be set
 * @param kind       kind of the value
 * @param key        key for the value
 * @param value      the value itself
 * @return #MHD_NO on failure (out of memory), #MHD_YES for success
 */
static int
http2_connection_add_header (struct MHD_Connection *connection,
                             const char *key, const char *value,
                             enum MHD_ValueKind kind)
{
  if (MHD_NO == MHD_set_connection_value (connection, kind, key, value))
  {
#ifdef HAVE_MESSAGES
    MHD_DLOG (connection->daemon,
                _("Not enough memory in pool to allocate header record!\n"));
#endif
    return MHD_NO;
  }
  return MHD_YES;
}


/**
 * Parse the cookie header (see RFC 2109).
 *
 * @param connection connection to parse header of
 * @param stream     stream we are processing
 * @param value      cookie header value
 * @param valuelen   length of cookie header value
 * @return #MHD_YES for success, #MHD_NO for failure (malformed, out of memory)
 */
static int
http2_parse_cookie_header (struct MHD_Connection *connection,
                           struct http2_stream *stream,
                           const char *value, size_t valuelen)
{
  char *pos;
  char *sce;
  char *ekill;
  char *equals;
  char *semicolon;
  char old;
  int quotes;

  pos = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
  if (NULL == pos)
  {
#ifdef HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                _("Not enough memory in pool to parse cookies!\n"));
#endif
      return MHD_NO;
  }
  memcpy (pos, value, valuelen + 1);

  while (NULL != pos)
  {
    while (' ' == *pos)
      pos++;                  /* skip spaces */

    sce = pos;
    while ( ((*sce) != '\0') &&
            ((*sce) != ',') &&
            ((*sce) != ';') &&
            ((*sce) != '=') )
      sce++;
    /* remove tailing whitespace (if any) from key */
    ekill = sce - 1;
    while ((*ekill == ' ') && (ekill >= pos))
      *(ekill--) = '\0';
    old = *sce;
    *sce = '\0';
    if (old != '=')
    {
        /* value part omitted, use empty string... */
        if (MHD_NO == http2_connection_add_header (connection, pos, "", MHD_COOKIE_KIND))
          return MHD_NO;
        if (old == '\0')
          break;
        pos = sce + 1;
        continue;
    }
    equals = sce + 1;
    quotes = 0;
    semicolon = equals;
    while (('\0' != semicolon[0]) &&
           ((0 != quotes) || ((';' != semicolon[0]) &&
           (',' != semicolon[0]))))
    {
        if ('"' == semicolon[0])
          quotes = (quotes + 1) & 1;
        semicolon++;
    }
    if ('\0' == semicolon[0])
      semicolon = NULL;
    if (NULL != semicolon)
    {
      semicolon[0] = '\0';
      semicolon++;
    }
    /* remove quotes */
    if (('"' == equals[0]) && ('"' == equals[strlen (equals) - 1]))
    {
      equals[strlen (equals) - 1] = '\0';
      equals++;
    }
    if (MHD_NO == http2_connection_add_header (connection, pos, equals, MHD_COOKIE_KIND))
      return MHD_NO;
    pos = semicolon;
  }
  return MHD_YES;
}


/**
 * A header name/value pair is received for the frame.
 *
 * @param session  current http2 session
 * @param frame    frame received
 * @param name     header name
 * @param namelen  length of header name
 * @param value    header value
 * @param valuelen length of header value
 * @param flags    flags for header field name/value pair
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_header_callback (nghttp2_session *session, const nghttp2_frame *frame,
                    const uint8_t *name,  size_t namelen,
                    const uint8_t *value, size_t valuelen,
                    uint8_t flags, void *user_data)
{
  (void)flags;
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  ENTER("[id=%zu] %s: %s", h2->session_id, name, value);

  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (stream == NULL)
  {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if ((namelen == H2_HEADER_METHOD_LEN) &&
      (strncmp(H2_HEADER_METHOD, name, namelen) == 0))
  {
      stream->method = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->method)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      strcpy(stream->method, value);
  }
  else if ((namelen == H2_HEADER_SCHEME_LEN) &&
      (strncmp(H2_HEADER_SCHEME, name, namelen) == 0))
  {
      stream->scheme = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->scheme)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      strcpy(stream->scheme, value);
  }
  else if ((namelen == H2_HEADER_PATH_LEN) &&
      (strncmp(H2_HEADER_PATH, name, namelen) == 0))
  {
      stream->path = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->path)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      strcpy(stream->path, value);

      /* Process the URI. See MHD_OPTION_URI_LOG_CALLBACK */
      struct MHD_Connection *connection = h2->connection;
      if (NULL != connection->daemon->uri_log_callback)
      {
        stream->client_aware = true;
        stream->client_context
            = connection->daemon->uri_log_callback (connection->daemon->uri_log_callback_cls,
                                                    stream->path, connection);
      }
      char *args;
      args = memchr (value, '?', valuelen);

      if (NULL != args)
      {
        args[0] = '\0';
        size_t argslen = valuelen - 1;
        valuelen = (size_t)(args - (char *) value);
        argslen -= valuelen;
        args++;

        // TODO
        // char *fragment = memchr (args, '#', argslen);
        // if (NULL != fragment)
        // {
        //   fragment[0] = '\0';
        //   argslen = (size_t)(fragment - (char *) args);
        // }

        stream->query = MHD_pool_allocate (stream->pool, argslen + 1, MHD_YES);
        if (NULL == stream->query)
          return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        strcpy(stream->query, args);

        /* note that this call clobbers 'query' */
        unsigned int unused_num_headers;
        connection->headers_received = stream->headers_received;
        connection->headers_received_tail = stream->headers_received_tail;

        MHD_parse_arguments_ (connection, MHD_GET_ARGUMENT_KIND, stream->query,
          &http2_connection_add_header, &unused_num_headers);

        stream->headers_received = connection->headers_received;
        stream->headers_received_tail = connection->headers_received_tail;
      }

      /* Absolute path */
      stream->url = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->url)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      strcpy(stream->url, value);

      /* Decode %HH */
      if (NULL != stream->url)
      {
        connection->daemon->unescape_callback (connection->daemon->unescape_callback_cls,
                                   connection, stream->url);
      }
  }
  else if ((namelen == H2_HEADER_AUTH_LEN) &&
      (strncmp(H2_HEADER_AUTH, name, namelen) == 0))
  {
      stream->authority = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->authority)
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      strcpy(stream->authority, value);
  }
  else
  {
    /* Add an entry to the HTTP headers of a stream. */
    struct MHD_Connection *connection = h2->connection;
    connection->headers_received = stream->headers_received;
    connection->headers_received_tail = stream->headers_received_tail;

    enum MHD_ValueKind kind = MHD_HEADER_KIND;
    if ((namelen == H2_HEADER_COOKIE_LEN) &&
        (strncmp(H2_HEADER_COOKIE, name, namelen) == 0))
    {
      kind = MHD_COOKIE_KIND;
      http2_parse_cookie_header (connection, stream, value, valuelen);
    }

    char *key = MHD_pool_allocate (stream->pool, namelen + 1, MHD_YES);
    char *val = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);

    if ((NULL == key) || (NULL == val))
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    strcpy(key, name);
    strcpy(val, value);

    if (MHD_NO == http2_connection_add_header (connection, key, val, kind))
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;

    stream->headers_received = connection->headers_received;
    stream->headers_received_tail = connection->headers_received_tail;
  }
  return 0;
}


/**
 * Stream is closed. If there was an error, a RST stream is sent.
 *
 * @param session    current http2 session
 * @param stream_id  id of stream
 * @param error_code reason of closure
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_stream_close_callback (nghttp2_session *session, int32_t stream_id,
                          uint32_t error_code, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  (void)error_code;
  // ENTER("[id=%zu] stream_id=%zu", h2->session_id, stream_id);

  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (stream != NULL)
  {
    if (error_code)
    {
      ENTER("[stream_id=%d] Closing with err=%s", stream_id, nghttp2_strerror(error_code));
      nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                stream_id, error_code);
    }
    http2_stream_delete (h2, stream);
  }
  return 0;
}


/* ================================================================ */
/*                      HTTP2 helper functions                      */
/* ================================================================ */

/**
 * Set local session settings and callbacks.
 *
 * @param connection connection of the session
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
static int
http2_session_init (struct MHD_Connection *connection)
{
  mhd_assert (connection != NULL && connection->daemon != NULL);

  struct http2_conn *h2 = connection->h2;
  mhd_assert (h2 != NULL);

  h2->session_id = num_sessions++;

  /* Set initial local session settings */
  h2->settings = connection->daemon->h2_settings;
  h2->settings_len = connection->daemon->h2_settings_len;

  /* Set reference to connection */
  h2->connection = connection;

  /* Allocate read and write buffers */
  size_t size;
  size = MHD_MIN((1<<13), connection->daemon->pool_size / 2);
  connection->read_buffer = MHD_pool_allocate (connection->pool,
                                               size, MHD_NO);
  if (NULL == connection->read_buffer)
    return MHD_NO;
  connection->read_buffer_size = size;

  size = MHD_MIN((1<<16), connection->daemon->pool_size / 2);
  connection->write_buffer = MHD_pool_allocate (connection->pool,
                                                size, MHD_NO);
  if (NULL == connection->write_buffer)
    return MHD_NO;
  connection->write_buffer_size = size;

  int rv;
  nghttp2_session_callbacks *callbacks;

  rv = nghttp2_session_callbacks_new (&callbacks);
  if (rv != 0)
  {
    mhd_assert (rv == NGHTTP2_ERR_NOMEM);
    return MHD_NO;
  }

  nghttp2_session_callbacks_set_on_frame_recv_callback (
    callbacks, on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback (
    callbacks, on_frame_send_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback (
    callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback (
    callbacks, on_header_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback (
    callbacks, on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback (
    callbacks, on_invalid_frame_recv_callback);

  nghttp2_session_callbacks_set_error_callback (
    callbacks, error_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback (
    callbacks, on_begin_headers_callback);

  nghttp2_session_callbacks_set_send_data_callback(
    callbacks, send_data_callback);

  rv = nghttp2_session_server_new (&h2->session, callbacks, h2);
  if (rv != 0)
  {
    mhd_assert (rv == NGHTTP2_ERR_NOMEM);
    return MHD_NO;
  }

  nghttp2_session_callbacks_del (callbacks);
  return MHD_YES;
}


/**
 * Send HTTP/2 server connection preface.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
static int
http2_session_send_preface (struct http2_conn *h2)
{
  int rv;
  // ENTER("[id=%zu]", h2->session_id);

  /* Flags currently ignored */
  rv = nghttp2_submit_settings (h2->session, NGHTTP2_FLAG_NONE,
                                h2->settings, h2->settings_len);
  if (rv != 0)
  {
    warnx("Fatal error: %s", nghttp2_strerror (rv));
    return MHD_NO;
  }
  return MHD_YES;
}


/**
 * Sends at most length bytes of data stored in data.
 *
 * @param session    session
 * @param user_data  HTTP2 connection of type http2_conn
 * @return If succeeds, returns the number of bytes sent.
 *         Otherwise, if it cannot send any single byte without blocking,
 *         it returns NGHTTP2_ERR_WOULDBLOCK.
 *         For other errors, it returns NGHTTP2_ERR_CALLBACK_FAILURE.
 */
static int
http2_fill_write_buffer (nghttp2_session *session, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  mhd_assert (h2 != NULL);
  struct MHD_Connection *connection = h2->connection;

  // ENTER("[id=%zu]", h2->session_id);
  /* If there is pending data from previous nghttp2_session_mem_send call */
  if (h2->data_pending)
  {
    ENTER("h2->data_pending=%zu", h2->data_pending_len);
    size_t left = connection->write_buffer_size - connection->write_buffer_append_offset;
    size_t n = MHD_MIN(left, h2->data_pending_len);

    memcpy(&connection->write_buffer[connection->write_buffer_append_offset], h2->data_pending, n);
    connection->write_buffer_append_offset += n;

    if (n < h2->data_pending_len)
    {
      h2->data_pending += n;
      h2->data_pending_len -= n;
      return 0;
    }
    h2->data_pending = NULL;
    h2->data_pending_len = 0;
  }

  for (;;)
  {
    const uint8_t *data;
    ssize_t data_len;
    data_len = nghttp2_session_mem_send(session, &data);

    if (data_len < 0)
      return -1;

    if (data_len == 0)
      break;
// for (int i = 0; i < data_len; i++) {
//   fprintf(stderr, "%02X ", data[i]);
// }
// fprintf(stderr, "\n");

    size_t left = connection->write_buffer_size - connection->write_buffer_append_offset;
    size_t n = MHD_MIN(left, data_len);
// ENTER("size=%d append=%d n=%d left=%d data_len=%d", connection->write_buffer_size, connection->write_buffer_append_offset, n, left, data_len);
    memcpy(&connection->write_buffer[connection->write_buffer_append_offset], data, n);
    connection->write_buffer_append_offset += n;

    /* Not enough space in write_buffer for all data */
    if (n < data_len)
    {
      h2->data_pending = data + n;
      h2->data_pending_len = data_len - n;
      break;
    }
  }
  return 0;
}


/* ================================================================ */
/*                          HTTP2 MHD API                           */
/* ================================================================ */

/**
 * Delete HTTP2 structures.
 *
 * @param connection connection to handle
 */
void
MHD_http2_session_delete (struct MHD_Connection *connection)
{
  struct http2_conn *h2 = connection->h2;
  struct http2_stream *stream;

  if (h2 == NULL) return;
  // ENTER("[id=%zu]", h2->session_id);

  for (stream = h2->streams; h2->num_streams > 0 && stream != NULL; )
  {
    struct http2_stream *next = stream->next;
    http2_stream_delete (h2, stream);
    stream = next;
  }

  nghttp2_session_del (h2->session);
  free (h2);
  connection->h2 = NULL;
  connection->state = MHD_CONNECTION_HTTP2_CLOSED;
  MHD_pool_destroy (connection->pool);
  connection->pool = NULL;
  connection->read_buffer = NULL;
  connection->read_buffer_size = 0;
  connection->write_buffer = NULL;
  connection->write_buffer_size = 0;
}


/**
 * Initialize HTTP2 structures, set the initial local settings for the session,
 * and send server preface.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_session_start (struct MHD_Connection *connection)
{
  int rv;

  if (connection->h2 != NULL) return MHD_YES;
  connection->h2 = calloc (1, sizeof (struct http2_conn));
  if (connection->h2 == NULL)
  {
    connection->state = MHD_CONNECTION_HTTP2_CLOSED;
    return MHD_NO;
  }

  /* Create session and fill callbacks */
  rv = http2_session_init (connection);
  if (rv != MHD_YES)
  {
    MHD_http2_session_delete (connection);
    return MHD_NO;
  }

  // ENTER("[id=%zu]", connection->h2->session_id);

  /* Send server preface */
  rv = http2_session_send_preface (connection->h2);
  if (rv != MHD_YES)
  {
    MHD_http2_session_delete (connection);
    return MHD_NO;
  }

  connection->version = MHD_HTTP_VERSION_2_0;

  connection->state = MHD_CONNECTION_HTTP2_IDLE;
  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */

  return MHD_YES;
}


/**
 * Read data from the connection.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_handle_read (struct MHD_Connection *connection)
{
  if (connection->state == MHD_CONNECTION_HTTP2_INIT)
  {
    return MHD_NO;
  }
  struct http2_conn *h2 = connection->h2;
  if (h2 == NULL) return MHD_NO;
  // ENTER("[id=%zu]", h2->session_id);

  connection->state = MHD_CONNECTION_HTTP2_BUSY;

  for (;;)
  {
    ssize_t bytes_read;
    bytes_read = connection->recv_cls (connection,
                                       connection->read_buffer,
                                       connection->read_buffer_size);
    // ENTER("read %d / %d", bytes_read, connection->read_buffer_size);
    if (bytes_read < 0)
    {
      if (bytes_read == MHD_ERR_AGAIN_)
         break; /* No new data to process. */
      if (bytes_read == MHD_ERR_CONNRESET_)
      {
        connection_close_error (connection,
                                _("Socket is unexpectedly disconnected when reading request.\n"));
        return MHD_NO;
      }
      connection_close_error (connection,
                              _("Connection socket is closed due to unexpected error when reading request.\n"));
      return MHD_NO;
    }

    /* Remote side closed connection. */
    if (bytes_read == 0)
    {
      connection->read_closed = true;
      MHD_connection_close_ (connection,
                             MHD_REQUEST_TERMINATED_CLIENT_ABORT);
      return MHD_NO;
    }

    MHD_update_last_activity_ (connection);

    ssize_t rv;
    rv = nghttp2_session_mem_recv (h2->session, connection->read_buffer, bytes_read);
    if (rv < 0)
    {
      if (rv != NGHTTP2_ERR_BAD_CLIENT_MAGIC)
      {
        warnx("nghttp2_session_mem_recv () returned error: %s %zd", nghttp2_strerror (rv), rv);
      }
      /* Should send a GOAWAY frame with last stream_id successfully received */
      nghttp2_submit_goaway(h2->session, NGHTTP2_FLAG_NONE, h2->accepted_max,
                            NGHTTP2_PROTOCOL_ERROR, NULL, 0);
      // nghttp2_session_send(h2->session);
      // MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
      // return MHD_NO;
      break;
    }
  }
  connection->state = MHD_CONNECTION_HTTP2_IDLE;
  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */

  return MHD_YES;
}


/**
 * Write data to the connection.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_handle_write (struct MHD_Connection *connection)
{
  struct http2_conn *h2 = connection->h2;
  if (h2 == NULL) return MHD_NO;
  // ENTER("[id=%zu]", h2->session_id);

  connection->state = MHD_CONNECTION_HTTP2_BUSY;

  for (;;)
  {
    // ENTER("write_buffer send=%d append=%d = %d", connection->write_buffer_send_offset, connection->write_buffer_append_offset, connection->write_buffer_append_offset - connection->write_buffer_send_offset);
    if (connection->write_buffer_append_offset - connection->write_buffer_send_offset > 0)
    {
      ssize_t ret;
      ret = connection->send_cls (connection,
                                  &connection->write_buffer
                                  [connection->write_buffer_send_offset],
                                  connection->write_buffer_append_offset -
                                    connection->write_buffer_send_offset);
      // ENTER("send_cls ret=%d", ret);
      if (ret < 0)
      {
        if (MHD_ERR_AGAIN_ == ret)
        {
          /* TODO: Transmission could not be accomplished. Try again. */
          connection->state = MHD_CONNECTION_HTTP2_IDLE;
          ENTER(" =================== ADD WRITE EVENT ================== ret=%zd", ret);
          return MHD_YES;
        }
        MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
        return MHD_NO;
      }
      connection->write_buffer_send_offset += ret;
      MHD_update_last_activity_ (connection);
      continue;
    }

    /* Reset offsets */
    connection->write_buffer_append_offset = 0;
    connection->write_buffer_send_offset = 0;

    /* FILL WRITE BUFFER */
    if (http2_fill_write_buffer(h2->session, h2) != 0)
    {
      MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
      return MHD_NO;
    }

    // ENTER("http2_fill_write_buffer: send=%d append=%d = %d", connection->write_buffer_send_offset, connection->write_buffer_append_offset, connection->write_buffer_append_offset - connection->write_buffer_send_offset);

    /* Nothing to write */
    if (connection->write_buffer_append_offset - connection->write_buffer_send_offset == 0)
      break;
  }

  /* Nothing to write */
  if (connection->write_buffer_append_offset - connection->write_buffer_send_offset == 0)
  {

  }
  else
  {
    /* TODO: Add new write event */
    ENTER(" =================== ADD WRITE EVENT2 ==================");
  }

  if ((nghttp2_session_want_read (h2->session) == 0) &&
      (nghttp2_session_want_write (h2->session) == 0) &&
      (connection->write_buffer_append_offset - connection->write_buffer_send_offset == 0))
  {
    MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_COMPLETED_OK);
    return MHD_NO;
  }
  MHD_update_last_activity_ (connection);
  connection->state = MHD_CONNECTION_HTTP2_IDLE;
  connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */
  return MHD_YES;
}


/**
 * Process data.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
MHD_http2_handle_idle (struct MHD_Connection *connection)
{
  if (connection->state == MHD_CONNECTION_HTTP2_INIT)
  {
    if (MHD_http2_session_start (connection) != MHD_YES)
    {
      /* Error, close connection */
      connection_close_error (connection,
          _("Closing connection (failed to send server connection preface)\n"));
      return MHD_NO;
    }
  }
  // ENTER("[id=%zu]", connection->h2->session_id);
  if (connection->write_buffer_append_offset - connection->write_buffer_send_offset != 0)
  {
    MHD_update_last_activity_ (connection);
    connection->state = MHD_CONNECTION_HTTP2_IDLE;
    connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
#ifdef EPOLL_SUPPORT
    MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */
  }

  /* TODO: resume all deferred streams */
  if (connection->h2->deferred_stream > 0)
  {
    nghttp2_session_resume_data(connection->h2->session, connection->h2->deferred_stream);
  }

  return MHD_YES;
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
MHD_http2_queue_response (struct MHD_Connection *connection,
                          unsigned int status_code,
                          struct MHD_Response *response)
{
  struct http2_conn *h2 = connection->h2;
  struct http2_stream *stream;

  mhd_assert (h2 != NULL);
  // ENTER("[id=%zu]", connection->h2->session_id);

  stream = nghttp2_session_get_stream_user_data (h2->session, h2->current_stream_id);
  if (stream == NULL)
  {
    return MHD_NO;
  }

  MHD_increment_response_rc (response);
  stream->response = response;
  stream->response_code = status_code;

  if ( ( (NULL != stream->method) &&
         (MHD_str_equal_caseless_ (stream->method,
                                   MHD_HTTP_METHOD_HEAD)) ) ||
       (MHD_HTTP_OK > status_code) ||
       (MHD_HTTP_NO_CONTENT == status_code) ||
       (MHD_HTTP_NOT_MODIFIED == status_code) )
    {
      /* if this is a "HEAD" request, or a status code for
         which a body is not allowed, pretend that we
         have already sent the full message body. */
      stream->response_write_position = response->total_size;
    }

  int r = http2_build_headers(h2, stream, response);
  if (r != 0)
  {
    return MHD_NO;
  }

  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */
  return MHD_YES;
}

#endif /* HTTP2_SUPPORT */

/* end of connection_http2.c */
