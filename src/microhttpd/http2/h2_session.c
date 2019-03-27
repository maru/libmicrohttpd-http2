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
 * @file microhttpd/http2/h2_session.c
 * @brief Session functions for h2 connections.
 * @author Maru Berezin
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"
#include "base64.h"
#include "connection.h"
#include "memorypool.h"
#include "mhd_str.h"

#define H2_HEADER_METHOD     ":method"
#define H2_HEADER_METHOD_LEN 7
#define H2_HEADER_SCHEME     ":scheme"
#define H2_HEADER_SCHEME_LEN 7
#define H2_HEADER_AUTH       ":authority"
#define H2_HEADER_AUTH_LEN   10
#define H2_HEADER_PATH       ":path"
#define H2_HEADER_PATH_LEN   5
#define H2_HEADER_COOKIE     "cookie"
#define H2_HEADER_COOKIE_LEN 6
#define H2_HEADER_CONTENT_LENGTH     "content-length"
#define H2_HEADER_CONTENT_LENGTH_LEN 14

/* Number of sessions, for debugging purposes */
size_t num_sessions = 0;

char status_string[600][4] = {
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "100", "101", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "200", "201", "202", "203", "204", "205", "206", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "300", "301", "302", "303", "304", "305", "306", "307", "308", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "400", "401", "402", "403", "404", "405", "406", "407", "408", "409",
 "410", "411", "412", "413", "414", "415", "416", "417", "", "",
 "", "421", "", "", "", "", "426", "", "428", "429", "", "431", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "451", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "500", "501", "502", "503", "504", "505", "", "", "", "", "", "511", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "",
 "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "", "" };

 int
 h2_transmit_error_response (struct h2_session_t *h2, struct h2_stream_t *stream);


 /**
  * Delete HTTP2 structures.
  *
  * @param h2 HTTP/2 session to handle
  */
 void
 h2_session_destroy (struct h2_session_t *h2)
 {
   mhd_assert (NULL != h2);
   // h2_debug_vprintf ("[id=%zu]", h2->session_id);

   struct h2_stream_t *stream;
   for (stream = h2->streams; h2->num_streams > 0 && stream != NULL; )
     {
       struct h2_stream_t *next = stream->next;
       h2_stream_destroy (stream);
       stream = next;
     }

   if (NULL != h2->session)
     {
       nghttp2_session_del (h2->session);
       h2->session = NULL;
     }

   free (h2);
 }


 /**
  * Add a stream to the end of the stream list.
  *
  * @param h2 HTTP/2 session
  * @param stream new stream to add to the session
  */
 static void
 h2_session_add_stream (struct h2_session_t *h2, struct h2_stream_t *stream)
 {
   mhd_assert (h2 != NULL && stream != NULL);

   // First element
   if (NULL == h2->streams)
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
h2_session_remove_stream (struct h2_session_t *h2,
                          struct h2_stream_t *stream)
{
  mhd_assert (h2->num_streams > 0);
  h2->num_streams--;

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

  h2_stream_destroy (stream);
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
  * @return If succeeds, returns 0. Otherwise, returns an error.
  */
 int
 h2_connection_stream_add_header (struct MHD_Connection *connection,
                       struct h2_session_t *h2, struct h2_stream_t *stream,
                       const uint8_t *name, const size_t namelen,
                       const uint8_t *value, const size_t valuelen)
 {
   connection->headers_received = stream->headers_received;
   connection->headers_received_tail = stream->headers_received_tail;

   enum MHD_ValueKind kind = MHD_HEADER_KIND;
   if ((namelen == H2_HEADER_COOKIE_LEN) &&
       (strncmp(H2_HEADER_COOKIE, name, namelen) == 0))
     {
       kind = MHD_COOKIE_KIND;
       h2_stream_parse_cookie_header (connection, stream, value, valuelen);
     }

   char *key = MHD_pool_allocate (stream->pool, namelen + 1, MHD_YES);
   char *val = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);

   if ((NULL == key) || (NULL == val))
     {
       stream->response_code = MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
       return h2_transmit_error_response (h2, stream);
     }

   strncpy (key, name, namelen + 1);
   strncpy (val, value, valuelen + 1);

   connection->pool = stream->pool;

   int r = MHD_set_connection_value (connection, kind, key, val);

   stream->pool = connection->pool;
   stream->headers_received = connection->headers_received;
   stream->headers_received_tail = connection->headers_received_tail;

   if (MHD_NO == r)
     {
     #ifdef HAVE_MESSAGES
       MHD_DLOG (connection->daemon,
                   _("Not enough memory in pool to allocate header record!\n"));
     #endif
       return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
     }

   return 0;
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
 * @param user_data  HTTP2 connection of type h2_session_t
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
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  struct MHD_Response *response;
  ssize_t nread;

  // h2_debug_vprintf ("[id=%zu]", h2->session_id);
  /* Get current stream */
  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (NULL == stream)
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
      // h2->deferred_stream = stream_id;
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
      if (NULL == nva)
        return nread;

      /* Add trailers */
      for (pos = response->first_header; NULL != pos; pos = pos->next)
      {
        if (pos->kind == MHD_FOOTER_KIND)
        {
          add_header (&nva[i++], pos->header, pos->value);
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
int
h2_session_build_stream_headers (struct h2_session_t *h2, struct h2_stream_t *stream,
                  struct MHD_Response *response)
{
  nghttp2_nv *nva;
  size_t nvlen = 2;
  // h2_debug_vprintf ("[id=%zu]", h2->session_id);

  /* Count the number of headers to send */
  struct MHD_HTTP_Header *pos;
  if (NULL != response)
    {
      for (pos = response->first_header; NULL != pos; pos = pos->next)
        {
          if (pos->kind == MHD_HEADER_KIND)
            nvlen++;
        }

      /* content-length header */
      if (response->total_size != MHD_SIZE_UNKNOWN)
        nvlen++;
    }
  /* Allocate memory; check if there is enough in the pool */
  nva = MHD_pool_allocate (stream->pool, sizeof (nghttp2_nv)*nvlen, MHD_YES);
  if (NULL == nva)
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (h2->connection->daemon,
                _("Not enough memory in pool for headers!\n"));
#endif
      return NGHTTP2_ERR_NOMEM;
    }
  size_t i = 0;
  /* Check status code value, to detect programming errors */
  mhd_assert (stream->response_code < sizeof(status_string)/sizeof(status_string[100]));

  /* :status */
  add_header (&nva[i++], ":status", status_string[stream->response_code]);

  /* date */
  char date[128];
  get_date_string (date, sizeof (date), "", "");
  add_header (&nva[i++], "date", date);

  /* content-length */
  char clen[32];
  if (NULL != response)
    {
      if (response->total_size != MHD_SIZE_UNKNOWN)
        {
          snprintf (clen, sizeof(clen), "%" PRIu64, response->total_size);
          add_header (&nva[i++], "content-length", clen);
        }

      /* Additional headers */
      for (pos = response->first_header; NULL != pos; pos = pos->next)
        {
          if (pos->kind == MHD_HEADER_KIND)
            add_header (&nva[i++], pos->header, pos->value);
        }
    }

  int r;
  if ((strcmp (MHD_HTTP_METHOD_HEAD, stream->method) == 0) || (NULL == response))
    {
      /* Only HEADERS frame */
      r = nghttp2_submit_response (h2->session, stream->stream_id, nva, nvlen, NULL);
    }
  else
    {
      /* HEADERS + DATA frames */
      nghttp2_data_provider data_prd;
      data_prd.source.fd = response->fd;
      data_prd.read_callback = response_read_callback;
      r = nghttp2_submit_response (h2->session, stream->stream_id, nva, nvlen, &data_prd);
    }
  return r;
}


/**
 * We encountered an error processing the request.
 * Send the indicated response code and message.
 *
 * @param h2       HTTP/2 session
 * @param stream   current stream
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
int
h2_transmit_error_response (struct h2_session_t *h2, struct h2_stream_t *stream)
{
  return h2_session_build_stream_headers (h2, stream, NULL);
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
h2_call_connection_handler (struct MHD_Connection *connection,
                               struct h2_stream_t *stream,
                               char *upload_data, size_t *upload_data_size)
{
  if ((NULL != stream->response) || (stream->response_code != 0))
    return 0;                     /* already queued a response */
  // h2_debug_vprintf ("[id=%zu] method %s url %s", connection->h2->session_id, stream->method, stream->url);
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
 * @param user_data  HTTP2 connection of type h2_session_t
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
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  struct MHD_Connection *connection;
  struct MHD_Response *response;
  char *buffer;
  size_t padlen;
  size_t left;
  size_t pos;
  mhd_assert (h2 != NULL);

  // h2_debug_vprintf ("[id=%zu]", h2->session_id);
  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (NULL == stream)
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
    // h2_debug_vprintf ("pos %d len %d", pos, length);
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
  h2_debug_vprintf ("%s", buffer);

  /* Set padding */
  if (padlen > 0)
  {
    buffer += length;
    memset(buffer, 0, padlen - 1);
  }

  // h2_debug_vprintf ("size:%d pos %d len %d", connection->write_buffer_size, stream->response_write_position, length);
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
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_data_chunk_recv_callback (nghttp2_session *session, uint8_t flags,
                             int32_t stream_id, const uint8_t *data,
                             size_t len, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  mhd_assert (h2 != NULL);
  // h2_debug_vprintf ("[id=%zu] len: %zu", h2->session_id, len);

  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (NULL == stream)
    return 0;

  size_t available = len;
  size_t to_be_processed;
  size_t left_unprocessed;
  size_t processed_size;

  if ((0 != stream->remaining_upload_size) &&
      (MHD_SIZE_UNKNOWN != stream->remaining_upload_size) &&
      (stream->remaining_upload_size < available) )
    {
      to_be_processed = (size_t)stream->remaining_upload_size;
    }
  else
    {
      to_be_processed = available;
    }
  left_unprocessed = to_be_processed;
  int r = h2_call_connection_handler (h2->connection, stream,
                                        (char *)data, &left_unprocessed);
  if (r != 0)
    return r;

  if (left_unprocessed > to_be_processed)
    mhd_panic (mhd_panic_cls, __FILE__, __LINE__
    #ifdef HAVE_MESSAGES
      , _("libmicrohttpd API violation")
    #else
      , NULL
    #endif
    );

  if (0 != left_unprocessed)
    {
      /*
       * Can return NGHTTP2_ERR_PAUSE to make nghttp2_session_mem_recv() return
       * without processing further input bytes. The memory by pointed by
       * the data is retained until nghttp2_session_mem_recv() is called.
       * The application must retain the input bytes which was used to produce
       * the data parameter, because it may refer to the memory region included
       * in the input bytes.
       */
      /* client did not process everything */
      if ((0 != (h2->connection->daemon->options & MHD_USE_INTERNAL_POLLING_THREAD)) &&
          (! h2->connection->suspended) )
        MHD_DLOG (h2->connection->daemon,
            _("WARNING: incomplete upload processing and connection not suspended may result in hung connection.\n"));
      // mhd_assert(left_unprocessed == 0);
    }

  processed_size = to_be_processed - left_unprocessed;
  /* default_handler left "unprocessed" bytes in buffer for next time... */
  data += processed_size;
  available -= processed_size;
  if (MHD_SIZE_UNKNOWN != stream->remaining_upload_size)
    stream->remaining_upload_size -= processed_size;
  return 0;
}


/**
 * A frame was received. If it is a DATA or HEADERS frame,
 * we pass the request to the MHD application.
 *
 * @param session    current http2 session
 * @param frame      frame received
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_frame_recv_callback (nghttp2_session *session,
                        const nghttp2_frame *frame, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  h2_debug_vprintf ("[id=%zu] recv %s frame <length=%zu, flags=0x%02X, stream_id=%u>", h2->session_id, FRAME_TYPE (frame->hd.type), frame->hd.length, frame->hd.flags, frame->hd.stream_id);
  if (frame->hd.flags) print_flags(frame->hd);

  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (NULL == stream)
    return 0;

  switch (frame->hd.type)
  {
    case NGHTTP2_HEADERS:
      if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
      {
        if (need_100_continue (h2->connection))
        {
          nghttp2_nv nva;
          stream->response_code = 100;
          add_header (&nva, ":status", status_string[100]);
          nghttp2_submit_headers (session, NGHTTP2_FLAG_NONE, stream->stream_id,
                                  NULL, &nva, 1, NULL);
          stream->response_code = 0;
        }
        /* First call */
        size_t unused = 0;
        int ret = h2_call_connection_handler (h2->connection, stream, NULL, &unused);
        if (ret != 0)
          return ret;
      }
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      {
        /* Final call to application handler: GET, HEAD requests */

        size_t unused = 0;
        return h2_call_connection_handler (h2->connection, stream, NULL, &unused);
      }
      break;
    case NGHTTP2_DATA:
      /* Check that the client request has finished */
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      {
        /* Final call to application handler: POST, PUT requests */
        size_t unused = 0;
        return h2_call_connection_handler (h2->connection, stream, NULL, &unused);
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
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
int
on_frame_send_callback (nghttp2_session *session,
                        const nghttp2_frame *frame, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  h2_debug_vprintf ("[id=%zu] send %s frame <length=%zu, flags=0x%02X, stream_id=%u>", h2->session_id, FRAME_TYPE (frame->hd.type), frame->hd.length, frame->hd.flags, frame->hd.stream_id);
  if (frame->hd.type == NGHTTP2_HEADERS) {
    nghttp2_nv *nva = frame->headers.nva;
    nghttp2_nv *end = frame->headers.nva + frame->headers.nvlen;
    for (; nva != end; ++nva) {
      h2_debug_vprintf ("[id=%zu] %s%s%s: %s", h2->session_id, do_color("\033[1;34m"), nva->name, do_color("\033[0m"), nva->value);
    }
  }
  MHD_update_last_activity_ (h2->connection);
  return 0;
}


/**
 * The reception of a header block in HEADERS or PUSH_PROMISE is started.
 *
 * @param session    current http2 session
 * @param frame      frame received
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_begin_headers_callback (nghttp2_session *session,
                           const nghttp2_frame *frame, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  // h2_debug_vprintf ("[id=%zu]", h2->session_id);

  if ((frame->hd.type != NGHTTP2_HEADERS) ||
      (frame->headers.cat != NGHTTP2_HCAT_REQUEST))
    {
      return 0;
    }

  int32_t stream_id = frame->hd.stream_id;
  stream = h2_stream_create (stream_id, h2->connection->daemon->pool_size);
  if (NULL == stream)
    {
      // Out of memory.
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }
  h2->num_streams++;
  h2->accepted_max = stream_id;

  h2_session_add_stream (h2, stream);

  nghttp2_session_set_stream_user_data(session, stream_id, stream);
  return 0;
}


/**
 * Library provides the error message. Only for debugging purposes.
 *
 * @param session  current http2 session
 * @param msg  error message
 * @param len  length of msg
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
error_callback (nghttp2_session *session,
                const char *msg, size_t len,
                void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  mhd_assert (h2 != NULL);
  h2_debug_vprintf ("[id=%zu] %s", h2->session_id, msg);
  return 0;
}


/**
 * Invalid frame received. Only for debugging purposes.
 *
 * @param session    current http2 session
 * @param frame      frame sent
 * @param error_code reason of closure
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_invalid_frame_recv_callback (nghttp2_session *session,
                                const nghttp2_frame *frame,
                                int error_code,
                                void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  mhd_assert (h2 != NULL);
  h2_debug_vprintf ("[id=%zu] INVALID: %s", h2->session_id, nghttp2_strerror(error_code));
  return 0;
}




/**
 * An invalid header name/value pair is received for the frame.
 *
 * @param session  current http2 session
 * @param frame    frame received
 * @param name     header name
 * @param namelen  length of header name
 * @param value    header value
 * @param valuelen length of header value
 * @param flags    flags for header field name/value pair
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If header is ignored, returns 0. Otherwise, returns an error.
 */
static int
on_invalid_header_callback (nghttp2_session *session, const nghttp2_frame *frame,
                    const uint8_t *name,  size_t namelen,
                    const uint8_t *value, size_t valuelen,
                    uint8_t flags, void *user_data)
{
  (void)flags;
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  h2_debug_vprintf ("[id=%zu] %s%s%s: %s", h2->session_id, do_color("\033[1;34m"), name, do_color("\033[0m"), value);
  return 0;
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
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_header_callback (nghttp2_session *session, const nghttp2_frame *frame,
                    const uint8_t *name,  size_t namelen,
                    const uint8_t *value, size_t valuelen,
                    uint8_t flags, void *user_data)
{
  (void)flags;
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  h2_debug_vprintf ("[id=%zu] %s%s%s: %s", h2->session_id, do_color("\033[1;34m"), name, do_color("\033[0m"), value);

  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (NULL == stream)
  {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if ((namelen == H2_HEADER_METHOD_LEN) &&
      (strncmp(H2_HEADER_METHOD, name, namelen) == 0))
  {
      stream->method = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->method)
      {
        stream->response_code = MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
        return h2_transmit_error_response (h2, stream);
      }
      strcpy(stream->method, value);
  }
  else if ((namelen == H2_HEADER_SCHEME_LEN) &&
      (strncmp(H2_HEADER_SCHEME, name, namelen) == 0))
  {
      stream->scheme = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->scheme)
      {
        stream->response_code = MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
        return h2_transmit_error_response (h2, stream);
      }
      strcpy(stream->scheme, value);
  }
  else if ((namelen == H2_HEADER_PATH_LEN) &&
      (strncmp(H2_HEADER_PATH, name, namelen) == 0))
  {
      stream->path = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->path)
      {
        stream->response_code = MHD_HTTP_URI_TOO_LONG;
        return h2_transmit_error_response (h2, stream);
      }
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
        {
          stream->response_code = MHD_HTTP_URI_TOO_LONG;
          return h2_transmit_error_response (h2, stream);
        }
        strcpy(stream->query, args);

        /* note that this call clobbers 'query' */
        unsigned int unused_num_headers;
        connection->headers_received = stream->headers_received;
        connection->headers_received_tail = stream->headers_received_tail;
        connection->pool = stream->pool;

        MHD_parse_arguments_ (connection, MHD_GET_ARGUMENT_KIND, stream->query,
          &connection_add_header, &unused_num_headers);

        stream->pool = connection->pool;
        stream->headers_received = connection->headers_received;
        stream->headers_received_tail = connection->headers_received_tail;
      }

      /* Absolute path */
      stream->url = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      if (NULL == stream->url)
      {
        stream->response_code = MHD_HTTP_URI_TOO_LONG;
        return h2_transmit_error_response (h2, stream);
      }
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
      {
        stream->response_code = MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
        return h2_transmit_error_response (h2, stream);
      }
      strcpy(stream->authority, value);
      return h2_connection_stream_add_header (h2->connection, h2, stream,
                               MHD_HTTP_HEADER_HOST, strlen(MHD_HTTP_HEADER_HOST),
                               value, valuelen);
  }
  else if ((namelen == H2_HEADER_CONTENT_LENGTH_LEN) &&
      (strncmp(H2_HEADER_CONTENT_LENGTH, name, namelen) == 0))
  {
      stream->remaining_upload_size = atol(value);
  }
  else
  {
    return h2_connection_stream_add_header (h2->connection, h2, stream,
                                    name, namelen, value, valuelen);
  }
  return 0;
}


/**
 * Stream is closed. If there was an error, a RST stream is sent.
 *
 * @param session    current http2 session
 * @param stream_id  id of stream
 * @param error_code reason of closure
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_stream_close_callback (nghttp2_session *session, int32_t stream_id,
                          uint32_t error_code, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  (void)error_code;
  // h2_debug_vprintf ("[id=%zu] stream_id=%zu", h2->session_id, stream_id);

  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (stream != NULL)
  {
    if (error_code)
    {
      h2_debug_vprintf ("[stream_id=%d] Closing with err=%s", stream_id, nghttp2_strerror(error_code));
      nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                stream_id, error_code);
    }
    h2_session_remove_stream (h2, stream);
  }
  return 0;
}


/**
 * Sends at most length bytes of data stored in data.
 *
 * @param session    session
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns the number of bytes sent.
 *         Otherwise, if it cannot send any single byte without blocking,
 *         it returns NGHTTP2_ERR_WOULDBLOCK.
 *         For other errors, it returns NGHTTP2_ERR_CALLBACK_FAILURE.
 */
int
h2_fill_write_buffer (nghttp2_session *session, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  mhd_assert (h2 != NULL);
  struct MHD_Connection *connection = h2->connection;

  // h2_debug_vprintf ("[id=%zu]", h2->session_id);
  /* If there is pending data from previous nghttp2_session_mem_send call */
  if (h2->data_pending)
  {
    h2_debug_vprintf ("h2->data_pending=%zu", h2->data_pending_len);
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
// h2_debug_vprintf ("size=%d append=%d n=%d left=%d data_len=%d", connection->write_buffer_size, connection->write_buffer_append_offset, n, left, data_len);
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

/**
 * Send HTTP/2 server connection preface.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
h2_session_send_preface (struct h2_session_t *h2)
{
  int rv;

  /* Flags currently ignored */
  rv = nghttp2_submit_settings (h2->session, NGHTTP2_FLAG_NONE,
                                h2->settings, h2->settings_len);
  if (rv != 0)
    {
      h2_debug_vprintf("Fatal error: %s", nghttp2_strerror (rv));
      return MHD_NO;
    }
  return MHD_YES;
}



/**
 * Set local session settings and callbacks.
 *
 * @param h2 h2 session
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
h2_session_init (struct h2_session_t *h2)
{
  mhd_assert (h2 != NULL);

  int rv;
  nghttp2_session_callbacks *callbacks;

  rv = nghttp2_session_callbacks_new (&callbacks);
  if (rv != 0)
    {
      mhd_assert (rv == NGHTTP2_ERR_NOMEM);
      return MHD_NO;
    }

  nghttp2_session_callbacks_set_on_frame_recv_callback (callbacks,
    on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback (callbacks,
    on_frame_send_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback (callbacks,
    on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback (callbacks,
    on_header_callback);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback (callbacks,
    on_data_chunk_recv_callback);

  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback (callbacks,
    on_invalid_frame_recv_callback);

  nghttp2_session_callbacks_set_error_callback (callbacks,
    error_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback (callbacks,
    on_begin_headers_callback);

  nghttp2_session_callbacks_set_send_data_callback (callbacks,
    send_data_callback);

  nghttp2_session_callbacks_set_on_invalid_header_callback (callbacks,
    on_invalid_header_callback);

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
 * Initialize HTTP2 structures, set the initial local settings for the session,
 * and send server preface.
 *
 * @param connection connection to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
struct h2_session_t *
h2_session_create (struct MHD_Connection *connection)
{
  int rv;

  struct h2_session_t *h2 = calloc (1, sizeof (struct h2_session_t));
  if (NULL == h2)
    {
      return NULL;
    }

  h2->session_id = num_sessions++;

  /* Set initial local session settings */
  struct MHD_Daemon *daemon = connection->daemon;
  h2->settings = h2_config_get_settings (daemon->h2_config);
  h2->settings_len = h2_config_get_settings_len (daemon->h2_config);

  /* Set reference to connection */
  h2->connection = connection;
  // /* Bigger pool? */
  // MHD_pool_destroy (connection->pool);
  // connection->pool = MHD_pool_create (daemon->pool_size*2);

  /* Create session and fill callbacks */
  rv = h2_session_init (h2);
  if (rv != MHD_YES)
    {
      h2_session_destroy (h2);
      return NULL;
    }

  /* Send server preface */
  rv = h2_session_send_preface (h2);
  if (rv != MHD_YES)
    {
      h2_session_destroy (h2);
      return NULL;
    }

  return h2;
}

int
h2_session_upgrade (struct h2_session_t *h2, const char *settings, const char *method)
{
  char *settings_payload;
  int head_request = 0, ret;
  size_t len;

  settings_payload = BASE64Decode (settings);
  len = strlen (settings_payload);

  /* Is it a HEAD request? */
  if (MHD_str_equal_caseless_ (method, MHD_HTTP_METHOD_HEAD))
    {
      head_request = 1;
    }

  ret = nghttp2_session_upgrade2 (h2->session, settings_payload, len,
                                  head_request, NULL);
  free (settings_payload);
  return ret;
}

/* end of h2_session.c */
