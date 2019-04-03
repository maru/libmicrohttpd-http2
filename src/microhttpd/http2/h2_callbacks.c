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
#include "connection.h"
#include "memorypool.h"


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

const size_t MHD_HTTP_HEADER_HOST_LEN = strlen(MHD_HTTP_HEADER_HOST);

typedef struct {
  const char *name;
  size_t len;
} h2_pseudo_header_t;

static h2_pseudo_header_t h2_pseudo_headers[] = {
  { .name = ":method",    .len = 7 },
  { .name = ":scheme",    .len = 7 },
  { .name = ":authority", .len = 10 },
  { .name = ":path",      .len = 5 },
};

enum h2_pseudo_headers_idx {
  H2_HEADER_METHOD, H2_HEADER_SCHEME, H2_HEADER_AUTH, H2_HEADER_PATH
};

extern struct MHD_Daemon *daemon_;

static ssize_t
response_read_cb (nghttp2_session*, int32_t, uint8_t*, size_t, uint32_t*,
                  nghttp2_data_source*, void*);

static int
h2_transmit_error_response (struct h2_session_t *h2, struct h2_stream_t *stream);

/**
 * The reception of a header block in HEADERS or PUSH_PROMISE is started.
 * Create a stream.
 *
 * @param session    current http2 session
 * @param frame      frame received
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
on_begin_headers_cb (nghttp2_session *session,
                     const nghttp2_frame *frame, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  // ENTER ("XXXX [id=%zu]", h2->session_id);

  if ( !((frame->hd.type == NGHTTP2_HEADERS) &&
         (frame->headers.cat == NGHTTP2_HCAT_REQUEST)) )
    {
      /* Frame is not beginning of a new stream */
      return 0;
    }

  int32_t stream_id = frame->hd.stream_id;
  stream = h2_stream_create (stream_id, daemon_->pool_size);
  if (NULL == stream)
    {
      /* Out of memory */
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

  int rv;
  rv = nghttp2_session_set_stream_user_data (session, stream_id, stream);
  if (rv != 0)
    {
      h2_stream_destroy (stream);
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

  h2_session_add_stream (h2, stream);
  h2->num_streams++;
  h2->last_stream_id = stream_id;

  return 0;
}


static int
header_parse_path (struct h2_stream_t *stream, const char *value, size_t valuelen)
{
  /* Process the URI. See MHD_OPTION_URI_LOG_CALLBACK */
  if (NULL != daemon_->uri_log_callback)
    {
      stream->c.client_aware = true;
      stream->c.client_context
          = daemon_->uri_log_callback (daemon_->uri_log_callback_cls,
                                       stream->c.url, &stream->c);
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

      char *fragment = memchr (args, '#', argslen);
      if (NULL != fragment)
        {
          fragment[0] = '\0';
          argslen = (size_t)(fragment - (char *) args);
        }

      /* note that this call clobbers 'query' */
      unsigned int unused_num_headers;

      MHD_parse_arguments_ (&stream->c, MHD_GET_ARGUMENT_KIND, args,
        &connection_add_header, &unused_num_headers);

    }
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
on_header_cb (nghttp2_session *session, const nghttp2_frame *frame,
              const uint8_t *name,  size_t namelen,
              const uint8_t *value, size_t valuelen,
              uint8_t flags, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;

  ENTER ("XXXX [id=%zu] %s%s%s: %s", h2->session_id, do_color("\033[1;34m"), name, do_color("\033[0m"), value);

  /* Get stream */
  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (NULL == stream)
    {
      return NGHTTP2_ERR_CALLBACK_FAILURE;
    }

  /* Not a pseudo header :hhhhhh */
  if ( (namelen > 0) && (name[0] != ':') )
    {
      return h2_stream_add_header (stream, name, namelen, value, valuelen);
    }

  int header;
  for (header = 0; header < sizeof (h2_pseudo_headers); header++)
    {
      if ( (namelen == h2_pseudo_headers[header].len) &&
           (0 == strcmp (h2_pseudo_headers[header].name, name)) )
        break;
    }

  if (H2_HEADER_AUTH == header)
    {
      /* Add header Host: */
      return h2_stream_add_header (stream,
                                   MHD_HTTP_HEADER_HOST, MHD_HTTP_HEADER_HOST_LEN,
                                   value, valuelen);
    }

  char *buf = MHD_pool_allocate (stream->c.pool, valuelen + 1, MHD_YES);
  if (NULL == buf)
    {
      stream->c.responseCode = MHD_HTTP_REQUEST_HEADER_FIELDS_TOO_LARGE;
      return h2_transmit_error_response (h2, stream);
    }
  strcpy (buf, value);

  switch (header)
    {
      /* :method */
      case H2_HEADER_METHOD:
        stream->c.method = buf;
        break;

      /* :scheme */
      case H2_HEADER_SCHEME:
        stream->scheme = buf;
        break;

      /* :path */
      case H2_HEADER_PATH:
        daemon_->unescape_callback (daemon_->unescape_callback_cls,
                                    &stream->c, buf);
        stream->c.url = buf;
        return header_parse_path (stream, value, valuelen);
        break;

      /* :authority */
      case H2_HEADER_AUTH:
        break;

      default:
        mhd_assert (header >= sizeof (h2_pseudo_headers));
        break;
    }
  return 0;
}


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
 * Call the handler of the application for this connection.
 * Handles chunking of the upload as well as normal uploads.
 *
 * @param stream            stream we are processing
 * @param upload_data       the data being uploaded
 * @param upload_data_size  the size of the upload_data provided
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
h2_call_connection_handler (struct h2_stream_t *stream, nghttp2_session *session,
                            char *upload_data, size_t *upload_data_size)
{
  if ((NULL != stream->c.response) || (stream->c.responseCode != 0))
    return 0;                     /* already queued a response */
  ENTER ("XXXX method %s url %s", stream->c.method, stream->c.url);
  stream->c.client_aware = true;
  if (MHD_NO ==
      daemon_->default_handler (daemon_->default_handler_cls,
					   &stream->c, stream->c.url, stream->c.method, MHD_HTTP_VERSION_2_0,
					   upload_data, upload_data_size,
					   &stream->c.client_context))
    {
      /* serious internal error, close stream */
      nghttp2_submit_rst_stream (session, NGHTTP2_FLAG_NONE,
                                stream->stream_id, NGHTTP2_INTERNAL_ERROR);
      ENTER ("XXXX fail!");
      return 0; //NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
  return 0;
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
// static
int
h2_build_stream_headers (struct h2_session_t *h2, struct h2_stream_t *stream,
                  struct MHD_Response *response)
{
  nghttp2_nv *nva;
  size_t nvlen = 2;
  ENTER ("XXXX [id=%zu]", h2->session_id);

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
  nva = MHD_pool_allocate (stream->c.pool, sizeof (nghttp2_nv)*nvlen, MHD_YES);
  if (NULL == nva)
    {
#ifdef HAVE_MESSAGES
      MHD_DLOG (daemon_,
                _("Not enough memory in pool for headers!\n"));
#endif
      return NGHTTP2_ERR_NOMEM;
    }
  size_t i = 0;
  /* Check status code value, to detect programming errors */
  mhd_assert (stream->c.responseCode < sizeof(status_string)/sizeof(status_string[100]));

  /* :status */
  add_header (&nva[i++], ":status", status_string[stream->c.responseCode]);

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
  if ((strcmp (MHD_HTTP_METHOD_HEAD, stream->c.method) == 0) || (NULL == response))
    {
      /* Only HEADERS frame */
      r = nghttp2_submit_response (h2->session, stream->stream_id, nva, nvlen, NULL);
    }
  else
    {
      /* HEADERS + DATA frames */
      nghttp2_data_provider data_prd;
      data_prd.source.fd = response->fd;
      data_prd.read_callback = response_read_cb;
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
static int
h2_transmit_error_response (struct h2_session_t *h2, struct h2_stream_t *stream)
{
  ENTER("XXXX");
  return h2_build_stream_headers (h2, stream, NULL);
}

/**
 * Callback function invoked when the nghttp2 library wants to
 * read data from the source.
 * Determines the number of bytes that will be in the next DATA frame.
 * Sets NGHTTP2_DATA_FLAG_NO_COPY flag, so data will be read in
 * send_data_cb function (copied directly to connection->write_buffer).
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
response_read_cb (nghttp2_session *session, int32_t stream_id,
                        uint8_t *buf, size_t length, uint32_t *data_flags,
                        nghttp2_data_source *source, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  struct MHD_Response *response;
  ssize_t nread;

  ENTER ("XXXX [id=%zu]", h2->session_id);
  /* Get current stream */
  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (NULL == stream)
    {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

  response = stream->c.response;

  /* Check: the DATA frame has to enter in the write_buffer - 10 bytes
     (frame header + padding) */
  length = MHD_MIN (length, stream->c.write_buffer_size - 10);

  /* Determine number of bytes to read */
  if (response->data_size > 0)
    {
      /* Response in data buffer */
      size_t data_write_offset;
      data_write_offset = (size_t) stream->c.response_write_position - response->data_start;
      nread = MHD_MIN (length, (ssize_t) (response->data_size - data_write_offset));
    }
  else if (response->total_size == MHD_SIZE_UNKNOWN)
    {
      /* Response size unknown, call the MHD_ContentReaderCallback function */
      mhd_assert (response->crc != NULL);
      MHD_mutex_lock_chk_ (&response->mutex);
      ssize_t ret = response->crc (response->crc_cls,
                                   stream->c.response_write_position,
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
      nread = MHD_MIN (length, (ssize_t) (response->total_size - stream->c.response_write_position));
    }

  /* We will write the complete DATA frame into the write_buffer in function send_data_cb. */
  *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;

  if ((nread == 0) || (response->total_size == stream->c.response_write_position + nread))
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
          nva = MHD_pool_allocate (stream->c.pool, sizeof (nghttp2_nv)*nvlen, MHD_YES);
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
 * Copy the application data to send in the DATA frame into the write_buffer
 * of the connection of the session.
 * Callback function invoked when NGHTTP2_DATA_FLAG_NO_COPY is used in
 * response_read_cb to send complete DATA frame.
 *
 * @param session    current http2 session
 * @param frame      DATA frame to send
 * @param framehd    serialized frame header (9 bytes)
 * @param length     length of application data to send
 * @param source     same pointer passed to response_read_cb
 * @param user_data  HTTP2 connection of type h2_session_t
 * @return If succeeds, returns 0. Otherwise, returns an error:
 *        - NGHTTP2_ERR_WOULDBLOCK: cannot send DATA frame now
 *          (write_buffer doesn't have enough space).
 *        - NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE: closes stream by issuing an
 *          RST_STREAM frame with NGHTTP2_INTERNAL_ERROR.
 *        - NGHTTP2_ERR_CALLBACK_FAILURE: session failure.
 */
static int
send_data_cb (nghttp2_session *session, nghttp2_frame *frame,
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

  ENTER ("XXXX [id=%zu]", h2->session_id);
  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (NULL == stream)
    {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

  // connection = h2->connection;
  response = stream->c.response;
  // mhd_assert (connection != NULL);
  mhd_assert (response != NULL);

  padlen = frame->data.padlen;

  left = stream->c.write_buffer_size - stream->c.write_buffer_append_offset;

  if ((stream->c.suspended) || (left < 9 + length + padlen)  /* 9 = frame header */)
    {
      return NGHTTP2_ERR_WOULDBLOCK;
    }

  buffer = &stream->c.write_buffer[stream->c.write_buffer_append_offset];

  /* Copy header */
  memcpy (buffer, framehd, 9);
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
      pos = (size_t) stream->c.response_write_position - response->data_start;
      memcpy (buffer, &response->data[pos], length);
      ENTER ("XXXX pos %d len %d", pos, length);
    }
  else if ((response->crc != NULL) && (length > 0))
    {
      /* File or response size known */
      MHD_mutex_lock_chk_ (&response->mutex);
      ssize_t ret = response->crc (response->crc_cls,
                                   stream->c.response_write_position,
                                   buffer, length);
      MHD_mutex_unlock_chk_ (&response->mutex);
      if ((((ssize_t) MHD_CONTENT_READER_END_OF_STREAM) == ret) ||
          (((ssize_t) MHD_CONTENT_READER_END_WITH_ERROR) == ret))
        {
          response->total_size = stream->c.response_write_position;

          /* error, close stream */
          return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
        }
    }

  *(buffer + length) = 0;
  ENTER ("XXXX %s", buffer);

  /* Set padding */
  if (padlen > 0)
    {
      buffer += length;
      memset (buffer, 0, padlen - 1);
    }

  ENTER ("XXXX size:%d pos %d len %d", stream->c.write_buffer_size, stream->c.response_write_position, length);
  stream->c.response_write_position += length;

  /* Reset data buffer */
  if ((response->total_size == MHD_SIZE_UNKNOWN) &&
      ((stream->c.response_write_position - response->data_start) == response->data_size))
    {
      response->data_size = 0;
      response->data_start = stream->c.response_write_position;
    }

  stream->c.write_buffer_append_offset += 9 + (padlen > 0) + length;
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
on_data_chunk_recv_cb (nghttp2_session *session, uint8_t flags,
                             int32_t stream_id, const uint8_t *data,
                             size_t len, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  mhd_assert (h2 != NULL);
  ENTER ("XXXX [id=%zu] len: %zu", h2->session_id, len);

  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (NULL == stream)
    return 0;

  size_t available = len;
  size_t to_be_processed;
  size_t left_unprocessed;
  size_t processed_size;

  if ((0 != stream->c.remaining_upload_size) &&
      (MHD_SIZE_UNKNOWN != stream->c.remaining_upload_size) &&
      (stream->c.remaining_upload_size < available) )
    {
      to_be_processed = (size_t)stream->c.remaining_upload_size;
    }
  else
    {
      to_be_processed = available;
    }
  left_unprocessed = to_be_processed;
  int r = h2_call_connection_handler (stream, session, (char *)data, &left_unprocessed);
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
      if ((0 != (daemon_->options & MHD_USE_INTERNAL_POLLING_THREAD)) &&
          (! stream->c.suspended) )
        MHD_DLOG (daemon_,
            _("WARNING: incomplete upload processing and connection not suspended may result in hung connection.\n"));
      // mhd_assert(left_unprocessed == 0);
    }

  processed_size = to_be_processed - left_unprocessed;
  /* default_handler left "unprocessed" bytes in buffer for next time... */
  data += processed_size;
  available -= processed_size;
  if (MHD_SIZE_UNKNOWN != stream->c.remaining_upload_size)
    stream->c.remaining_upload_size -= processed_size;
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
on_frame_recv_cb (nghttp2_session *session,
                  const nghttp2_frame *frame, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;

  /* FIXME h2_debug_print_frame */
  ENTER ("XXXX [id=%zu] recv %s%s%s frame <length=%zu, flags=0x%02X, stream_id=%u>",
      h2->session_id, do_color(PRINT_RECV), FRAME_TYPE (frame->hd.type), do_color(COLOR_WHITE),
      frame->hd.length, frame->hd.flags, frame->hd.stream_id);
  if (frame->hd.flags) print_flags(frame->hd);
  /*  */

  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  /* Stream not found: frame is not HEADERS, PUSH_PROMISE or DATA */
  if (NULL == stream)
    {
      return 0;
    }

  switch (frame->hd.type)
    {
    case NGHTTP2_HEADERS:
      if (0 != (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS))
        {
          /* FIXME */
          if (need_100_continue (&stream->c))
            {
              nghttp2_nv nva;
              stream->c.responseCode = 100;
              add_header (&nva, ":status", status_string[100]);
              nghttp2_submit_headers (session, NGHTTP2_FLAG_NONE, stream->stream_id,
                                      NULL, &nva, 1, NULL);
              stream->c.responseCode = 0;
            }
          /* First call */
          size_t unused = 0;
          int ret = h2_call_connection_handler (stream, session, NULL, &unused);
          if (ret != 0)
            return ret;
        }
      if (0 != (frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        {
          /* Final call to application handler: GET, HEAD requests */
          size_t unused = 0;
          return h2_call_connection_handler (stream, session, NULL, &unused);
        }
      break;
    case NGHTTP2_PUSH_PROMISE:
      break;
    case NGHTTP2_DATA:
      /* Check that the client request has finished */
      if (0 != (frame->hd.flags & NGHTTP2_FLAG_END_STREAM))
        {
          /* Final call to application handler: POST, PUT requests */
          size_t unused = 0;
          return h2_call_connection_handler (stream, session, NULL, &unused);
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
static int
on_frame_send_cb (nghttp2_session *session,
                        const nghttp2_frame *frame, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  ENTER ("XXXX [id=%zu] send %s%s%s frame <length=%zu, flags=0x%02X, stream_id=%u>",
    h2->session_id, do_color(PRINT_SEND), FRAME_TYPE (frame->hd.type), do_color(COLOR_WHITE),
    frame->hd.length, frame->hd.flags, frame->hd.stream_id);
  if (frame->hd.type == NGHTTP2_HEADERS)
    {
      nghttp2_nv *nva = frame->headers.nva;
      nghttp2_nv *end = frame->headers.nva + frame->headers.nvlen;
      for (; nva != end; ++nva)
        {
          ENTER ("XXXX [id=%zu] %s%s%s: %s", h2->session_id, do_color("\033[1;34m"), nva->name, do_color("\033[0m"), nva->value);
        }
    }
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
error_cb (nghttp2_session *session,
                const char *msg, size_t len,
                void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  mhd_assert (h2 != NULL);
  ENTER ("XXXX [id=%zu] %s", h2->session_id, msg);
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
on_invalid_frame_recv_cb (nghttp2_session *session,
                                const nghttp2_frame *frame,
                                int error_code,
                                void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  mhd_assert (h2 != NULL);
  ENTER ("XXXX [id=%zu] INVALID: %s", h2->session_id, nghttp2_strerror(error_code));
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
on_invalid_header_cb (nghttp2_session *session, const nghttp2_frame *frame,
                    const uint8_t *name,  size_t namelen,
                    const uint8_t *value, size_t valuelen,
                    uint8_t flags, void *user_data)
{
  (void)flags;
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  ENTER ("XXXX [id=%zu] %s%s%s: %s", h2->session_id, do_color("\033[1;34m"), name, do_color("\033[0m"), value);
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
on_stream_close_cb (nghttp2_session *session, int32_t stream_id,
                    uint32_t error_code, void *user_data)
{
  struct h2_session_t *h2 = (struct h2_session_t *)user_data;
  struct h2_stream_t *stream;
  (void)error_code;
  ENTER ("XXXX [id=%zu] stream_id=%zu", h2->session_id, stream_id);

  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (stream != NULL)
    {
      if (error_code)
        {
          ENTER ("XXXX [stream_id=%d] Closing with err=%s", stream_id, nghttp2_strerror(error_code));
          nghttp2_submit_rst_stream(session, NGHTTP2_FLAG_NONE,
                                    stream_id, error_code);
        }
      h2_session_remove_stream (h2, stream);
    }
  return 0;
}


/**
 * Set local session settings and callbacks.
 *
 * @param h2 HTTP/2 session to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
h2_session_set_callbacks (struct h2_session_t *h2)
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
    on_frame_recv_cb);

  nghttp2_session_callbacks_set_on_frame_send_callback (callbacks,
    on_frame_send_cb);

  nghttp2_session_callbacks_set_on_stream_close_callback (callbacks,
    on_stream_close_cb);

  nghttp2_session_callbacks_set_on_header_callback (callbacks,
    on_header_cb);

  nghttp2_session_callbacks_set_on_data_chunk_recv_callback (callbacks,
    on_data_chunk_recv_cb);

  nghttp2_session_callbacks_set_on_invalid_frame_recv_callback (callbacks,
    on_invalid_frame_recv_cb);

  nghttp2_session_callbacks_set_error_callback (callbacks,
    error_cb);

  nghttp2_session_callbacks_set_on_begin_headers_callback (callbacks,
    on_begin_headers_cb);

  nghttp2_session_callbacks_set_send_data_callback (callbacks,
    send_data_cb);

  nghttp2_session_callbacks_set_on_invalid_header_callback (callbacks,
    on_invalid_header_cb);

  rv = nghttp2_session_server_new (&h2->session, callbacks, h2);
  if (rv != 0)
    {
      mhd_assert (rv == NGHTTP2_ERR_NOMEM);
      return MHD_NO;
    }

  nghttp2_session_callbacks_del (callbacks);
  return MHD_YES;
}

/* end of h2_callbacks.c */
