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
#include "mhd_mono_clock.h"
#include "connection.h"
#include "memorypool.h"
#include "response.h"
#include "mhd_str.h"

#ifdef HTTP2_SUPPORT

#undef ENTER_COLOR
#define ENTER_COLOR "31;1m"
#undef HTTP2_DEBUG
#define HTTP2_DEBUG 1

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

void print_flags(const nghttp2_frame_hd hd) {
  char s[8000]; bool is_empty = true;
  memset(s, 0, sizeof(s));
  switch (hd.type) {
  case NGHTTP2_DATA:
    if (hd.flags & NGHTTP2_FLAG_END_STREAM) {
      strcat(s, "END_STREAM");
      is_empty = false;
    }
    if (hd.flags & NGHTTP2_FLAG_PADDED) {
      if (!is_empty) {
        strcat(s, " | ");
      }
      is_empty = false;
      strcat(s, "PADDED");
    }
    break;
  case NGHTTP2_HEADERS:
    if (hd.flags & NGHTTP2_FLAG_END_STREAM) {
      is_empty = false;
      strcat(s, "END_STREAM");
    }
    if (hd.flags & NGHTTP2_FLAG_END_HEADERS) {
      if (!is_empty) {
        strcat(s, " | ");
      }
      is_empty = false;
      strcat(s, "END_HEADERS");
    }
    if (hd.flags & NGHTTP2_FLAG_PADDED) {
      if (!is_empty) {
        strcat(s, " | ");
      }
      is_empty = false;
      strcat(s, "PADDED");
    }
    if (hd.flags & NGHTTP2_FLAG_PRIORITY) {
      if (!is_empty) {
        strcat(s, " | ");
      }
      is_empty = false;
      strcat(s, "PRIORITY");
    }

    break;
  case NGHTTP2_PRIORITY:
    break;
  case NGHTTP2_SETTINGS:
    if (hd.flags & NGHTTP2_FLAG_ACK) {
      is_empty = false;
      strcat(s, "ACK");
    }
    break;
  case NGHTTP2_PUSH_PROMISE:
    if (hd.flags & NGHTTP2_FLAG_END_HEADERS) {
      is_empty = false;
      strcat(s, "END_HEADERS");
    }
    if (hd.flags & NGHTTP2_FLAG_PADDED) {
      if (!is_empty) {
        strcat(s, " | ");
      }
      is_empty = false;
      strcat(s, "PADDED");
    }
    break;
  case NGHTTP2_PING:
    if (hd.flags & NGHTTP2_FLAG_ACK) {
      is_empty = false;
      strcat(s, "ACK");
    }
    break;
  }
  ENTER("; %s", s);
}

#define warnx(format, args...) fprintf(stderr, format "\n", ##args)

static int add_header(nghttp2_nv *nv, const char *key, const char *value)
{
  nv->name = (uint8_t*)key;
  nv->namelen = strlen(key);
  nv->value = (uint8_t*)value;
  nv->valuelen = strlen(value);
  nv->flags = NGHTTP2_NV_FLAG_NONE;
}

static size_t num_sessions = 0;

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
  // ENTER("id=%d stream_id=%d", h2->session_id, stream->stream_id);
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
  // ENTER("id=%d stream_id=%d", h2->session_id, stream->stream_id);
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
 * We encountered an error processing the request.
 * Handle it properly by stopping to read data
 * and sending the indicated response code and message.
 *
 * @param connection the connection
 * @param status_code the response code to send (400, 413 or 414)
 * @param message the error message to send
 */
static void
http2_transmit_error_response (struct MHD_Connection *connection,
                               unsigned int status_code, const char *message)
{
  // ENTER();
  struct MHD_Response *response;

  // connection->state = MHD_CONNECTION_HTTP2_CLOSED_REMOTE;
  // connection->read_closed = true;
#ifdef HAVE_MESSAGES
  MHD_DLOG (connection->daemon,
            _("Error processing request (HTTP response code is %u (`%s')). Closing stream.\n"),
            status_code,
            message);
#endif
  if (NULL != connection->response)
    {
      MHD_destroy_response (connection->response);
      connection->response = NULL;
    }
  response = MHD_create_response_from_buffer (strlen (message),
					      (void *) message,
					      MHD_RESPMEM_PERSISTENT);
  MHD_queue_response (connection,
                      status_code,
                      response);
  mhd_assert (NULL != connection->response);
  MHD_destroy_response (response);
  /* Do not reuse this connection. */
  // connection->keepalive = MHD_CONN_MUST_CLOSE;
  // if (MHD_NO == build_header_response (connection))
  //   {
  //     /* oops - close! */
  //     connection_close_error (connection,
	// 		      _("Closing connection (failed to create response header)\n"));
  //   }
  // else
  //   {
  //     connection->state = MHD_CONNECTION_HEADERS_SENDING;
  //   }
}


static ssize_t
response_read_callback(nghttp2_session *session, int32_t stream_id,
                                  uint8_t *buf, size_t length,
                                  uint32_t *data_flags,
                                  nghttp2_data_source *source,
                                  void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  struct MHD_Response *response;
  ssize_t nread;
  int fd = source->fd;

  ENTER("[id=%d]", h2->session_id);
  /* Get current stream */
  stream = nghttp2_session_get_stream_user_data (session, stream_id);
  if (stream == NULL)
  {
    return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
  }

  response = stream->response;

  /* Number of bytes to read */
  nread = (ssize_t) MHD_MIN((uint64_t) length,
                            response->total_size - stream->response_write_position);

  if ((nread == 0) || (response->total_size == stream->response_write_position + nread))
  {
    *data_flags |= NGHTTP2_DATA_FLAG_EOF;
    /* TODO: Add trailer nghttp2_submit_trailer */

    /* TODO: check nghttp2_session_get_stream_remote_close */
  }

  /* Use sendfile? */
#if defined(_MHD_HAVE_SENDFILE)
  if (MHD_resp_sender_sendfile == stream->resp_sender)
  {
    *data_flags |= NGHTTP2_DATA_FLAG_NO_COPY;
    return nread;
  }
#endif /* _MHD_HAVE_SENDFILE */

  /* Use callback function provided by the MHD application */
  if (response->crc != NULL)
  {
    if ((0 == response->total_size) ||
         (stream->response_write_position == response->total_size))
         mhd_assert(0);
    if ((response->data_start <= stream->response_write_position) &&
        (response->data_size + response->data_start >	stream->response_write_position))
      mhd_assert(0);

    MHD_mutex_lock_chk_ (&response->mutex);
    ssize_t ret = response->crc (response->crc_cls,
                                 stream->response_write_position,
                                 buf, nread);
    if ((((ssize_t) MHD_CONTENT_READER_END_OF_STREAM) == ret) ||
        (((ssize_t) MHD_CONTENT_READER_END_WITH_ERROR) == ret) ||
        (0 == ret))
    {
      response->total_size = stream->response_write_position;
      MHD_mutex_unlock_chk_ (&response->mutex);
      if ((((ssize_t)MHD_CONTENT_READER_END_OF_STREAM) == ret) || (0 == ret))
      {
        *data_flags |= NGHTTP2_DATA_FLAG_EOF;
        return 0;
      }
      else
      {
        /* error, close socket! */
        connection_close_error (h2->connection,
      				_("Closing connection (application reported error generating data)\n"));
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
    }
    response->data_start = stream->response_write_position;
    response->data_size = ret;
    MHD_mutex_unlock_chk_ (&response->mutex);
    if (0 >= ret)
    {
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }
    stream->response_write_position += ret;
    return ret;
  }

  /* Response is in a buffer */
  mhd_assert (fd == -1);

  uint64_t data_write_offset;
  data_write_offset = stream->response_write_position - response->data_start;
  nread = response->data_size - (size_t) data_write_offset;

  /* Copy to buf */
  memcpy(buf, &response->data[(size_t) data_write_offset], nread);

  /* Update write offset */
  stream->response_write_position += nread;

  return nread;
}

/**
 * Allocate the connection's write buffer and fill it with all of the
 * headers (or footers, if we have already sent the body) from the
 * HTTPd's response.  If headers are missing in the response supplied
 * by the application, additional headers may be added here.
 *
 * @param connection the connection
 * @return #MHD_YES on success, #MHD_NO on failure (out of memory)
 */
static int
build_headers (struct http2_conn *h2, struct http2_stream *stream, struct MHD_Response *response)
{
  nghttp2_nv *nva;
  size_t nvlen = 2;
  ENTER("[id=%d]", h2->session_id);
  /* Count the number of headers to send */
  struct MHD_HTTP_Header *pos;
  for (pos = response->first_header; NULL != pos; pos = pos->next)
  {
    if (pos->kind == MHD_HEADER_KIND)
    {
      nvlen++;
    }
  }
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
      return MHD_NO;
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

  /* content-lenght */
  char clen[32];
  if (response->total_size != MHD_SIZE_UNKNOWN)
  {
    snprintf(clen, sizeof(clen), "%d", response->total_size);
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

  /* Submits response HEADERS frame */
  nghttp2_data_provider data_prd;
  data_prd.source.fd = response->fd;
  data_prd.read_callback = response_read_callback;
  int r = nghttp2_submit_response(h2->session, stream->stream_id, nva, nvlen, &data_prd);
  return r;
}


/**
 * Call the handler of the application for this connection.
 * Handles chunking of the upload as well as normal uploads.
 *
 * @param connection connection we are processing
 * @param stream     stream we are processing
 * @return If succeeds, returns 0. Otherwise, returns an error.
 */
static int
http2_call_connection_handler (struct MHD_Connection *connection,
                               struct http2_stream *stream)
{
  size_t processed;

  if (NULL != stream->response)
    return 0;                     /* already queued a response */
  ENTER("[id=%d] method %s path %s", connection->h2->session_id, stream->method, stream->path);
  connection->h2->current_stream_id = stream->stream_id;
  processed = 0;
  stream->client_aware = true;
  if (MHD_NO ==
      connection->daemon->default_handler (connection->daemon->default_handler_cls,
					   connection, stream->path, stream->method, MHD_HTTP_VERSION_2_0,
             /* upload_data */ NULL, &processed,
					   &stream->client_context))
  {
    /* serious internal error, close stream */
    nghttp2_submit_rst_stream(connection->h2->session, NGHTTP2_FLAG_NONE,
                              stream->stream_id, NGHTTP2_INTERNAL_ERROR);
  }
  return 0;
}


int
send_data_callback(nghttp2_session *session, nghttp2_frame *frame,
                       const uint8_t *framehd, size_t length,
                       nghttp2_data_source *source, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  size_t padlen;
  mhd_assert (h2 != NULL);

  ENTER("[id=%d]", h2->session_id);
  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);

  ssize_t ret;

#if defined(_MHD_HAVE_SENDFILE)
  if ((stream != NULL) && (MHD_resp_sender_sendfile == stream->resp_sender))
  {
    struct MHD_Connection *connection = h2->connection;
    mhd_assert (connection != NULL);

    mhd_assert (length > 0);

    /* Send header */
    ret = connection->send_cls (connection, framehd, 9);

    /* Send padding length */
    padlen = frame->data.padlen;
    if (padlen > 0)
    {
      char p = padlen - 1;
      ret = connection->send_cls (connection, &p, 1);
    }

    /* Send file */
    connection->response = stream->response;
    mhd_assert (connection->response != NULL);
    ret = sendfile_adapter (connection);
    connection->response = NULL;

    if (ret < 0)
    {
      ENTER("ret: %d", ret);
      if (MHD_ERR_AGAIN_ == ret)
      {
        return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
      }
#ifdef HAVE_MESSAGES
      MHD_DLOG (connection->daemon,
                _("Failed to send data in request for `%s'.\n"),
                stream->path);
#endif
      connection_close_error (connection, NULL);
      return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
    }

    /* Send padding */
    if (padlen > 0)
    {
      uint8_t *buf = MHD_pool_allocate (stream->pool, padlen - 1, MHD_YES);
      memset(buf, 0, padlen - 1);
      ret = connection->send_cls (connection, buf, padlen - 1);
    }

    stream->response_write_position += ret;
    return 0;
  }
#endif /* ! _MHD_HAVE_SENDFILE */

  return NGHTTP2_ERR_TEMPORAL_CALLBACK_FAILURE;
}


#define FRAME_TYPE(x) (x==NGHTTP2_DATA?"DATA": (x==NGHTTP2_HEADERS?"HEADERS": (x==NGHTTP2_PRIORITY?"PRIORITY": (x==NGHTTP2_RST_STREAM?"RST_STREAM": (x==NGHTTP2_SETTINGS?"SETTINGS": (x==NGHTTP2_PUSH_PROMISE?"PUSH_PROMISE": (x==NGHTTP2_PING?"PING": (x==NGHTTP2_GOAWAY?"GOAWAY": (x==NGHTTP2_WINDOW_UPDATE?"WINDOW_UPDATE": (x==NGHTTP2_CONTINUATION?"CONTINUATION": (x==NGHTTP2_ALTSVC?"ALTSVC":"-")))))))))))

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
  ENTER("[id=%d] frame->hd.type %s %X", h2->session_id, FRAME_TYPE (frame->hd.type), frame->hd.flags);
  if (frame->hd.flags) print_flags(frame->hd);
  switch (frame->hd.type)
  {
    case NGHTTP2_HEADERS:
      stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
      if (stream != NULL)
      {
        if (frame->hd.flags & NGHTTP2_FLAG_END_HEADERS)
        {
          /* First call */
          http2_call_connection_handler (h2->connection, stream);
        }
        if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
          /* Final call to application handler: GET, HEAD requests */
          return http2_call_connection_handler (h2->connection, stream);
        }
      }
      break;
    case NGHTTP2_DATA:
      /* Check that the client request has finished */
      if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM)
      {
        stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
        if (stream != NULL)
        {
          /* Final call to application handler: POST, PUT requests */
          return http2_call_connection_handler (h2->connection, stream);
        }
      }
      break;
    case NGHTTP2_PRIORITY:
      break;
    case NGHTTP2_WINDOW_UPDATE:
      break;
    case NGHTTP2_RST_STREAM:
      break;
    case NGHTTP2_GOAWAY:
      break;
    default:
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
on_frame_send_callback(nghttp2_session *session,
                       const nghttp2_frame *frame, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  ENTER("[id=%d] frame->hd.type %s %X", h2->session_id, FRAME_TYPE (frame->hd.type), frame->hd.flags);
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
  // ENTER("[id=%d]", h2->session_id);

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
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
int
error_callback (nghttp2_session *session,
                const char *msg, size_t len,
                void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  mhd_assert (h2 != NULL);
  ENTER("[id=%d] %s", h2->session_id, msg);
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
  // ENTER("[id=%d] %s: %s", h2->session_id, name, value);

  stream = nghttp2_session_get_stream_user_data (session, frame->hd.stream_id);
  if (stream == NULL)
  {
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }

  if ((namelen == H2_HEADER_METHOD_LEN) &&
      (strncmp(H2_HEADER_METHOD, name, namelen) == 0))
  {
      stream->method = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      mhd_assert (NULL != stream->method) ;
      strcpy(stream->method, value);
  }
  else if ((namelen == H2_HEADER_SCHEME_LEN) &&
      (strncmp(H2_HEADER_SCHEME, name, namelen) == 0))
  {
      stream->scheme = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      mhd_assert (NULL != stream->scheme) ;
      strcpy(stream->scheme, value);
  }
  else if ((namelen == H2_HEADER_PATH_LEN) &&
      (strncmp(H2_HEADER_PATH, name, namelen) == 0))
  {
      stream->path = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      mhd_assert (NULL != stream->path) ;
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
  }
  else if ((namelen == H2_HEADER_AUTH_LEN) &&
      (strncmp(H2_HEADER_AUTH, name, namelen) == 0))
  {
      stream->authority = MHD_pool_allocate (stream->pool, valuelen + 1, MHD_YES);
      mhd_assert (NULL != stream->authority) ;
      strcpy(stream->authority, value);
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
  // ENTER("[id=%d]", h2->session_id);

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



/**
 * Callback: invoked when session wants to send data to the remote peer.
 * Sends at most length bytes of data stored in data.
 *
 * @param session session
 * @param data buffer to send
 * @param length size of data to send
 * @param flags currently not used
 * @param user_data HTTP2 connection of type http2_conn
 * @return If succeeds, returns the number of bytes sent.
 *         Otherwise, if it cannot send any single byte without blocking,
 *         it returns NGHTTP2_ERR_WOULDBLOCK.
 *         For other errors, it returns NGHTTP2_ERR_CALLBACK_FAILURE.
 */
static ssize_t
send_callback (nghttp2_session *session, const uint8_t *data,
               size_t length, int flags, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  (void) session;
  (void) flags;

  mhd_assert (h2 != NULL);
  mhd_assert (length > 0);

  struct MHD_Connection *connection = h2->connection;
  ssize_t ret;

  ret = connection->send_cls (connection, data, length);

  ENTER("[id=%d] len=%d ret=%d", h2->session_id, length, ret);
  if (ret < 0)
  {
    if (ret == MHD_ERR_AGAIN_)
    {
      /* Transmission could not be accomplished. Try again. */
      return NGHTTP2_ERR_WOULDBLOCK;
    }
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return ret;
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

  int rv;
  nghttp2_session_callbacks *callbacks;

  rv = nghttp2_session_callbacks_new (&callbacks);
  if (rv != 0)
  {
    mhd_assert (rv == NGHTTP2_ERR_NOMEM);
    return MHD_NO;
  }

  nghttp2_session_callbacks_set_send_callback (
    callbacks, send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback (
    callbacks, on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_frame_send_callback (
    callbacks, on_frame_send_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback (
    callbacks, on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback (
    callbacks, on_header_callback);

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
  // ENTER("[id=%d]", h2->session_id);

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
 * Send frames to the client.
 *
 * @param h2 HTTP/2 session
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
static int
http2_session_send (struct http2_conn *h2)
{
  // ENTER("[id=%d]", h2->session_id);
  int rv;
  rv = nghttp2_session_send (h2->session);
  if (rv != 0)
  {
    warnx("Fatal error: %s", nghttp2_strerror (rv));
    return MHD_NO;
  }
  return MHD_YES;
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
  // ENTER("[id=%d]", h2->session_id);

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
  connection->read_buffer_offset = 0;
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

  // ENTER("[id=%d]", connection->h2->session_id);

  /* Send server preface */
  rv = http2_session_send_preface (connection->h2);
  if (rv != MHD_YES)
  {
    MHD_http2_session_delete (connection);
    return MHD_NO;
  }

  connection->version = MHD_HTTP_VERSION_2_0;

  connection->state = MHD_CONNECTION_HTTP2_BUSY;
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
  // ENTER("[id=%d]", h2->session_id);

  connection->state = MHD_CONNECTION_HTTP2_BUSY;

  ssize_t bytes_read;
  bytes_read = connection->recv_cls (connection,
                                     connection->read_buffer,
                                     connection->read_buffer_size);
  // ENTER("read %d / %d", bytes_read, connection->read_buffer_size);
  if (bytes_read < 0)
  {
    if (bytes_read == MHD_ERR_AGAIN_)
       return MHD_NO; /* No new data to process. */
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

  /* This should be moved to handle_idle() because that's were the parsing is done for HTTP/1 */
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
    nghttp2_session_send(h2->session);
    connection_close_error (connection,
                            _("Connection socket is closed due to unexpected error when parsing request.\n"));
    return MHD_NO;
  }

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
  // ENTER("[id=%d]", h2->session_id); //, MHD_state_to_string (connection->state));

  if ((nghttp2_session_want_read (h2->session) == 0) &&
      (nghttp2_session_want_write (h2->session) == 0))
  {
    MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_COMPLETED_OK);
    return MHD_NO;
  }

  ssize_t ret;
  ret = http2_session_send (h2);
  if (ret < 0)
  {
    if (ret == MHD_ERR_AGAIN_)
      return MHD_NO;
    MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
    return MHD_NO;
  }

  MHD_update_last_activity_ (connection);
  connection->state = MHD_CONNECTION_HTTP2_IDLE;
  h2->connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (h2->connection);
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
  // ENTER("[id=%d]", connection->h2->session_id);
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
  // ENTER("[id=%d]", connection->h2->session_id);

  stream = nghttp2_session_get_stream_user_data (h2->session, h2->current_stream_id);
  if (stream == NULL)
  {
    return MHD_NO;
  }

  MHD_increment_response_rc (response);
  stream->response = response;
  stream->response_code = status_code;
#if defined(_MHD_HAVE_SENDFILE)
  if ( (response->fd == -1) ||
       (0 != (connection->daemon->options & MHD_USE_TLS)) )
    stream->resp_sender = MHD_resp_sender_std;
  else
    stream->resp_sender = MHD_resp_sender_sendfile;
#endif /* _MHD_HAVE_SENDFILE */

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

  int r = build_headers(h2, stream, response);
  if (r != 0)
  {
    return MHD_NO;
  }

  connection->state = MHD_CONNECTION_HTTP2_BUSY;
  connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (connection);
#endif /* EPOLL_SUPPORT */
  return MHD_YES;
}

#endif /* HTTP2_SUPPORT */

/* end of connection_http2.c */
