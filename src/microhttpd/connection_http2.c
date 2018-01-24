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

#ifdef HTTP2_SUPPORT

#define ENTER(format, args...) fprintf(stderr, "\e[31;1m[%s]\e[0m " format "\n", __FUNCTION__, ##args)

#define warnx(format, args...) fprintf(stderr, format "\n", ##args)

#define ARRLEN(x) (sizeof(x) / sizeof(x[0]))

#define MAKE_NV(NAME, VALUE)                                                   \
  {                                                                            \
    (uint8_t *)NAME, (uint8_t *)VALUE, sizeof(NAME) - 1, sizeof(VALUE) - 1,    \
        NGHTTP2_NV_FLAG_NONE                                                   \
  }

static size_t num_sessions = 0;

/* ================================================================ */
/*                         Stream operations                        */
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
  mhd_assert(h2 != NULL && stream != NULL);

  // First element
  if (h2->streams == NULL)
  {
    h2->streams = stream;
    stream->prev = NULL;
  }
  else
  {
    mhd_assert(h2->streams != NULL);
    mhd_assert(h2->streams_tail != NULL);

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
  mhd_assert(h2 != NULL && stream != NULL);

  // Only one element
  if (h2->streams == h2->streams_tail)
  {
    mhd_assert(h2->streams != NULL);
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
  stream = calloc(1, sizeof(struct http2_stream));
  if (NULL == stream)
  {
    return NULL;
  }

  stream->stream_id = stream_id;
  h2->num_streams++;
  add_stream (h2, stream);
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
  mhd_assert(h2->num_streams > 0);
  h2->num_streams--;
  remove_stream (h2, stream);
  free (stream);
}


/* ================================================================ */
/*                             Callbacks                            */
/* ================================================================ */

/**
 *
 *
 * @param
 * @param
 * @param
 * @param
 * @param
 * @param
 * @param
 * @return
 */
static ssize_t str_read_callback(nghttp2_session *session,
                                 int32_t stream_id, uint8_t *buf,
                                 size_t length, uint32_t *data_flags,
                                 nghttp2_data_source *source,
                                 void *user_data)
{
  ssize_t len = strlen(source->ptr);
  memcpy(buf, source->ptr, len);
  *data_flags |= NGHTTP2_DATA_FLAG_EOF;
  return len;
}


/**
 *
 *
 * @param
 * @param
 * @param
 * @param
 * @param
 * @return
 */
static int
send_response(nghttp2_session *session, int32_t stream_id,
                         nghttp2_nv *nva, size_t nvlen, void *ptr)
{
  int rv;
  nghttp2_data_provider data_prd;
  data_prd.source.ptr = ptr;
  data_prd.read_callback = str_read_callback;

  rv = nghttp2_submit_response(session, stream_id, nva, nvlen, &data_prd);
  if (rv != 0) {
    warnx("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}


/**
 * Call the handler of the application for this
 * connection.  Handles chunking of the upload
 * as well as normal uploads.
 *
 * @param connection connection we are processing
 * @param stream     stream we are processing
 */
static void
http2_call_connection_handler (struct MHD_Connection *connection, struct http2_stream *stream)
{
  size_t processed;

  if (NULL != stream->response)
    return;                     /* already queued a response */
  processed = 0;
  stream->client_aware = true;
  if (MHD_NO ==
      connection->daemon->default_handler (connection->daemon->default_handler_cls,
					   connection, stream->url, stream->method, MHD_HTTP_VERSION_2_0,
             /* upload_data */ NULL, &processed,
					   &stream->client_context))
    {
      /* serious internal error, close connection */
      connection_close_error (connection,
			      _("Application reported internal error, closing connection.\n"));
      return;
    }
}

/**
 *
 *
 * @param
 * @param
 * @param
 * @return
 */
static int
on_request_recv(nghttp2_session *session,
                           struct http2_conn *h2,
                           struct http2_stream *stream)
{
  int fd;
  nghttp2_nv hdrs[] = {MAKE_NV(":status", "200")};
  char *rel_path;
  ENTER();

  http2_call_connection_handler (h2->connection, stream);
  return 0;
  char *page = "<html><head><title>libmicrohttpd demo</title></head><body>libmicrohttpd demo</body></html>\n";
  if (send_response(session, stream->stream_id, hdrs, ARRLEN(hdrs), page) !=
      0) {
    close(fd);
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  return 0;
}

#define FRAME_TYPE(x) (x==NGHTTP2_DATA?"DATA":(x==NGHTTP2_HEADERS?"HEADERS":(x==NGHTTP2_PRIORITY?"PRIORITY":(x==NGHTTP2_RST_STREAM?"RST_STREAM":(x==NGHTTP2_SETTINGS?"SETTINGS":(x==NGHTTP2_PUSH_PROMISE?"PUSH_PROMISE":(x==NGHTTP2_PING?"PING":(x==NGHTTP2_GOAWAY?"GOAWAY":(x==NGHTTP2_WINDOW_UPDATE?"WINDOW_UPDATE":(x==NGHTTP2_CONTINUATION?"CONTINUATION":(x==NGHTTP2_ALTSVC?"ALTSVC":"-")))))))))))

/**
 *
 *
 * @param
 * @param
 * @param
 * @return
 */
static int
on_frame_recv_callback(nghttp2_session *session,
                                  const nghttp2_frame *frame, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *) user_data;
  struct http2_stream *stream;
  ENTER("[id=%d] frame->hd.type %s", h2->session_id, FRAME_TYPE(frame->hd.type));
  switch (frame->hd.type) {
  case NGHTTP2_DATA:
  case NGHTTP2_HEADERS:
    /* Check that the client request has finished */
    if (frame->hd.flags & NGHTTP2_FLAG_END_STREAM) {
      stream =
          nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);
      /* For DATA and HEADERS frame, this callback may be called after
         on_stream_close_callback. Check that stream still alive. */
      if (!stream) {
        return 0;
      }
      return on_request_recv(session, h2, stream);
    }
    break;
  default:
    break;
  }
  return 0;
}

/**
 *
 *
 * @param
 * @param
 * @param
 * @return
 */
static int on_begin_headers_callback(nghttp2_session *session,
                                     const nghttp2_frame *frame,
                                     void *user_data) {
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  ENTER("[id=%d]", h2->session_id);

  if (frame->hd.type != NGHTTP2_HEADERS ||
      frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
    return 0;
  }
  stream = http2_stream_create(h2, frame->hd.stream_id);
  if (stream == NULL)
  {
    // Out of memory.
    return NGHTTP2_ERR_CALLBACK_FAILURE;
  }
  nghttp2_session_set_stream_user_data(session, frame->hd.stream_id,
                                       stream);
  return 0;
}

/**
 *
 *
 * @param
 * @param
 * @param
 * @param
 * @param
 * @param
 * @param
 * @param
 * @return
 */
/* nghttp2_on_header_callback: Called when nghttp2 library emits
   single header name/value pair. */
static int on_header_callback(nghttp2_session *session,
                              const nghttp2_frame *frame, const uint8_t *name,
                              size_t namelen, const uint8_t *value,
                              size_t valuelen, uint8_t flags, void *user_data)
{
  (void)flags;
  struct http2_conn *h2 = (struct http2_conn *)user_data;

  char buf[10000]; int j = 0;
  for (int i = 0; i < namelen; i++) {
    buf[j++] = name[i];
  }
  buf[j++] = ' ';
  for (int i = 0; i < valuelen; i++) {
    buf[j++] = value[i];
  }
  buf[j++] = '\0';
  ENTER("%s", buf);

  switch (frame->hd.type) {
  case NGHTTP2_HEADERS:
    if (frame->headers.cat != NGHTTP2_HCAT_REQUEST) {
      break;
    }
    struct http2_stream *stream =
        nghttp2_session_get_stream_user_data(session, frame->hd.stream_id);

    if (namelen == 7 && memcmp(name, ":method", namelen) == 0) {
      stream->method = malloc(valuelen+1);
      strncpy(stream->method, value, valuelen);
    } else if (namelen == 5 && memcmp(name, ":path", namelen) == 0) {
      stream->url = malloc(valuelen+1);
      strncpy(stream->url, value, valuelen);
    }

    break;
  default: mhd_assert(0);
  }
  return 0;
}

/**
 *
 *
 * @param
 * @param
 * @param
 * @param
 * @return
 */
static int
on_stream_close_callback(nghttp2_session *session, int32_t stream_id,
                                    uint32_t error_code, void *user_data)
{
  struct http2_conn *h2 = (struct http2_conn *)user_data;
  struct http2_stream *stream;
  (void)error_code;
  ENTER("[id=%d]", h2->session_id);

  stream = nghttp2_session_get_stream_user_data(session, stream_id);
  if (!stream) {
    return 0;
  }
  http2_stream_delete (h2, stream);
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
 * @param user_data connection of type MHD_Connection
 * @return If succeeds, returns the number of bytes sent.
           Otherwise, if it cannot send any single byte without blocking,
           it returns NGHTTP2_ERR_WOULDBLOCK.
           For other errors, it returns NGHTTP2_ERR_CALLBACK_FAILURE.
 */
static ssize_t
send_callback(nghttp2_session *session, const uint8_t *data,
              size_t length, int flags, void *user_data)
{
  const struct http2_conn *h2 = (struct http2_conn *) user_data;
  (void) session;
  (void) flags;

  mhd_assert(h2 != NULL);
  mhd_assert(length > 0);
  struct MHD_Connection *connection = h2->connection;
  const ssize_t ret = connection->send_cls (connection, data, length);
  ENTER("[id=%d] ret=%d", h2->session_id, ret);
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


/**
 * Set local session settings and callbacks.
 *
 * @param connection connection of the session
 * @return
 */
static int
http2_session_init (struct MHD_Connection *connection)
{
  mhd_assert(connection != NULL && connection->daemon != NULL);

  struct http2_conn *h2 = connection->h2;
  mhd_assert(h2 != NULL);

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
    // NGHTTP2_ERR_NOMEM
    return rv;
  }

  nghttp2_session_callbacks_set_send_callback (callbacks,
                                                     send_callback);

  nghttp2_session_callbacks_set_on_frame_recv_callback (callbacks,
                                                     on_frame_recv_callback);

  nghttp2_session_callbacks_set_on_stream_close_callback (callbacks,
                                                     on_stream_close_callback);

  nghttp2_session_callbacks_set_on_header_callback (callbacks,
                                                     on_header_callback);

  nghttp2_session_callbacks_set_on_begin_headers_callback (callbacks,
                                                     on_begin_headers_callback);

  rv = nghttp2_session_server_new (&h2->session, callbacks, h2);
  if (rv != 0)
  {
    // NGHTTP2_ERR_NOMEM
    return rv;
  }

  nghttp2_session_callbacks_del (callbacks);
  return 0;
}



/**
 *
 *
 * @param h2
 * @return
 */
/* Serialize the frame and send (or buffer) the data to
   bufferevent. */
static int
http2_session_send(struct http2_conn *h2)
{
  ENTER("[id=%d]", h2->session_id);
  int rv;
  rv = nghttp2_session_send(h2->session);
  if (rv != 0) {
    ENTER("Fatal error: %s", nghttp2_strerror(rv));
    return -1;
  }
  return 0;
}

/**
 * Read data from input buffer and
 *
 * @param connection
 * @return
 */
/* Read the data in the bufferevent and feed them into nghttp2 library
   function. Invocation of nghttp2_session_mem_recv() may make
   additional pending frames, so call session_send() at the end of the
   function. */
static int
http2_session_recv(struct MHD_Connection *connection)
{
  mhd_assert(connection);
  if (0 == connection->read_buffer_offset) {
    return 0;
  }

  ssize_t readlen;

  struct http2_conn *h2 = connection->h2;
  size_t datalen = connection->read_buffer_offset;
  unsigned char *data = connection->read_buffer;

  ENTER("[id=%d]", h2->session_id);

  mhd_assert(data);
  mhd_assert(datalen <= connection->read_buffer_size);
  mhd_assert(datalen <= connection->read_buffer_offset);

  connection->read_buffer += datalen;
  connection->read_buffer_size -= datalen;
  connection->read_buffer_offset -= datalen;

  mhd_assert(h2 && h2->session);
  readlen = nghttp2_session_mem_recv (h2->session, data, datalen);
  if (readlen < 0) {
    warnx("Fatal error: %s", nghttp2_strerror((int)readlen));
    return -1;
  }
  h2->connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
#ifdef EPOLL_SUPPORT
  MHD_connection_epoll_update_ (h2->connection);
#endif /* EPOLL_SUPPORT */
// -  if (http2_session_send(h2) != 0) {
// -    return -1;
// -  }
// -  return 0;
}



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
}

/**
 * Send HTTP/2 server connection preface.
 *
 * @param connection connection to handle
 * @return
 */
int
http2_session_send_preface (struct http2_conn *h2)
{
  int rv;
  ENTER("[id=%d]", h2->session_id);

  rv = nghttp2_submit_settings (h2->session, NGHTTP2_FLAG_NONE,
                                h2->settings, h2->settings_len);
  if (rv != 0)
  {
    ENTER("Fatal error: %s", nghttp2_strerror(rv));
    return MHD_NO;
  }
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
int
MHD_http2_session_start (struct MHD_Connection *connection)
{
  int rv;
  ENTER();
  connection->state = MHD_CONNECTION_HTTP2_INIT;

  if (connection->h2 != NULL) return MHD_YES;
  connection->h2 = calloc(1, sizeof(struct http2_conn));
  if (connection->h2 == NULL)
  {
    connection->state = MHD_CONNECTION_HTTP2_CLOSED;
    return MHD_NO;
  }

  /* Create session and fill callbacks */
  rv = http2_session_init (connection);
  if (rv != 0)
  {
    MHD_http2_session_delete (connection);
    return MHD_NO;
  }

  /* Send server preface */
  rv = http2_session_send_preface (connection->h2);
  if (rv == MHD_NO)
  {
    MHD_http2_session_delete (connection);
    return MHD_NO;
  }

  connection->state = MHD_CONNECTION_HTTP2_OPEN;

  return MHD_YES;
}


/**
 * Callback: invoked when there is data to be read from the connection.
 *
 * @param connection connection to handle
 * @return #MHD_YES if we should continue to process the
 *         connection (not dead yet), #MHD_NO if it died
 */
int
MHD_http2_handle_read (struct MHD_Connection *connection)
{
  ENTER();
  if (connection->state == MHD_CONNECTION_HTTP2_INIT)
    {
      return MHD_NO;
    }

  int rv;

  for (;;) {
    /* make sure "read" has a reasonable number of bytes
       in buffer to use per system call (if possible) */
    // if (connection->read_buffer_offset + connection->daemon->pool_increment >
    //     connection->read_buffer_size)
    //   try_grow_read_buffer (connection);

    // if (connection->read_buffer_size == connection->read_buffer_offset) {
    //   ENTER("No space");
    //   exit(0);
    //   return MHD_NO; /* No space for receiving data. */
    // }

    ssize_t bytes_read;
    size_t read_buffer_size = 1 << 13;
    uint8_t *read_buffer = (uint8_t *) malloc(read_buffer_size*sizeof(uint8_t));
    bytes_read = connection->recv_cls (connection,
                                       read_buffer,
                                       read_buffer_size);
ENTER("read %d", bytes_read);
    if (bytes_read < 0)
      {
        if (MHD_ERR_AGAIN_ == bytes_read)
            return MHD_NO; /* No new data to process. */
        if (MHD_ERR_CONNRESET_ == bytes_read)
          {
             connection_close_error (connection,
                                       _("Socket is unexpectedly disconnected when reading request.\n"));
             return MHD_NO;
          }
        connection_close_error (connection,
                                  _("Connection socket is closed due to unexpected error when reading request.\n"));
        return MHD_NO;
      }

    if (0 == bytes_read)
      { /* Remote side closed connection. */
        connection->read_closed = true;
        MHD_connection_close_ (connection,
                               MHD_REQUEST_TERMINATED_CLIENT_ABORT);
        return MHD_NO;
      }

    rv = nghttp2_session_mem_recv(connection->h2->session, read_buffer, bytes_read);
    if (rv < 0) {
      if (rv != NGHTTP2_ERR_BAD_CLIENT_MAGIC) {
        fprintf(stderr, "nghttp2_session_mem_recv() returned error: %d\n", nghttp2_strerror(rv));
      }
      connection_close_error (connection,
                                _("Connection socket is closed due to unexpected error when parsing request.\n"));
      return MHD_NO;
    }
    connection->event_loop_info = MHD_EVENT_LOOP_INFO_WRITE;
  #ifdef EPOLL_SUPPORT
    MHD_connection_epoll_update_ (connection);
  #endif /* EPOLL_SUPPORT */
    MHD_update_last_activity_ (connection);
  }
  return MHD_YES;
}


/**
 * Callback: invoked when there is data to be written to the connection.
 *
 * @param connection connection to handle
 * @return #MHD_YES if we should continue to process the
 *         connection (not dead yet), #MHD_NO if it died
 */
int
MHD_http2_handle_write (struct MHD_Connection *connection)
{
  ENTER("connection->responseCode %d", connection->responseCode);
  struct http2_conn *h2 = connection->h2;
  mhd_assert(h2 != NULL);

  if (nghttp2_session_want_read (h2->session) == 0 &&
      nghttp2_session_want_write (h2->session) == 0)
  {
    MHD_http2_session_delete (connection);
    MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_COMPLETED_OK);
    return MHD_NO;
  }

  ssize_t ret;
  ret = http2_session_send (h2);
  if (ret < 0)
  {
    if (MHD_ERR_AGAIN_ == ret)
      return MHD_NO;
    MHD_http2_session_delete (connection);
    MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
    return MHD_NO;
  }
  connection->write_buffer_send_offset += ret;
  MHD_update_last_activity_ (connection);
  if (1) // check_write_done (connection, MHD_CONNECTION_HTTP2_OPEN) == MHD_YES)
  {
    h2->connection->event_loop_info = MHD_EVENT_LOOP_INFO_READ;
#ifdef EPOLL_SUPPORT
    MHD_connection_epoll_update_ (h2->connection);
#endif /* EPOLL_SUPPORT */
  } else {
    mhd_assert(0);
  }
  return MHD_YES;
}


/**
 * This function was created to handle per-connection processing that
 * has to happen even if the socket cannot be read or written to.
 * @remark To be called only from thread that process connection's
 * recv(), send() and response.
 *
 * @param connection connection to handle
 * @return #MHD_YES if we should continue to process the
 *         connection (not dead yet), #MHD_NO if it died
 */
int
MHD_http2_handle_idle (struct MHD_Connection *connection)
{
  ENTER("enter: %d", connection->event_loop_info);

  // if (0 != http2_session_recv (connection))
  // {
  //   MHD_http2_session_delete (connection);
  //   MHD_connection_close_ (connection, MHD_REQUEST_TERMINATED_WITH_ERROR);
  //   return MHD_NO;
  // }
// ENTER("exit: %d", connection->event_loop_info);
  return MHD_YES;
}


#endif /* HTTP2_SUPPORT */

/* end of connection_http2.c */
