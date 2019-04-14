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

#undef COLOR_RED
#define COLOR_RED    "\033[33;1m"

/* Number of sessions, for debugging purposes */
size_t num_sessions = 0;

/**
 * Add a stream to the end of the stream list.
 *
 * @param h2 HTTP/2 session
 * @param stream new stream to add to the session
 */
void
h2_session_add_stream (struct h2_session_t *h2, struct h2_stream_t *stream)
{
  mhd_assert (h2 != NULL && stream != NULL);
  DLL_insert (h2->streams, h2->streams_tail, stream);
}


/**
 * Remove a stream from the stream list.
 *
 * @param h2 HTTP/2 session
 * @param stream stream to remove from the session
 */
void
h2_session_remove_stream (struct h2_session_t *h2, struct h2_stream_t *stream)
{
  mhd_assert (h2->num_streams > 0);
  h2->num_streams--;

  DLL_remove (h2->streams, h2->streams_tail, stream);
  h2_stream_destroy (stream);
}


/**
 * Processes the data received by the client.
 *
 * @param h2 HTTP/2 session to handle
 * @param in data to process
 * @param inlen length of data to process
 * @return If succeeds, returns the number of processed bytes.
 *         Otherwise, sends a GOAWAY frame and return -1.
 */
ssize_t
h2_session_read_data (struct h2_session_t *h2, const uint8_t *in, size_t inlen)
{
  struct MHD_Daemon *daemon = h2->c->daemon;

  ssize_t rv;
  rv = nghttp2_session_mem_recv (h2->session, in, inlen);
  if (rv < 0)
    {
      if (rv != NGHTTP2_ERR_BAD_CLIENT_MAGIC)
        {
          MHD_DLOG (daemon,
              _("nghttp2_session_mem_recv () returned error: %s %zd\n"),
              nghttp2_strerror (rv), rv);
        }
      /* Should send a GOAWAY frame with last stream_id successfully received */
      rv = nghttp2_submit_goaway (h2->session, NGHTTP2_FLAG_NONE, h2->last_stream_id,
                                  NGHTTP2_PROTOCOL_ERROR, NULL, 0);
      rv = rv ?: nghttp2_session_send (h2->session);
      return -1;
    }
  return rv;
}

/**
 * Sends at most length bytes of data stored in data.
 *
 * @param h2      HTTP/2 session to handle
 * @param out     data to process
 * @param outlen  length of data to process
 * @append_offset Last valid location in write_buffer (need to update because DATA
 *                frames are written directly in the buffer, not in this function).
 *                See send_data_cb in h2_callbacks.c
 * @return If succeeds, returns the number of written bytes >= 0.
 *         Otherwise, returns -1.
 */
ssize_t
h2_session_write_data (struct h2_session_t *h2, uint8_t *out, size_t outlen,
                       size_t *append_offset)
{
  /* If there is pending data from previous nghttp2_session_mem_send call */
  if (h2->pending_write_data)
    {
      ENTER ("h2->pending_write_data=%zu", h2->pending_write_data_len);
      size_t n = MHD_MIN (outlen, h2->pending_write_data_len);

      memcpy (out, h2->pending_write_data, n);

      /* Update buffer offset */
      outlen -= n;
      out += n;

      /* Not enough space for all pending data */
      if (n < h2->pending_write_data_len)
        {
          h2->pending_write_data += n;
          h2->pending_write_data_len -= n;
          return n;
        }

      /* Reset */
      h2->pending_write_data = NULL;
      h2->pending_write_data_len = 0;
    }

  ssize_t total_bytes = 0;
  for (;;)
    {
      const uint8_t *data;
      ssize_t data_len;
      data_len = nghttp2_session_mem_send (h2->session, &data);

      if (data_len < 0)
        return -1;

      if (data_len == 0)
        break;

      size_t n = MHD_MIN (outlen, data_len);
      memcpy (out, data, n);
      total_bytes += n;

      /* Update buffer offset */
      outlen -= n;
      out += n;
      *append_offset += n;
      ENTER("n=%d --> append=%d", n, *append_offset);

      /* Not enough space in write_buffer for all data */
      if (n < data_len)
        {
          ENTER("pending data! %d", data_len - n);
          h2->pending_write_data = data + n;
          h2->pending_write_data_len = data_len - n;
          break;
        }
    }
  return total_bytes;
}

/**
 * Send HTTP/2 server connection preface.
 *
 * @param h2 HTTP/2 session to handle
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
int
h2_session_send_preface (struct h2_session_t *h2)
{
  struct MHD_Daemon *daemon = h2->c->daemon;
  int rv;

  /* Flags currently ignored */
  rv = nghttp2_submit_settings (h2->session, NGHTTP2_FLAG_NONE,
                                h2->settings, h2->settings_len);
  if (rv != 0)
    {
      MHD_DLOG (daemon, _("Fatal error: %s\n"), nghttp2_strerror (rv));
      return MHD_NO;
    }
  return MHD_YES;
}


/**
* Delete HTTP2 structures.
*
* @param h2 HTTP/2 session to handle
*/
void
h2_session_destroy (struct h2_session_t *h2)
{
  mhd_assert (NULL != h2);

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
 * Initialize HTTP2 structures, set the initial local settings for the session,
 * and send server preface.
 *
 * @param pid Thread handle for this connection.
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise, connection must be closed.
 */
struct h2_session_t *
h2_session_create (struct MHD_Connection *connection)
{
  struct MHD_Daemon *daemon = connection->daemon;
  int rv;

  struct h2_session_t *h2 = calloc (1, sizeof (struct h2_session_t));
  if (NULL == h2)
    {
      return NULL;
    }

  h2->session_id = ++num_sessions;
  h2->c = connection;

  /* Set initial local session settings */
  h2->settings = h2_config_get_settings (daemon->h2_config);
  h2->settings_len = h2_config_get_settings_len (daemon->h2_config);

  /* Create session and send server preface */
  if ( (MHD_YES != h2_session_set_callbacks (h2)) ||
       (MHD_YES != h2_session_send_preface (h2)) )
    {
      h2_session_destroy (h2);
      return NULL;
    }

  return h2;
}

/**
 * Performs post-process of HTTP Upgrade request.
 * @param h2 HTTP/2 session to handle
 * @param settings
 * @param method
 * @return #MHD_YES if no error
 *         #MHD_NO otherwise.
 */
int
h2_session_upgrade (struct h2_session_t *h2,
                    const char *settings, const char *method)
{
  char *settings_payload;
  size_t len;

  settings_payload = BASE64Decode (settings);
  len = strlen (settings_payload);

  /* Is it a HEAD request? */
  int head_request;
  head_request = MHD_str_equal_caseless_ (method, MHD_HTTP_METHOD_HEAD) ? 1 : 0;

  int ret;
  ret = nghttp2_session_upgrade2 (h2->session, settings_payload, len,
                                  head_request, NULL);
  free (settings_payload);

  if (0 != ret)
    {
      return MHD_NO;
    }
  return MHD_YES;
}

/* end of h2_session.c */
