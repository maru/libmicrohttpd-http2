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
#include "memorypool.h"

/* ================================================================ */
/*                        Stream operations                         */
/* ================================================================ */

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

  stream->pool = MHD_pool_create (pool_size);
  if (NULL == stream->pool)
    {
      free (stream);
      return NULL;
    }

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
  // h2_debug_vprintf ("id=%zu stream_id=%zu", h2->session_id, stream->stream_id);
  if (stream->response)
    {
      MHD_destroy_response (stream->response);
      stream->response = NULL;

      // struct MHD_Connection *connection = h2->connection;
      // if ((NULL != connection->daemon->notify_completed) && (stream->client_aware))
      //   {
      //     stream->client_aware = false;
      //     connection->daemon->notify_completed (connection->daemon->notify_completed_cls,
      //       connection, &stream->client_context,
      //       MHD_REQUEST_TERMINATED_COMPLETED_OK);
      //   }
    }
  MHD_pool_destroy (stream->pool);
  stream->pool = NULL;
  free (stream);
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
int
h2_stream_parse_cookie_header (struct MHD_Connection *connection,
                               struct h2_stream_t *stream,
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
        if (MHD_NO == MHD_set_connection_value (connection, MHD_COOKIE_KIND, pos, ""))
          {
          #ifdef HAVE_MESSAGES
            MHD_DLOG (connection->daemon,
                        _("Not enough memory in pool to allocate header record!\n"));
          #endif
            return MHD_NO;
          }
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
      if (MHD_NO == MHD_set_connection_value (connection, MHD_COOKIE_KIND, pos, equals))
        {
          #ifdef HAVE_MESSAGES
            MHD_DLOG (connection->daemon,
                        _("Not enough memory in pool to allocate header record!\n"));
          #endif
          return MHD_NO;
        }
      pos = semicolon;
    }
  return MHD_YES;
}

/* end of h2_stream.c */
