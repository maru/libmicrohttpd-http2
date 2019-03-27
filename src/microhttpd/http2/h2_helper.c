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
 * @file microhttpd/http2/h2_helper.c
 * @brief Methods for printing HTTP/2 frames
 * @author Maru Berezin, inspired from nghttpd
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"

char * FRAME_TYPE(int type)
{
  switch (type)
  {
    case NGHTTP2_DATA: return "DATA";
    case NGHTTP2_HEADERS: return "HEADERS";
    case NGHTTP2_PRIORITY: return "PRIORITY";
    case NGHTTP2_RST_STREAM: return "RST_STREAM";
    case NGHTTP2_SETTINGS: return "SETTINGS";
    case NGHTTP2_PUSH_PROMISE: return "PUSH_PROMISE";
    case NGHTTP2_PING: return "PING";
    case NGHTTP2_GOAWAY: return "GOAWAY";
    case NGHTTP2_WINDOW_UPDATE: return "WINDOW_UPDATE";
    case NGHTTP2_CONTINUATION: return "CONTINUATION";
    case NGHTTP2_ALTSVC: return "ALTSVC";
  }
  return "???";
}

#define bufsize 1024
char s[bufsize];

void print_flags(const nghttp2_frame_hd hd)
{
  memset (s, 0, sizeof(s));
  size_t len = bufsize - 1;
  switch (hd.type)
    {
    case NGHTTP2_DATA:
      if (hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
          strncat(s, "END_STREAM", len);
          len -= 10;
        }
      if (hd.flags & NGHTTP2_FLAG_PADDED)
        {
          if (len < bufsize - 1)
            {
              strncat(s, " | ", len);
              len -= 3;
            }
          strncat(s, "PADDED", len);
          len -= 6;
        }
      break;
    case NGHTTP2_HEADERS:
      if (hd.flags & NGHTTP2_FLAG_END_STREAM)
        {
          strncat(s, "END_STREAM", len);
          len -= 10;
        }
      if (hd.flags & NGHTTP2_FLAG_END_HEADERS)
        {
          if (len < bufsize - 1)
            {
              strncat(s, " | ", len);
              len -= 3;
            }
          strncat(s, "END_HEADERS", len);
          len -= 11;
        }
      if (hd.flags & NGHTTP2_FLAG_PADDED)
        {
          if (len < bufsize - 1)
            {
              strncat(s, " | ", len);
              len -= 3;
            }
          strncat(s, "PADDED", len);
          len -= 6;
        }
      if (hd.flags & NGHTTP2_FLAG_PRIORITY)
        {
          if (len < bufsize - 1)
            {
              strncat(s, " | ", len);
              len -= 3;
            }
          strncat(s, "PRIORITY", len);
          len -= 8;
        }
      break;
    case NGHTTP2_PRIORITY:
      break;
    case NGHTTP2_SETTINGS:
      if (hd.flags & NGHTTP2_FLAG_ACK)
        {
          strncat(s, "ACK", len);
          len -= 3;
        }
      break;
    case NGHTTP2_PUSH_PROMISE:
      if (hd.flags & NGHTTP2_FLAG_END_HEADERS)
        {
          strncat(s, "END_HEADERS", len);
          len -= 11;
        }
      if (hd.flags & NGHTTP2_FLAG_PADDED)
        {
          if (len < bufsize - 1)
            {
              strncat(s, " | ", len);
              len -= 3;
            }
          strncat(s, "PADDED", len);
          len -= 6;
        }
      break;
    case NGHTTP2_PING:
      if (hd.flags & NGHTTP2_FLAG_ACK)
        {
          strncat(s, "ACK", len);
          len -= 3;
        }
      break;
  }
  mhd_assert(s[bufsize - len] == '\0');
  h2_debug_vprintf ("; %s", s);
}

/* end of h2_helper.c */
