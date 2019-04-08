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
 * @author code from nghttp2 (see copyright below), ported to C by Maru Berezin
 */

/*
 * nghttp2 - HTTP/2 C Library
 *
 * Copyright (c) 2013, 2014 Tatsuhiro Tsujikawa
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice shall be
 * included in all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
 * NONINFRINGEMENT. IN NO EVENT SHALL THE AUTHORS OR COPYRIGHT HOLDERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"

struct timeval h2_util_tm_start;
int color_output;

void set_timer () { gettimeofday(&h2_util_tm_start, NULL); }

void set_color_output (bool f) { color_output = f; }

const char *do_color (const char *code) { return color_output ? code : ""; }

const char *
strsettingsid (int32_t id)
{
  switch (id)
    {
    case NGHTTP2_SETTINGS_HEADER_TABLE_SIZE:
      return "SETTINGS_HEADER_TABLE_SIZE";
    case NGHTTP2_SETTINGS_ENABLE_PUSH:
      return "SETTINGS_ENABLE_PUSH";
    case NGHTTP2_SETTINGS_MAX_CONCURRENT_STREAMS:
      return "SETTINGS_MAX_CONCURRENT_STREAMS";
    case NGHTTP2_SETTINGS_INITIAL_WINDOW_SIZE:
      return "SETTINGS_INITIAL_WINDOW_SIZE";
    case NGHTTP2_SETTINGS_MAX_FRAME_SIZE:
      return "SETTINGS_MAX_FRAME_SIZE";
    case NGHTTP2_SETTINGS_MAX_HEADER_LIST_SIZE:
      return "SETTINGS_MAX_HEADER_LIST_SIZE";
    default:
      return "UNKNOWN";
    }
}

const char *
frame_type (uint8_t type)
{
  switch (type)
    {
    case NGHTTP2_DATA:
      return "DATA";
    case NGHTTP2_HEADERS:
      return "HEADERS";
    case NGHTTP2_PRIORITY:
      return "PRIORITY";
    case NGHTTP2_RST_STREAM:
      return "RST_STREAM";
    case NGHTTP2_SETTINGS:
      return "SETTINGS";
    case NGHTTP2_PUSH_PROMISE:
      return "PUSH_PROMISE";
    case NGHTTP2_PING:
      return "PING";
    case NGHTTP2_GOAWAY:
      return "GOAWAY";
    case NGHTTP2_WINDOW_UPDATE:
      return "WINDOW_UPDATE";
    case NGHTTP2_CONTINUATION:
      return "CONTINUATION";
    case NGHTTP2_ALTSVC:
      return "ALTSVC";
    }
  return "<UNKNOWN>";
}

void h2_debug_print_indent () { fprintf (stderr, "%s", "          "); }

#define bufsize 1024
char s[bufsize];

void h2_debug_print_flags(const nghttp2_frame_hd hd)
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
  h2_debug_print_indent ();
  fprintf (stderr, "; %s\n", s);
}

void
h2_debug_print_time ()
{
  struct timeval now;
  gettimeofday(&now, NULL);

  time_t usec = (now.tv_sec - h2_util_tm_start.tv_sec)*1000000 + (now.tv_usec - h2_util_tm_start.tv_usec);
  time_t now_sec = usec/1000000;
  time_t now_msec = (usec/1000) % 1000;

  fprintf (stderr, "%s[%3ld.%03ld]", do_color(COLOR_YELLOW), now_sec, now_msec);
  fprintf (stderr, "%s ", do_color(COLOR_WHITE));
}

void h2_debug_print_session_id (size_t session_id) { fprintf (stderr, "[id=%zu] ", session_id); }

void
h2_debug_print_headers (nghttp2_nv *nva, size_t nvlen)
{
  for (size_t i = 0; i < nvlen; i++)
    {
      h2_debug_print_indent ();
      fprintf (stderr, "%s%s%s: %s\n", do_color(COLOR_LBLUE),
        nva[i].name, do_color(COLOR_WHITE), nva[i].value);
    }
}

void
h2_debug_print_header (size_t session_id, size_t stream_id, const uint8_t *name, const uint8_t *value)
{
  h2_debug_print_session_id (session_id);
  h2_debug_print_time ();

  fprintf (stderr, "recv (stream_id=%zu) ", stream_id);

  fprintf (stderr, "%s%s%s: %s\n", do_color(COLOR_LBLUE),
    name, do_color(COLOR_WHITE), value);
}

void
h2_debug_print_frame (size_t session_id, int action, const nghttp2_frame *frame)
{
  h2_debug_print_session_id (session_id);
  h2_debug_print_time ();
  fprintf (stderr, "%s %s%s%s frame <length=%zu, flags=0x%02X, stream_id=%u>\n",
      action == PRINT_RECV ? "recv" : "send",
      do_color(action == PRINT_RECV ? COLOR_RECV : COLOR_SEND),
      frame_type (frame->hd.type), do_color(COLOR_WHITE),
      frame->hd.length, frame->hd.flags, frame->hd.stream_id);

  if (frame->hd.flags) h2_debug_print_flags(frame->hd);

  switch (frame->hd.type)
    {
    case NGHTTP2_DATA:
      if (frame->data.padlen > 0)
        {
          h2_debug_print_indent ();
          fprintf (stderr, "(padlen=%zu)\n", frame->data.padlen);
        }
      break;
    case NGHTTP2_HEADERS:
      h2_debug_print_indent ();
      fprintf (stderr, "(padlen=%zu", frame->headers.padlen);
      if (frame->hd.flags & NGHTTP2_FLAG_PRIORITY)
        {
          fprintf (stderr, ", dep_stream_id=%d, weight=%u, exclusive=%d",
                   frame->headers.pri_spec.stream_id, frame->headers.pri_spec.weight,
                   frame->headers.pri_spec.exclusive);
        }
      fprintf (stderr, ")\n");
      switch (frame->headers.cat)
        {
        case NGHTTP2_HCAT_REQUEST:
          h2_debug_print_indent ();
          fprintf (stderr, "; Open new stream\n");
          break;
        case NGHTTP2_HCAT_RESPONSE:
          h2_debug_print_indent ();
          fprintf (stderr, "; First response header\n");
          break;
        case NGHTTP2_HCAT_PUSH_RESPONSE:
          h2_debug_print_indent ();
          fprintf (stderr, "; First push response header\n");
          break;
        default:
          break;
        }
      h2_debug_print_headers (frame->headers.nva, frame->headers.nvlen);
      break;
    case NGHTTP2_PRIORITY:
      h2_debug_print_indent ();
      fprintf (stderr, "(dep_stream_id=%d, weight=%u, exclusive=%d)\n",
               frame->priority.pri_spec.stream_id, frame->priority.pri_spec.weight,
               frame->priority.pri_spec.exclusive);
      break;
      case NGHTTP2_RST_STREAM:
        h2_debug_print_indent ();
        fprintf (stderr, "(error_code=%s(0x%02x))\n",
                 nghttp2_http2_strerror(frame->rst_stream.error_code),
                 frame->rst_stream.error_code);
        break;
      case NGHTTP2_SETTINGS:
        h2_debug_print_indent ();
        fprintf (stderr, "(niv=%lu)\n", (unsigned long)frame->settings.niv);
        for (size_t i = 0; i < frame->settings.niv; ++i)
          {
            h2_debug_print_indent ();
            fprintf (stderr, "[%s(0x%02x):%u]\n",
                     strsettingsid(frame->settings.iv[i].settings_id),
                     frame->settings.iv[i].settings_id, frame->settings.iv[i].value);
          }
        break;
      case NGHTTP2_PUSH_PROMISE:
        h2_debug_print_indent ();
        fprintf (stderr, "(padlen=%zu, promised_stream_id=%d)\n",
                 frame->push_promise.padlen, frame->push_promise.promised_stream_id);
        h2_debug_print_headers (frame->push_promise.nva, frame->push_promise.nvlen);
        break;
      case NGHTTP2_PING:
        h2_debug_print_indent ();
        fprintf (stderr, "(opaque_data=");
        for (size_t i = 0; i < 8; i++)
          {
            fprintf (stderr, "%X", frame->ping.opaque_data[i]);
          }
        fprintf (stderr, ")\n");
        break;
      case NGHTTP2_GOAWAY:
        h2_debug_print_indent ();
        fprintf (stderr,
                 "(last_stream_id=%d, error_code=%s(0x%02x), "
                 "opaque_data(%u)=[",
                 frame->goaway.last_stream_id,
                 nghttp2_http2_strerror(frame->goaway.error_code),
                 frame->goaway.error_code,
                 (int) frame->goaway.opaque_data_len);
        for (size_t i = 0; i < frame->goaway.opaque_data_len; i++)
          {
            uint8_t c = frame->goaway.opaque_data[i];
            fprintf (stderr, "%c", c >= 0x20 && c < 0x7f ? c : '.');
          }
        fprintf (stderr, "])\n");
        break;
      case NGHTTP2_WINDOW_UPDATE:
        h2_debug_print_indent ();
        fprintf (stderr, "(window_size_increment=%d)\n",
                 frame->window_update.window_size_increment);
        break;
      case NGHTTP2_ALTSVC:
        {
          const nghttp2_ext_altsvc *altsvc = (nghttp2_ext_altsvc *)(frame->ext.payload);
          h2_debug_print_indent ();
          fprintf (stderr, "(origin=[%.*s], altsvc_field_value=[%.*s])\n",
                   (int)(altsvc->origin_len), altsvc->origin,
                   (int)(altsvc->field_value_len), altsvc->field_value);
        }
        break;
      case NGHTTP2_ORIGIN:
        {
          const nghttp2_ext_origin *origin = (nghttp2_ext_origin *)(frame->ext.payload);
          for (size_t i = 0; i < origin->nov; ++i)
            {
              const nghttp2_origin_entry *ent = &origin->ov[i];
              h2_debug_print_indent ();
              fprintf (stderr, "[%.*s]\n", (int)ent->origin_len, ent->origin);
            }
        }
        break;
    }
}

/* end of h2_helper.c */
