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
 * @file microhttpd/connection_http2_helper.h
 * @brief Methods for printing HTTP/2 frames
 * @author Maru Berezin, inspired from nghttpd
 */


#ifndef HTTP2_HELPER_H
#define HTTP2_HELPER_H

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

/* Number of sessions, for debugging purposes */
static size_t num_sessions = 0;

#define warnx(format, args...) fprintf(stderr, format "\n", ##args)

#define FRAME_TYPE(x) (x==NGHTTP2_DATA?"DATA": (x==NGHTTP2_HEADERS?"HEADERS": (x==NGHTTP2_PRIORITY?"PRIORITY": (x==NGHTTP2_RST_STREAM?"RST_STREAM": (x==NGHTTP2_SETTINGS?"SETTINGS": (x==NGHTTP2_PUSH_PROMISE?"PUSH_PROMISE": (x==NGHTTP2_PING?"PING": (x==NGHTTP2_GOAWAY?"GOAWAY": (x==NGHTTP2_WINDOW_UPDATE?"WINDOW_UPDATE": (x==NGHTTP2_CONTINUATION?"CONTINUATION": (x==NGHTTP2_ALTSVC?"ALTSVC":"-")))))))))))

// #define ENTER_COLOR "32;1m"
#define ENTER_COLOR "31;1m"
int color;
#define do_color(code) (color ? code : "")
#define ENTER(format, args...) if (HTTP2_DEBUG) {\
  color = isatty(fileno(stderr));\
  struct timeval now; gettimeofday(&now, NULL);\
  long int milli = (now.tv_sec-tm_start.tv_sec)*1000000+(now.tv_usec-tm_start.tv_usec);\
  fprintf(stderr, "%s[%3ld.%03ld]%s ", do_color("\033[33m"), milli/1000000, (milli%1000000)/1000, do_color("\033[0m"));\
  fprintf(stderr, "%s[%s]%s " format "\n", do_color("\033["ENTER_COLOR), __FUNCTION__, do_color("\033[0m"), ##args);\
}

void print_flags(const nghttp2_frame_hd hd)
{
  char s[2000]; bool is_empty = true;
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

#endif
