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
 * @file microhttpd_http2.h
 * @brief interface for HTTP2 support
 * @author Maru Berezin
 */

#ifndef MICROHTTPD_HTTP2_H
#define MICROHTTPD_HTTP2_H

#include <nghttp2/nghttp2.h>

typedef nghttp2_settings_entry h2_settings_entry;

/**
 * @brief Flags for the `struct MHD_Daemon`.
 */
enum MHD_FLAG_HTTP2
{
  /**
   * Enables protocol HTTP/2.
   */
  MHD_USE_HTTP2 = 536870912,
};

/**
 * @brief MHD options.
 *
 * Passed in the varargs portion of #MHD_start_daemon.
 */
enum MHD_OPTION_HTTP2
{
  /**
   * HTTP/2 settings of the daemon, which are sent when a new client connection
   * occurs. This option should be followed by two arguments:
   *  - An integer of type `size_t`, which indicates the number of
   *    h2_settings_entry.
   *  - A pointer to a `h2_settings_entry` structure, an array of http2
   *    settings.
   * Note that the application must ensure that the buffer of the
   * second argument remains allocated and unmodified while the
   * deamon is running.
   * Settings parameters and their default values are defined in
   * https://tools.ietf.org/html/rfc7540#section-6.5.2
   */
  MHD_OPTION_HTTP2_SETTINGS = 7540,

  /**
   * Clients can connect directly using HTTP/2.
   */
  MHD_OPTION_HTTP2_DIRECT = 7541,

  /**
   * Clients can upgrade from HTTP/1.1 to HTTP/2.
   */
  MHD_OPTION_HTTP2_UPGRADE = 7542,

};


#endif /* MICROHTTPD_HTTP2_H */
