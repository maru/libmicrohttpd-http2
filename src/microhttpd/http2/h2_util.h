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
 * @file microhttpd/http2/h2_util.h
 * @brief Utility methods
 * @author Maru Berezin
 */

#ifndef H2_UTIL_H
#define H2_UTIL_H

void
util_reset_connection_buffers (struct MHD_Connection *connection);

void
util_copy_connection_buffers (struct MHD_Connection *src, struct MHD_Connection *dst);

void
util_copy_connection_response (struct MHD_Connection *src, struct MHD_Connection *dst);

#endif
