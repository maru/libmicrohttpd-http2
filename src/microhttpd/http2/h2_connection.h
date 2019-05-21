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
 * @file microhttpd/http2/h2_connection.h
 * @brief HTTP/2 API for MHD
 * @author Maru Berezin
 */

#ifndef H2_CONNECTION_H
#define H2_CONNECTION_H

int h2_is_h2_preface (struct MHD_Connection *connection);

void h2_connection_suspend (struct MHD_Connection *connection);

void h2_connection_resume (struct MHD_Connection *connection);

void h2_connection_close (struct MHD_Connection *connection);

void h2_set_h1_callbacks (struct MHD_Connection *connection);

void h2_set_h2_callbacks (struct MHD_Connection *connection);

#endif
