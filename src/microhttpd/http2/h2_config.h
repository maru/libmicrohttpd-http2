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
 * @file microhttpd/http2/h2_config.h
 * @brief Configuration for h2 connections.
 * @author Maru Berezin
 */

#ifndef H2_CONFIG_H
#define H2_CONFIG_H

struct h2_config_t;

struct h2_config_t *
h2_config_init (int is_tls);

void
h2_config_destroy (struct h2_config_t *conf);

void
h2_config_set_settings (struct h2_config_t *conf,
                        size_t nmemb, h2_settings_entry *settings);

void
h2_config_set_direct (struct h2_config_t *conf, int val);

void
h2_config_set_upgrade (struct h2_config_t *conf, int val);

h2_settings_entry *
h2_config_get_settings (const struct h2_config_t *conf);

size_t
h2_config_get_settings_len (const struct h2_config_t *conf);

int
h2_config_is_direct (const struct h2_config_t *conf);

int
h2_config_is_upgrade (const struct h2_config_t *conf);

#endif
