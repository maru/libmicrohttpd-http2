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
 * @file microhttpd/http2/h2_config.c
 * @brief Configuration for h2 connections.
 * @author Maru Berezin
 */

#include "http2/h2.h"
#include "http2/h2_internal.h"

struct h2_config_t *
h2_config_init (int is_tls)
{
#if HTTP2_DEBUG
  /* Time struct for debugging */
  extern struct timeval h2_util_tm_start;
  gettimeofday(&h2_util_tm_start, NULL);
#endif

  struct h2_config_t *conf = calloc(1, sizeof(struct h2_config_t));
  conf->h2_direct  = is_tls ? 0 : 1;
  conf->h2_upgrade = is_tls ? 0 : 1;

  return conf;
}

void
h2_config_destroy (struct h2_config_t *conf)
{
  free (conf);
}

void
h2_config_set_settings (struct h2_config_t *conf,
                        size_t nmemb, h2_settings_entry *settings)
{
  conf->h2_settings_size = nmemb;
  conf->h2_settings = settings;
}

void
h2_config_set_direct (struct h2_config_t *conf, int val)
{
  conf->h2_direct  = val ? 1 : 0;
}

void
h2_config_set_upgrade (struct h2_config_t *conf, int val)
{
  conf->h2_upgrade = val ? 1 : 0;
}

h2_settings_entry *
h2_config_get_settings (const struct h2_config_t *conf)
{
  return conf->h2_settings;
}

size_t
h2_config_get_settings_len (const struct h2_config_t *conf)
{
  return conf->h2_settings_size;
}

int
h2_config_is_direct (const struct h2_config_t *conf)
{
  return conf->h2_direct;
}

int
h2_config_is_upgrade (const struct h2_config_t *conf)
{
  return conf->h2_upgrade;
}

/* end of h2_config.c */
