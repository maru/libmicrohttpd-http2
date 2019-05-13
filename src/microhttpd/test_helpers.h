/*
  This file is part of libmicrohttpd
  Copyright (C) 2016 Karlson2k (Evgeny Grin)

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
 * @file microhttpd/test_helpers.h
 * @brief Static functions and macros helpers for testsuite.
 * @author Karlson2k (Evgeny Grin)
 */

#ifndef TEST_HELPERS_H_
#define TEST_HELPERS_H_

#include <string.h>
#include <curl/curl.h>
#include "microhttpd.h"

#ifdef HTTP2_SUPPORT
#include "microhttpd_http2.h"
#endif /* HTTP2_SUPPORT */

/**
 * Check whether program name contains specific @a marker string.
 * Only last component in pathname is checked for marker presence,
 * all leading directories names (if any) are ignored. Directories
 * separators are handled correctly on both non-W32 and W32
 * platforms.
 * @param prog_name program name, may include path
 * @param marker    marker to look for.
 * @return zero if any parameter is NULL or empty string or
 *         @prog_name ends with slash or @marker is not found in
 *         program name, non-zero if @maker is found in program
 *         name.
 */
static int
has_in_name(const char *prog_name, const char *marker)
{
  size_t name_pos;
  size_t pos;

  if (!prog_name || !marker || !prog_name[0] || !marker[0])
    return 0;

  pos = 0;
  name_pos = 0;
  while (prog_name[pos])
    {
      if ('/' == prog_name[pos])
        name_pos = pos + 1;
#if defined(_WIN32) || defined(__CYGWIN__)
      else if ('\\' == prog_name[pos])
        name_pos = pos + 1;
#endif /* _WIN32 || __CYGWIN__ */
      pos++;
    }
  if (name_pos == pos)
    return 0;
  return strstr(prog_name + name_pos, marker) != (char*)0;
}

/**
 * Check whether one of strings in array is equal to @a param.
 * String @a argv[0] is ignored.
 * @param argc number of strings in @a argv, as passed to main function
 * @param argv array of strings, as passed to main function
 * @param param parameter to look for.
 * @return zero if @a argv is NULL, @a param is NULL or empty string,
 *         @a argc is less then 2 or @a param is not found in @a argv,
 *         non-zero if one of strings in @a argv is equal to @a param.
 */
static int
has_param(int argc, char * const argv[], const char * param)
{
  int i;
  if (!argv || !param || !param[0])
    return 0;

  for(i = 1; i < argc; i++)
    {
      if(argv[i] && strcmp(argv[i], param) == 0)
        return !0;
    }

  return 0;
}

/* Curl debug callback
 * from https://curl.haxx.se/libcurl/c/CURLOPT_DEBUGFUNCTION.html
 */

static
void dump(const char *text,
          FILE *stream, unsigned char *ptr, size_t size)
{
  size_t i;
  size_t c;
  unsigned int width=0x10;

  fprintf(stream, "%s, %10.10ld bytes (0x%8.8lx)\n",
          text, (long)size, (long)size);

  for(i=0; i<size; i+= width) {
    fprintf(stream, "%4.4lx: ", (long)i);

    /* show hex to the left */
    for(c = 0; c < width; c++) {
      if(i+c < size)
        fprintf(stream, "%02x ", ptr[i+c]);
      else
        fputs("   ", stream);
    }

    /* show data on the right */
    for(c = 0; (c < width) && (i+c < size); c++) {
      char x = (ptr[i+c] >= 0x20 && ptr[i+c] < 0x80) ? ptr[i+c] : '.';
      fputc(x, stream);
    }

    fputc('\n', stream); /* newline */
  }
}

static
int my_trace(CURL *handle, curl_infotype type,
             char *data, size_t size,
             void *userp)
{
  const char *text;
  (void)handle; /* prevent compiler warning */
  (void)userp;

  switch (type) {
  case CURLINFO_TEXT:
    fprintf(stderr, "== Info: %s", data);
  default: /* in case a new one is introduced to shock us */
    return 0;

  case CURLINFO_HEADER_OUT:
    text = "=> Send header";
    break;
  case CURLINFO_DATA_OUT:
    text = "=> Send data";
    break;
  case CURLINFO_SSL_DATA_OUT:
    text = "=> Send SSL data";
    break;
  case CURLINFO_HEADER_IN:
    text = "<= Recv header";
    break;
  case CURLINFO_DATA_IN:
    text = "<= Recv data";
    break;
  case CURLINFO_SSL_DATA_IN:
    text = "<= Recv SSL data";
    break;
  }

  dump(text, stderr, (unsigned char *)data, size);
  return 0;
}


/**
 * HTTP version of connections.
 */
int http_version = 0;

/**
 * Use HTTP2 flag for daemon.
 */
int use_http2 = 0;

/**
 * HTTP version string for curl.
 */
char *use_http_version;

/**
 * Set HTTP version using the program name.
 * @param prog_name program name, may include path
 * @param allow_1_0 allow HTTP/1.0
 */
void
set_http_version(const char *prog_name, int allow_1_0)
{
#ifdef HTTP2_SUPPORT
  if (has_in_name(prog_name, "_http2"))
    {
#ifdef HAVE_CURL
      if (0 == (CURL_VERSION_HTTP2 & curl_version_info(CURLVERSION_NOW)->features))
        {
          abort();
        }
#endif /* HAVE_CURL */
      if (has_in_name(prog_name, "_http2_direct"))
        {
          http_version = CURL_HTTP_VERSION_2_PRIOR_KNOWLEDGE;
          use_http_version = "--http2-prior-knowledge";
        }
      else
        {
          http_version = CURL_HTTP_VERSION_2;
          use_http_version = "--http2";
        }
      use_http2 = MHD_USE_HTTP2;
    }
  else
#endif /* HTTP2_SUPPORT */
  if ((has_in_name(prog_name, "11")) || !allow_1_0)
    {
      http_version = CURL_HTTP_VERSION_1_1;
      use_http_version = "--http1.1";
    }
  else
    {
      http_version = CURL_HTTP_VERSION_1_0;
      use_http_version = "--http1.0";
    }
}

#endif /* TEST_HELPERS_H_ */
