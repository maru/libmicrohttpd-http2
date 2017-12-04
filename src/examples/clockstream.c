/*
     This file is part of libmicrohttpd
     Copyright (C) 2018 Christian Grothoff (and other contributing authors)

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
 * @file clockstream.c
 * @brief streams the current time every second.
 *        Based on suspend_resume_epoll.c example.
 * @author Maru Berezin
 * @author Robert D Kocisko
 * @author Christian Grothoff
 */

#include "platform.h"
#include <microhttpd.h>
#include <sys/epoll.h>
#include <sys/timerfd.h>
#include <limits.h>

#define TIMEOUT_INFINITE -1

struct Request {
  struct MHD_Connection *connection;
  int timerfd;
  uint32_t step;
};


static int epfd;

static struct epoll_event evt;

const int RESPONSE_MAX_LEN = 2048;

const char intro[] = "# ~1KB of junk to force browsers to start rendering immediately: \n";
const char junk[] =  "# xxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxxx\n";


/* Create timer and suspend connection */
static int
create_timer_suspend_connection (struct MHD_Connection *connection,
                                 struct Request* req)
{
  struct itimerspec ts;
  req->timerfd = timerfd_create(CLOCK_MONOTONIC, TFD_NONBLOCK);
  if (-1 == req->timerfd)
  {
    printf("timerfd_create: %s", strerror(errno));
    return MHD_NO;
  }
  evt.events = EPOLLIN;
  evt.data.ptr = req;
  if (-1 == epoll_ctl(epfd, EPOLL_CTL_ADD, req->timerfd, &evt))
  {
    printf("epoll_ctl: %s", strerror(errno));
    return MHD_NO;
  }
  ts.it_value.tv_sec = 1;
  ts.it_value.tv_nsec = 0;
  ts.it_interval.tv_sec = 0;
  ts.it_interval.tv_nsec = 0;
  if (-1 == timerfd_settime(req->timerfd, 0, &ts, NULL))
  {
    printf("timerfd_settime: %s", strerror(errno));
    return MHD_NO;
  }
  MHD_suspend_connection(connection);
  return MHD_YES;
}


void
print_time (char *buf, size_t len)
{
  struct timeval tv;
  time_t nowtime;
  struct tm *nowtm;
  char tmbuf[128];
  gettimeofday(&tv, NULL);
  nowtime = tv.tv_sec;
  nowtm = localtime(&nowtime);
  strftime(tmbuf, sizeof tmbuf, "%Y-%m-%d %H:%M:%S", nowtm);
  snprintf(buf, len, "%s.%09ld", tmbuf, tv.tv_usec);
  strftime(buf + strlen (buf), len - strlen (buf), " %z UTC\n", nowtm);
}


static ssize_t
send_first_bytes (char *buf, size_t max)
{
  size_t pos = 0;
  memcpy(buf, intro, strlen(intro));
  pos += strlen(buf);
  for (int i = 0; i < 13 && pos + strlen(junk) + 1 < max; i++) {
    memcpy(buf + pos, junk, strlen(junk));
    pos = strlen(buf);
  }
  return strlen (buf);
}


static ssize_t
clockstream (void *cls, uint64_t pos, char *buf, size_t max)
{
  struct Request* req = cls;
  (void)pos; /* Unused. Silence compiler warning. */
  if (max < RESPONSE_MAX_LEN)
    return MHD_CONTENT_READER_END_OF_STREAM;

  if (req->timerfd == 0) {
    req->timerfd = 1;
    return send_first_bytes (buf, max);
  }

  /* Sleep 1 second */
  if (req->step++ % 2 == 1) {
    create_timer_suspend_connection (req->connection, req);
    return 0;
  }
  /* Send time */
  print_time (buf, max);
  return strlen (buf);
}


static int
ahc_echo (void *cls,
          struct MHD_Connection *connection,
          const char *url,
          const char *method,
          const char *version,
          const char *upload_data, size_t *upload_data_size, void **ptr)
{
  struct MHD_Response *response;
  int ret;
  struct Request* req;
  struct itimerspec ts;
  (void)url;               /* Unused. Silence compiler warning. */
  (void)version;           /* Unused. Silence compiler warning. */
  (void)upload_data;       /* Unused. Silence compiler warning. */
  (void)upload_data_size;  /* Unused. Silence compiler warning. */

  req = *ptr;
  if (!req)
  {
    req = malloc(sizeof(struct Request));
    req->connection = connection;
    req->timerfd = 0;
    req->step = 0;
    *ptr = req;
    return MHD_YES;
  }

  /* Send response (first 1KB bytes, then current time each second) */
  response = MHD_create_response_from_callback (MHD_SIZE_UNKNOWN,
                                                RESPONSE_MAX_LEN,
                                                &clockstream, req, NULL);
  ret = MHD_queue_response (connection, MHD_HTTP_OK, response);
  MHD_destroy_response (response);
  return ret;
}


static int
connection_done(struct MHD_Connection *connection,
                void **con_cls,
                enum MHD_RequestTerminationCode toe)
{
  free(*con_cls);
}


int
main (int argc,
      char *const *argv)
{
  struct MHD_Daemon *d;
  const union MHD_DaemonInfo * info;
  int current_event_count;
  struct epoll_event events_list[1];
  struct Request *req;
  uint64_t timer_expirations;
  int use_http2 = 0;
  uint16_t port;

  switch (argc)
    {
    case 2:
      port = atoi (argv[1]);
      break;
    case 3:
      if (strcmp(argv[1], "-h2") == 0)
        {
          use_http2 = MHD_USE_HTTP2;
          port = atoi (argv[2]);
          break;
        }
    default:
      printf ("%s [-h2] PORT\n", argv[0]);
      return 1;
    }

  d = MHD_start_daemon (use_http2 | MHD_USE_EPOLL | MHD_ALLOW_SUSPEND_RESUME,
                        port,
                        NULL, NULL, &ahc_echo, NULL,
                        MHD_OPTION_NOTIFY_COMPLETED, &connection_done, NULL,
			MHD_OPTION_END);
  if (d == NULL)
    return 1;

  info = MHD_get_daemon_info(d, MHD_DAEMON_INFO_EPOLL_FD);
  if (info == NULL)
    return 1;

  epfd = epoll_create1(EPOLL_CLOEXEC);
  if (-1 == epfd)
    return 1;

  evt.events = EPOLLIN;
  evt.data.ptr = NULL;
  if (-1 == epoll_ctl(epfd, EPOLL_CTL_ADD, info->epoll_fd, &evt))
    return 1;

  while (1)
  {
    int timeout;
    MHD_UNSIGNED_LONG_LONG to;

    if (MHD_YES !=
        MHD_get_timeout (d,
                         &to))
      timeout = TIMEOUT_INFINITE;
    else
      timeout = (to < INT_MAX - 1) ? (int) to : (INT_MAX - 1);
    current_event_count = epoll_wait(epfd, events_list, 1, timeout);

    if (1 == current_event_count)
    {
      if (events_list[0].data.ptr)
      {
        // A timer has timed out
        req = events_list[0].data.ptr;
        // read from the fd so the system knows we heard the notice
        if (-1 == read(req->timerfd, &timer_expirations, sizeof(timer_expirations)))
        {
          return 1;
        }
        // Now resume the connection
        MHD_resume_connection(req->connection);
      }
    }
    else if (0 == current_event_count)
    {
      // no events: continue
    }
    else
    {
      // error
      return 1;
    }
    if (! MHD_run(d))
      return 1;
  }

  return 0;
}
