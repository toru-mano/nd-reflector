#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
#include <poll.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

#define ROUNDUP(a)                                                             \
  ((a) > 0 ? (1 + (((a)-1) | (sizeof(long) - 1))) : sizeof(long))
#define ADVANCE(x, n) (x += ROUNDUP((n)->sa_len))

struct {
  struct rt_msghdr m_rtm;
  char m_space[512];
} m_rtmsg;

struct rt_msghdr *rtm = &m_rtmsg.m_rtm;
static int rtsock;

void lookup_rib_init(void);
void lookup_rib(struct in6_addr *, char *);
// from ndprd.c
char *in6_ntoa(struct in6_addr *);
void log_warning(const char *, ...);
void log_info(const char *, ...);
void log_debug(const char *, ...);
__dead void error(const char *, ...);
__dead void errorx(const char *, ...);

static void assemble_rtmsg(struct in6_addr *, int);
static void parse_rtmsg(int, char *);

void lookup_rib_init(void) { rtsock = socket(AF_ROUTE, SOCK_RAW, AF_INET6); }

/*
 * Lookup routing entries for destination IP6 address `dst_addr`.
 * If route is found and then it's interface name is stored in `if_name`.
 */
void lookup_rib(struct in6_addr *dst_addr, char *if_name) {
  struct pollfd pfd;
  struct timespec now, stop, timeout;
  int rlen, pid, seq, nfds;

  log_debug("%s: lookup interface of destination %s in routing table", __func__,
            in6_ntoa(dst_addr));

  pid = getpid();
  seq = arc4random();

  assemble_rtmsg(dst_addr, seq);

  // Set rtsock read timeout for 3 seconds
  clock_gettime(CLOCK_MONOTONIC, &now);
  timespecclear(&timeout);
  timeout.tv_sec = 3;
  timespecadd(&now, &timeout, &stop);

  rlen = write(rtsock, (char *)&m_rtmsg, rtm->rtm_msglen);
  log_debug("%s: rtsock write %d bytes", __func__, rlen);
  if (rlen == -1) {
    log_warning("rtsock write error: %s", strerror(errno));
  }

  while (1) {
    clock_gettime(CLOCK_MONOTONIC, &now);
    if (timespeccmp(&stop, &now, <=))
      break;
    timespecsub(&stop, &now, &timeout);

    pfd.fd = rtsock;
    pfd.events = POLLIN;
    nfds = ppoll(&pfd, 1, &timeout, NULL);

    if (nfds == -1) {
      if (errno == EINTR)
        continue;
      log_warning("ppoll(rtsock): %s", strerror(errno));
      return;
    }
    if ((pfd.revents & (POLLERR | POLLHUP | POLLNVAL)) != 0) {
      log_warning("rtsock: ERR|HUP|NVAL");
      return;
    }
    if (nfds == 0 || (pfd.revents & POLLIN) == 0)
      continue;

    rlen = read(rtsock, (char *)&m_rtmsg, sizeof(m_rtmsg));
    if (rlen == -1) {
      log_warning("rtsock read error: %s", strerror(errno));
      return;
    }
    if (rlen == 0) {
      log_warning("rtscok read 0 bytes");
      return;
    }
    if (rtm->rtm_version == RTM_VERSION && rtm->rtm_seq == seq &&
        rtm->rtm_pid == pid) {
      log_debug(
          "%s: rtsock read %d bytes: ver %d type %d seq %d pid %d flag %#x",
          __func__, rlen, rtm->rtm_version, rtm->rtm_type, rtm->rtm_seq,
          rtm->rtm_pid, rtm->rtm_flags);
      parse_rtmsg(rlen, if_name);
    }
  }
}

static void assemble_rtmsg(struct in6_addr *dst_addr, int seq) {
  struct sockaddr_in6 sin6 = {.sin6_len = sizeof(sin6),
                              .sin6_family = AF_INET6,
                              .sin6_addr = *dst_addr};
  struct sockaddr_dl ifp = {.sdl_len = sizeof(ifp), .sdl_family = AF_LINK};
  char *cp = m_rtmsg.m_space;

  bzero((char *)&m_rtmsg, sizeof(m_rtmsg));
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type = RTM_GET;
  rtm->rtm_addrs = (RTA_DST | RTA_IFP);
  rtm->rtm_seq = seq;

#define NEXTADDR(w, s)                                                         \
  if (rtm->rtm_addrs & (w)) {                                                  \
    memcpy(cp, &(s), sizeof(s));                                               \
    ADVANCE(cp, (struct sockaddr *)&(s));                                      \
  }

  NEXTADDR(RTA_DST, sin6);
  NEXTADDR(RTA_IFP, ifp);

  rtm->rtm_msglen = cp - (char *)&m_rtmsg;
}

static void parse_rtmsg(int msglen, char *if_name) {
  struct sockaddr *sa;
  struct sockaddr_dl *sdl;
  char *cp;

  if (rtm->rtm_version != RTM_VERSION) {
    log_warning("routing message version %u not understood", rtm->rtm_version);
    return;
  }
  if (rtm->rtm_msglen > msglen)
    log_warning("message length mismatch, in packet %u, returned %d",
                rtm->rtm_msglen, msglen);

  if (rtm->rtm_errno) {
    log_warning("RTM_GET: %s (errno %d)", strerror(rtm->rtm_errno),
                rtm->rtm_errno);
    return;
  }

  // Scan all sockaddr in routing message and extract interface name.
  cp = ((char *)rtm + rtm->rtm_hdrlen);
  if (rtm->rtm_addrs) {
    for (int i = 1; i; i <<= 1) {
      if (i & rtm->rtm_addrs) {
        sa = (struct sockaddr *)cp;
        if (i == RTA_IFP && sa->sa_family == AF_LINK) {
          sdl = (struct sockaddr_dl *)sa;
          (void)strncpy(if_name, sdl->sdl_data, sdl->sdl_nlen);
          if_name[sdl->sdl_nlen] = '\0';
          log_debug("%s: lookup routing table result: %s", __func__, if_name);
        }
        ADVANCE(cp, sa);
      }
    }
  }
}
