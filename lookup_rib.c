#include <sys/socket.h>
#include <sys/types.h>

#include <net/if.h>
#include <net/if_dl.h>
#include <net/route.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <netdb.h>
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
static int rtsock, pid, seq;

void lookup_rib_init(void);
void lookup_rib(struct in6_addr *, char *);
// from ndprd.c
char *in6_ntoa(struct in6_addr *);
void log_warning(const char *, ...);
void log_info(const char *, ...);
void log_debug(const char *, ...);
__dead void error(const char *, ...);
__dead void errorx(const char *, ...);

static void assemble_rtmsg(struct in6_addr *);
static void parse_rtmsg(int, char *);

void lookup_rib_init(void) {
  pid = getpid();
  rtsock = socket(AF_ROUTE, SOCK_RAW, AF_INET6);
  seq = 0;
}

/*
 * Lookup routing entries for destination IP6 address `dst_addr`.
 * If route is found and then it's interface name is stored in `if_name`.
 */
void lookup_rib(struct in6_addr *dst_addr, char *if_name) {
  int rlen;

  log_debug("%s: lookup interface of destination %s in routing table", __func__,
            in6_ntoa(dst_addr));

  assemble_rtmsg(dst_addr);

  rlen = write(rtsock, (char *)&m_rtmsg, rtm->rtm_msglen);
  if (rlen == -1) {
    log_warning("routing socket write error: %s", strerror(errno));
  }

  do {
    rlen = read(rtsock, (char *)&m_rtmsg, sizeof(m_rtmsg));
  } while (rlen > 0 && (rtm->rtm_version != RTM_VERSION ||
                        rtm->rtm_seq != seq || rtm->rtm_pid != pid));
  if (rlen == -1) {
    log_warning("routing socket read error: %s", strerror(errno));
  }

  parse_rtmsg(rlen, if_name);
}

static void assemble_rtmsg(struct in6_addr *dst_addr) {
  struct sockaddr_in6 sin6 = {.sin6_len = sizeof(sin6),
                              .sin6_family = AF_INET6,
                              .sin6_addr = *dst_addr};
  struct sockaddr_dl ifp = {.sdl_len = sizeof(ifp), .sdl_family = AF_LINK};
  char *cp = m_rtmsg.m_space;

  bzero((char *)&m_rtmsg, sizeof(m_rtmsg));
  rtm->rtm_version = RTM_VERSION;
  rtm->rtm_type = RTM_GET;
  rtm->rtm_addrs = (RTA_DST | RTA_IFP);
  rtm->rtm_seq = ++seq;

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
