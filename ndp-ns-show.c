#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>

#include <netinet/if_ether.h>
#include <netinet/ip6.h>

#include <netinet/icmp6.h>

#include <arpa/inet.h>

#include <err.h>
#include <errno.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <poll.h>
#include <stdarg.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

struct if_info {
  int bpf_fd;                 /* BPF file descriptor for ND_NS receipt */
  int sock;                   /* Raw ICMPv6 socket for ND_NA sending */
  char if_name[IFNAMSIZ];     /* if name, e.g. "en0" */
  struct ether_addr eth_addr; /* Ethernet address of this iface */
  u_char *buf;                /* bpf read buffer */
  size_t buf_max;             /* Allocated buffer size */
} ii;

struct raw_nd_ns {
  struct ether_header eth_hdr;
  struct ip6_hdr ip6_hdr;
  struct nd_neighbor_solicit ns_hdr;
  struct nd_opt_hdr opt_hdr;
  struct ether_addr opt_lladr;
} __packed;

struct nd_na {
  struct nd_neighbor_advert na_hdr;
  struct nd_opt_hdr opt_hdr;
  struct ether_addr opt_lladr;
} __packed;

void lookup_addrs(char *);
int open_bpf(char *);
void ndp_show_loop(void);
void error(const char *, ...);
void errorx(const char *, ...);
void debug(const char *, ...);

int dflag = 1;

int main(int argc, char *argv[]) {
  char if_name[] = "hvn1";
  lookup_addrs(if_name);
  ii.bpf_fd = open_bpf(if_name);
  ndp_show_loop();
  exit(0);
}

static struct bpf_insn insns[] = {
    /* Make sure this is an IPv6 packet. */
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0, 5),

    /* Make sure this is an ICMPv6 packet. */
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 20),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 3),

    /* Make sure this is an Neighbor Solicit packet. */
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 54),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 0, 1),

    /* If we passed all the tests, ask for the whole packet. */
    BPF_STMT(BPF_RET + BPF_K, (u_int)-1),

    /* Otherwise, drop it. */
    BPF_STMT(BPF_RET + BPF_K, 0),
};

static struct bpf_program filter = {sizeof insns / sizeof(insns[0]), insns};

/*
 * Open a BPF file and attach it to the interface named 'if_name'.
 */
int open_bpf(char *if_name) {
  int fd, immediate, sz, flag;
  struct ifreq ifr;
  u_int dlt;

  if ((fd = open("/dev/bpf", O_RDWR)) == -1)
    error("open /dev/bpf:");

  debug("Open BPF file descriptor: %d", fd);

  /* Set immediate mode so packets are processed as they arrive. */
  immediate = 1;
  if (ioctl(fd, BIOCIMMEDIATE, &immediate) == -1)
    error("ioctl(BIOCIMMEDIATE)");

  /* Associate a hardware interface to BPF descriptor. */
  strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
  if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) == -1)
    error("ioctl(BIOCSETIF)");
  debug("Attach BPF descriptor to %s", if_name);

  /* Get the BPF buffer length. */
  if (ioctl(fd, BIOCGBLEN, &sz) == -1)
    error("ioctl(BIOCGBLEN)");

  /* Allocate buffer for BPF read */
  ii.buf_max = sz;
  ii.buf = malloc(ii.buf_max);
  if (!ii.buf)
    errorx("malloc for BFP buffer %zu byte", ii.buf_max);
  debug("Allocate %zu Bytes buffer for BPF descriptor.", ii.buf_max);

  /*
   * Check that the data link layer is an Ethernet; this code won't work with
   * anything else.
   */
  if (ioctl(fd, BIOCGDLT, (caddr_t)&dlt) == -1)
    err(1, "ioctl(BIOCGDLT)");
  if (dlt != DLT_EN10MB)
    error("%s is not an Ethernet interface.", if_name);

  /* Set filter program. */
  if (ioctl(fd, BIOCSETF, (caddr_t)&filter) == -1)
    error("ioctl(BIOCSETF)");

  /* Set direction filter to ignore outgoing packets. */
  flag = BPF_DIRECTION_OUT;
  if (ioctl(fd, BIOCSDIRFILT, &flag) == -1)
    error("ioctl(BIOCSDIRFILT)");

  /* Lock the BPF descriptor to prevent the security issues after dropping
   * privileges. */
  if (ioctl(fd, BIOCLOCK) == -1)
    error("ioctl(BIOCLOCK)");

  return fd;
}

/*
 * List Ethernet addresses, IPv4 addresses, and IPv4 addresses of given the
 * interface name.
 */
void lookup_addrs(char *if_name) {
  struct ifaddrs *ifap, *ifa;
  struct sockaddr *sa;
  struct sockaddr_dl *sdl;
  struct sockaddr_in *sin;
  struct sockaddr_in6 *sin6;

  int found = 0;
  char ntop_buf[INET6_ADDRSTRLEN];

  if (getifaddrs(&ifap) != 0)
    error("getifaddrs");

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

    if (strcmp(ifa->ifa_name, if_name)) {
      debug("Skip interface %s", ifa->ifa_name);
      continue;
    }

    switch (ifa->ifa_addr->sa_family) {

    case AF_LINK:
      sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      if (sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == 6) {
        ii.eth_addr = *(struct ether_addr *)LLADDR(sdl);
        debug("%s [Ethernet]: %s", ifa->ifa_name, ether_ntoa(&ii.eth_addr));
        found = 1;
      }
      break;

    case AF_INET:
      sin = (struct sockaddr_in *)ifa->ifa_addr;
      debug("%s [IPv4]: %s\n", ifa->ifa_name, inet_ntoa(sin->sin_addr));
      break;

    case AF_INET6:
      sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;
      if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ntop_buf, sizeof(ntop_buf)))
        error("inet_ntop");
      debug("%s [IPv6]: %s", ifa->ifa_name, ntop_buf);
      break;
    }
  }
  freeifaddrs(ifap);

  if (!found)
    errorx("Interface not found %s\n", if_name);
}

static int nd_ns_check(u_char *p, size_t len) {
  struct raw_nd_ns *ns = (struct raw_nd_ns *)p;

  debug("Receive a packet with captured length %zu", len);

  if (len < sizeof(struct raw_nd_ns)) {
    debug("Truncated packet or NS with unspecified source IPv6 address.");
    return 0;
  }

  if (ntohs(ns->eth_hdr.ether_type) != ETHERTYPE_IPV6) {
    debug("Not an IPv6 packet.");
    return 0;
  }

  if (len != sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
                 ntohs(ns->ip6_hdr.ip6_plen)) {
    debug("IPv6 payload length %u missmatches captured length.",
          ntohs(ns->ip6_hdr.ip6_plen));
    return 0;
  }

  if (ns->ip6_hdr.ip6_nxt != IPPROTO_ICMPV6) {
    debug("Not an ICMPv6 packet.");
    return 0;
  }

  if (ns->ns_hdr.nd_ns_type != ND_NEIGHBOR_SOLICIT) {
    debug("Not a ND_NS packet.");
    return 0;
  }

  // ND_NS with specified address, that is no unspecified address, has at least
  // one ND option.
  if (len == sizeof(struct raw_nd_ns)) {
    return ns->opt_hdr.nd_opt_type == ND_OPT_SOURCE_LINKADDR &&
           ns->opt_hdr.nd_opt_len == 1;
    debug("Unsupported ND opton, type: %u, len %u", ns->opt_hdr.nd_opt_type,
          ns->opt_hdr.nd_opt_len);
  }

  debug("More than one ND optoins.");
  return 0;
}

void print_nd_ns(u_char *p) {
  struct raw_nd_ns *ns = (struct raw_nd_ns *)p;
  char ntop_buf[INET6_ADDRSTRLEN];

  debug("[Dst MAC]: %s",
        ether_ntoa((struct ether_addr *)&ns->eth_hdr.ether_dhost));
  debug("[Src MAC]: %s",
        ether_ntoa((struct ether_addr *)&ns->eth_hdr.ether_shost));

  inet_ntop(AF_INET6, &ns->ip6_hdr.ip6_src, ntop_buf, sizeof(ntop_buf));
  debug("[Src IPv6]: %s", ntop_buf);

  inet_ntop(AF_INET6, &ns->ip6_hdr.ip6_dst, ntop_buf, sizeof(ntop_buf));
  debug("[Dst IPv6]: %s", ntop_buf);

  debug("[ICMPv6]: type: %u, code: %u", ns->ns_hdr.nd_ns_type,
        ns->ns_hdr.nd_ns_code);

  inet_ntop(AF_INET6, &ns->ns_hdr.nd_ns_target, ntop_buf, sizeof(ntop_buf));
  debug("[ND_NS]: target: %s", ntop_buf);

  // ND_NS may have a ND optoin
  if (ip6->ip6_plen > sizeof(*nd_ns)) {
    debug("[ND_OPT]: type: %d, len: %d", ns->opt_hdr.nd_opt_type,
          nd_opt->nd_opt_len);
    debug("[ND_MAC]: %s", ether_ntoa(&ns->opt_lladr));
  }
}

void nd_ns_process(u_char *p) { debug("Receive a ND NS packet."); }

void nd_na_send(struct in6_addr *dest_addr, struct in6_addr *target_addr) {
  struct nd_na na = {
      .na_hdr =
          {
              .nd_na_type = ND_NEIGHBOR_ADVERT,
              .nd_na_flags_reserved = ND_NA_FLAG_SOLICITED,
              .nd_na_target = *target_addr,
          },
      .opt_hdr =
          {
              .nd_opt_type = ND_OPT_TARGET_LINKADDR,
              .nd_opt_len = 1,
          },
      .opt_lladr = ii.eth_addr,
  };
  struct iovec iov = {
      .iov_base = &na,
      .iov_len = sizeof(na),
  };
  struct sockaddr_in6 sin6 = {
      .sin6_len = sizeof(sa_family_t),
      .sin6_family = AF_INET6,
      .sin6_port = htons(IPPROTO_ICMPV6),
      .sin6_addr = *dest_addr,
  };
  struct msghdr mhdr = {
      .msg_name = &sin6,
      .msg_namelen = sizeof(sin6),
      .msg_iov = &iov,
      .msg_iovlen = 1,
  };

  sendmsg(ii.sock, &mhdr, 0);
};

void ndp_show_loop(void) {
  struct pollfd pfd = {
      .fd = ii.bpf_fd,
      .events = POLLIN,
  };
  int ndfs, timeout = INFTIM;
  ssize_t length;
  u_char *buf, *buf_limit;
  struct bpf_hdr *bh;

  while (1) {

    ndfs = poll(&pfd, 1, timeout);
    if (ndfs == -1) {
      if (errno == EINTR)
        continue;
      error("poll");
    }
    if (ndfs == 0) {
      debug("poll returns zero.");
      continue;
    }

  again:
    length = read(pfd.fd, (char *)ii.buf, ii.buf_max);

    /* Don't choke when we get ptraced */
    if (length == -1 && errno == EINTR) {
      debug("EINTR while read.");
      goto again;
    }
    if (length == -1)
      error("read");

    buf = ii.buf;
    buf_limit = ii.buf + length;

    while (buf < buf_limit) {
      bh = (struct bpf_hdr *)buf;

      debug("BPF header length: %u, captured length: %lu", bh->bh_hdrlen,
            bh->bh_caplen);

      if (nd_ns_check(buf + bh->bh_hdrlen, bh->bh_caplen)) {
        print_nd_ns(buf + bh->bh_hdrlen);
        nd_ns_process(buf + bh->bh_hdrlen);
      }

      buf += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
    }
  }
}

__dead void error(const char *fmt, ...) {
  va_list ap;

  if (dflag) {
    (void)fprintf(stderr, "ndp-show: error: ");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, ":%s\n", strerror(errno));
  }
  exit(1);
}

__dead void errorx(const char *fmt, ...) {
  va_list ap;

  if (dflag) {
    (void)fprintf(stderr, "ndp-show: error: ");
    va_start(ap, fmt);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");
  }
  exit(1);
}

void debug(const char *fmt, ...) {
  va_list ap;

  if (dflag) {
    va_start(ap, fmt);
    (void)fprintf(stderr, "ndp-show: ");
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");
  }
}
