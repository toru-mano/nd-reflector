#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>

#include <netinet/if_ether.h>
#include <netinet6/in6_var.h>
#include <netinet/ip6.h>

#include <netinet/icmp6.h>
#include <netinet6/nd6.h>

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

struct lan_if {
  char if_name[IFNAMSIZ];
} lan;

struct wan_if {
  char if_name[IFNAMSIZ];     /* if name, e.g. "en0" */
  struct ether_addr eth_addr; /* Ethernet address of this iface */
  struct sockaddr_in6 sin6; /* IPv6 Link Local address without embed scope id*/
  int bpf_fd;               /* BPF file descriptor for ND_NS receipt */
  u_char *buf;              /* bpf read buffer */
  size_t buf_max;           /* Allocated buffer size */
} wan;

struct raw_nd_ns {
  struct ether_header eth_hdr;
  struct ip6_hdr ip6_hdr;
  struct nd_neighbor_solicit ns_hdr;
  struct nd_opt_hdr opt_hdr;
  struct ether_addr opt_lladr;
} __packed;

struct raw_nd_na {
  struct ether_header eth_hdr;
  struct ip6_hdr ip6_hdr;
  struct nd_neighbor_advert na_hdr;
  struct nd_opt_hdr opt_hdr;
  struct ether_addr opt_lladr;
} __packed;

void lookup_addrs(char *);
int open_bpf(char *);
void ndp_show_loop(void);
void nd_na_send(struct ether_addr *, struct in6_addr *, struct in6_addr *);
void print_nbr_state(struct in6_addr *);
int lookup_ndp_table(char *, struct in6_addr *);
void error(const char *, ...);
void errorx(const char *, ...);
void debug(const char *, ...);

int dflag = 1;

int main(int argc, char *argv[]) {
  char wan_if[] = "hvn1";
  char lan_if[] = "hvn2";
  strncpy(wan.if_name, wan_if, sizeof(wan.if_name));
  strncpy(lan.if_name, lan_if, sizeof(lan.if_name));

  lookup_addrs(wan.if_name);
  wan.bpf_fd = open_bpf(wan.if_name);

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
  wan.buf_max = sz;
  wan.buf = malloc(wan.buf_max);
  if (!wan.buf)
    errorx("malloc for BFP buffer %zu byte", wan.buf_max);
  debug("Allocate %zu Bytes buffer for BPF descriptor.", wan.buf_max);

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
        wan.eth_addr = *(struct ether_addr *)LLADDR(sdl);
        debug("%s [Ethernet]: %s", ifa->ifa_name, ether_ntoa(&wan.eth_addr));
        found = 1;
      }
      break;

    case AF_INET:
      sin = (struct sockaddr_in *)ifa->ifa_addr;
      debug("%s [IPv4]: %s\n", ifa->ifa_name, inet_ntoa(sin->sin_addr));
      break;

    case AF_INET6:
      sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

      if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
        // Clear scope id from address
        sin6->sin6_scope_id = ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
        sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
        wan.sin6 = *sin6;
      }

      if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ntop_buf, sizeof(ntop_buf)))
        error("inet_ntop");
      debug("%s [IPv6]: %s, scope_id %u", ifa->ifa_name, ntop_buf,
            sin6->sin6_scope_id);

      break;
    }
  }
  freeifaddrs(ifap);

  if (!found)
    errorx("Interface not found %s\n", if_name);
}

/*
 * Does the interface has the given IPV6 address addr?
 * If the interface `if_name` has IPv6 address `addr` then return 1 otherwise 0.
 * When an error occurs, this function returns -1.
 */
int
lookup_in6_addr(char *if_name, struct in6_addr *addr) {
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in6 *sin6;

  int found = 0;
  char ntop_buf[INET6_ADDRSTRLEN];

  if (!inet_ntop(AF_INET6, addr, ntop_buf, sizeof(ntop_buf)))
    error("inet_ntop");

  debug("lookup_in6_addr: Does interface %s has IPv6 address %s?", if_name, ntop_buf);


  if (getifaddrs(&ifap) != 0)
    error("getifaddrs");

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

    if (strcmp(ifa->ifa_name, if_name)) {
      debug("lookup_in6_addr: Skip interface %s", ifa->ifa_name);
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET6) {
      sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

      if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
        // Clear scope id from address
        sin6->sin6_scope_id = ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
        sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
      }

      if (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, addr)) {
        found = 1;
      };

    }
  }
  freeifaddrs(ifap);

  return found;
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
  if (ns->ip6_hdr.ip6_plen > sizeof(struct nd_neighbor_solicit)) {
    debug("[ND_OPT]: type: %d, len: %d", ns->opt_hdr.nd_opt_type,
          ns->opt_hdr.nd_opt_len);
    debug("[ND_MAC]: %s", ether_ntoa(&ns->opt_lladr));
  }
}

int
getnbrinfo(struct in6_nbrinfo *nbi, struct in6_addr *addr, char *if_name)
{
  int s;

  if ((s = socket(AF_INET6, SOCK_DGRAM, 0)) == -1)
    error("socket");

  memset(nbi, 0, sizeof(*nbi));
  strncpy(nbi->ifname, if_name, sizeof(nbi->ifname));
  nbi->addr = *addr;

  if (ioctl(s, SIOCGNBRINFO_IN6, (caddr_t)nbi) == -1) {
    debug("ioctl(SIOCGNBRINFO_IN6) %s", nbi->ifname);
    close(s);
    return -1;
  }

  close(s);
  return 0;
}

void nd_ns_process(u_char *p) {
  struct raw_nd_ns *ns = (struct raw_nd_ns *)p;

  // do sanity check
  // ether source address == nd_opt source link-layer address
  if (strncmp(ns->eth_hdr.ether_shost, (caddr_t) &ns->opt_lladr, ETHER_ADDR_LEN) != 0) {
    debug("(nd_ns_process: ether source does not match NS source link-layer address.");
    return;
  };

  // XXX: check this ND_NS should be proxied
  // NS target address is not unspecified
  if (IN6_IS_ADDR_UNSPECIFIED(&ns->ns_hdr.nd_ns_target)) {
    debug("nd_ns_process: NS target address is unspecified.");
    return;
  }

  // NS target address is not multicast
  if (IN6_IS_ADDR_MULTICAST(&ns->ns_hdr.nd_ns_target)) {
    debug("nd_ns_process: NS target address is multicast address.");
    return;
  }

  // NS target address is not address of WAN if address
  if (lookup_in6_addr(wan.if_name, &ns->ns_hdr.nd_ns_target) != 0) {
    debug("nd_ns_process: NS target address is WAN local address.");
    return;
  };

  // NS target address is on NDP table on LAN if
  if (lookup_ndp_table(lan.if_name, &ns->ns_hdr.nd_ns_target)) {
    debug("nd_ns_process: NS target address is found in LAN NDP table.");
  } else {
    debug("nd_ns_process: NS target address is not found in LAN NDP table.");
  }

  /* nd_na_send((struct ether_addr *)ns->eth_hdr.ether_shost, &ns->ip6_hdr.ip6_src, */
  /*            &ns->ns_hdr.nd_ns_target); */
}

/*
 * Does the NDP table of the interface has a possible reachable entry of given
address?
 * Return 1 if it has entry otherwise 0.
 */
int lookup_ndp_table(char *if_name, struct in6_addr *addr) {
  struct in6_nbrinfo nbi;

  char ntop_buf[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET6, addr, ntop_buf, sizeof(ntop_buf));
  debug("Lookup NDP table of %s for %s", if_name, ntop_buf);

  if (getnbrinfo(&nbi, addr, lan.if_name) == 0) {
    debug("NDP state: %d", nbi.state);

    switch (nbi.state) {
    case ND6_LLINFO_REACHABLE:
    case ND6_LLINFO_STALE:
    case ND6_LLINFO_DELAY:
    case ND6_LLINFO_PROBE:
      return 1;
    default:
      return 0;
    }

  } else {
    debug("Failed to get NDP state.");
    return 0;
  }
}


void
print_nbr_state(struct in6_addr *add) {
  struct in6_nbrinfo nbi;
  char ntop_buf[INET6_ADDRSTRLEN];

  inet_ntop(AF_INET6, add, ntop_buf, sizeof(ntop_buf));
  debug("Get neighbor info of %s", ntop_buf);

  if (getnbrinfo(&nbi, add, lan.if_name) == 0) {
    switch (nbi.state) {
    case ND6_LLINFO_NOSTATE:
      debug("NOSTATE");
      break;
    case ND6_LLINFO_INCOMPLETE:
      debug("INCOMPLETE");
      break;
    case ND6_LLINFO_REACHABLE:
      debug("REACHABLE");
      break;
    case ND6_LLINFO_STALE:
      debug("STALE");
      break;
    case ND6_LLINFO_DELAY:
      debug("DELAY");
      break;
    case ND6_LLINFO_PROBE:
      debug("PROBE");
      break;
    default:
      debug("Unknown");
      break;
    }
  } else {
    debug("Faile to get neighbor info.");
  }
}

void nd_na_send(struct ether_addr *dst_ll_addr, struct in6_addr *dest_addr,
                struct in6_addr *target_addr) {
  struct raw_nd_na na;
  struct in6_pktinfo ipi6;
  struct cmsghdr *cmsg;
  uint8_t cmsgbuf[CMSG_SPACE(sizeof(struct in6_pktinfo))];
  ssize_t n;

  // Assemble a raw ND_NA packet
  memset(&na, 0, sizeof(na));

  // Ether header
  memcpy(&na.eth_hdr.ether_dhost, dst_ll_addr, ETHER_ADDR_LEN);
  memcpy(&na.eth_hdr.ether_shost, &wan.eth_addr, ETHER_ADDR_LEN);
  na.eth_hdr.ether_type = htons(ETHERTYPE_IPV6);

  // IPv6 header
  na.ip6_hdr.ip6_vfc = IPV6_VERSION;
  na.ip6_hdr.ip6_plen =
      htons(sizeof(struct nd_neighbor_advert) + sizeof(struct nd_opt_hdr) +
            sizeof(struct ether_addr));
  na.ip6_hdr.ip6_nxt = IPPROTO_ICMPV6;
  na.ip6_hdr.ip6_hlim = 255;
  na.ip6_hdr.ip6_src = wan.sin6.sin6_addr;
  na.ip6_hdr.ip6_dst = *dest_addr;

  // ND_NA
  na.na_hdr.nd_na_type = ND_NEIGHBOR_ADVERT;
  na.na_hdr.nd_na_flags_reserved = ND_NA_FLAG_SOLICITED;
  na.na_hdr.nd_na_target = *target_addr;
  na.opt_hdr.nd_opt_type = ND_OPT_TARGET_LINKADDR;
  na.opt_hdr.nd_opt_len = 1;
  na.opt_lladr = wan.eth_addr;

  // Compute ICMPv6 checksum
  {
    uint32_t sum = 0;
    uint16_t *p = (uint16_t *)&na.na_hdr;
    uint16_t c = ntohs(na.ip6_hdr.ip6_plen);

    // Checksum for pesudo-header
    for (int i = 0; i < 8; i++)
      sum += na.ip6_hdr.ip6_src.__u6_addr.__u6_addr16[i];

    for (int i = 0; i < 8; i++)
      sum += na.ip6_hdr.ip6_dst.__u6_addr.__u6_addr16[i];

    sum += na.ip6_hdr.ip6_plen;
    sum += htons(na.ip6_hdr.ip6_nxt);

    // Checksum for ICMPv6 (ND_NA)
    while (c > 1) {
      sum += *p++;
      c -= 2;
    }

    if (c > 0)
      sum += *(uint8_t *)p;

    while (sum >> 16)
      sum = (sum & 0xffff) + (sum >> 16);

    na.na_hdr.nd_na_hdr.icmp6_cksum = ~sum;
  }

  if ((n = write(wan.bpf_fd, &na, sizeof(na))) == -1) {
    error("write");
  }

  debug("Write %zd of %zd characters.", n, sizeof(na));
};

void ndp_show_loop(void) {
  struct pollfd pfd = {
      .fd = wan.bpf_fd,
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
    length = read(pfd.fd, (char *)wan.buf, wan.buf_max);

    /* Don't choke when we get ptraced */
    if (length == -1 && errno == EINTR) {
      debug("EINTR while read.");
      goto again;
    }
    if (length == -1)
      error("read");

    buf = wan.buf;
    buf_limit = wan.buf + length;

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
