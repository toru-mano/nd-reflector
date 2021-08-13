#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/types.h>

#include <net/bpf.h>
#include <net/if.h>
#include <net/if_dl.h>
#include <net/if_types.h>

#include <netinet/in.h>

#include <netinet/icmp6.h>
#include <netinet/if_ether.h>
#include <netinet/ip6.h>

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

struct wan_if {
  char if_name[IFNAMSIZ];     /* if name, e.g. "en0" */
  struct ether_addr eth_addr; /* Ethernet address of this iface */
  struct sockaddr_in6 sin6; /* IPv6 Link Local address without embed scope id*/
  int bpf_fd;               /* BPF file descriptor for ND_NS receipt */
  u_char *buf;              /* bpf read buffer */
  size_t buf_max;           /* Allocated buffer size */
} wan;

struct lan_if {
  char if_name[IFNAMSIZ]; /* if name, e.g. "en1" */
} lan;

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

char prog_name[] = "nd-reflector";

void init_wan_if(struct wan_if *);
int open_bpf(char *);
int nd_ns_check(u_char *, size_t);
void print_nd_ns(u_char *);
void nd_ns_process(u_char *);
void nd_na_send(struct ether_addr *, struct in6_addr *, struct in6_addr *);
void ndp_show_loop(void);
void debug(const char *, ...);

// Enable debug mode if set to 1.
int dflag = 1;

int main(int argc, char *argv[]) {
  if (argc != 3) {
    errx(1, "usage: %s <wan_if_name> <lan_if_name>", argv[0]);
  }

  strncpy(wan.if_name, argv[1], sizeof(wan.if_name));
  strncpy(lan.if_name, argv[2], sizeof(lan.if_name));

  debug("wan: %s, lan:%s", wan.if_name, lan.if_name);

  init_wan_if(&wan);
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
    err(1, "open /dev/bpf:");

  debug("Open BPF file descriptor: %d", fd);

  /* Set immediate mode so packets are processed as they arrive. */
  immediate = 1;
  if (ioctl(fd, BIOCIMMEDIATE, &immediate) == -1)
    err(1, "ioctl(BIOCIMMEDIATE)");

  /* Associate a hardware interface to BPF descriptor. */
  strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
  if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) == -1)
    err(1, "ioctl(BIOCSETIF)");
  debug("Attach BPF descriptor to %s", if_name);

  /* Get the BPF buffer length. */
  if (ioctl(fd, BIOCGBLEN, &sz) == -1)
    err(1, "ioctl(BIOCGBLEN)");

  /* Allocate buffer for BPF read */
  wan.buf_max = sz;
  wan.buf = malloc(wan.buf_max);
  if (!wan.buf)
    errx(1, "malloc for BFP buffer %zu byte", wan.buf_max);
  debug("Allocate %zu Bytes buffer for BPF descriptor.", wan.buf_max);

  /*
   * Check that the data link layer is an Ethernet; this code won't work with
   * anything else.
   */
  if (ioctl(fd, BIOCGDLT, (caddr_t)&dlt) == -1)
    err(1, "ioctl(BIOCGDLT)");
  if (dlt != DLT_EN10MB)
    err(1, "%s is not an Ethernet interface.", if_name);

  /* Set filter program. */
  if (ioctl(fd, BIOCSETF, (caddr_t)&filter) == -1)
    err(1, "ioctl(BIOCSETF)");

  /* Set direction filter to ignore outgoing packets. */
  flag = BPF_DIRECTION_OUT;
  if (ioctl(fd, BIOCSDIRFILT, &flag) == -1)
    err(1, "ioctl(BIOCSDIRFILT)");

  /* Lock the BPF descriptor to prevent the security issues after dropping
   * privileges. */
  if (ioctl(fd, BIOCLOCK) == -1)
    err(1, "ioctl(BIOCLOCK)");

  return fd;
}

/*
 * Initialize WAN interface's Ethernet address and IPv6 link local address.
 */
void init_wan_if(struct wan_if *wan) {
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_dl *sdl;
  struct sockaddr_in6 *sin6;

  int found = 0, found_dl = 0, found_in6 = 0;
  char ntop_buf[INET6_ADDRSTRLEN];
  char func_name[] = "init_wan_if";

  debug("%s: Initialize WAN interface address information: %s.", func_name, wan->if_name);

  if (getifaddrs(&ifap) != 0)
    err(1, "getifaddrs");

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

    if (strcmp(ifa->ifa_name, wan->if_name)) {
      debug("%s: Skip interface %s", func_name, ifa->ifa_name);
      continue;
    }

    found = 1;

    switch (ifa->ifa_addr->sa_family) {

    case AF_LINK:
      sdl = (struct sockaddr_dl *)ifa->ifa_addr;
      if (sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == 6) {
        wan->eth_addr = *(struct ether_addr *)LLADDR(sdl);
        debug("%s: %s [Ethernet]: %s", func_name, ifa->ifa_name, ether_ntoa(&wan->eth_addr));
        found_dl = 1;
      }
      break;

    case AF_INET6:
      sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

      if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
        // Clear scope id from address
        sin6->sin6_scope_id = ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
        sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
        wan->sin6 = *sin6;
        found_in6 = 1;
      }

      if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ntop_buf, sizeof(ntop_buf)))
        err(1, "inet_ntop");
      debug("%s: %s [IPv6]: %s, scope_id %u", func_name, ifa->ifa_name, ntop_buf,
            sin6->sin6_scope_id);

      sin6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
      if (!inet_ntop(AF_INET6, &sin6->sin6_addr, ntop_buf, sizeof(ntop_buf)))
        err(1, "inet_ntop");
      debug("%s: %s [IPv6 netmask]: %s, scope_id %u", func_name, ifa->ifa_name, ntop_buf,
            sin6->sin6_scope_id);

      break;
    }
  }
  freeifaddrs(ifap);

  if (!found)
    errx(1, "Interface not found %s", wan->if_name);

  if (!found_dl)
    errx(1, "Interface %s has no Ether address", wan->if_name);

  if (!found_in6)
    errx(1, "Interface %s has no IPv6 link local address", wan->if_name);

  inet_ntop(AF_INET6, &wan->sin6.sin6_addr, ntop_buf, sizeof(ntop_buf));
  debug("%s: Complete initilization: {[Eth]:%s, [IP]:%s}", func_name, ether_ntoa(&wan->eth_addr), ntop_buf);
}

/*
 * Does the interface has the given IPV6 address addr?
 * If the interface `if_name` has IPv6 address `addr` then return 1.
 * If the address `addr` in the subnet of interface `if_name` then return 2.
 * Otherwise 0.
 * When an error occurs, this function returns -1.
 */
int lookup_in6_addr(char *if_name, struct in6_addr *addr) {
  struct ifaddrs *ifap, *ifa;
  struct sockaddr_in6 *sin6, *sin6_mask;
  int found = 0;
  size_t i;
  char ntop_buf[INET6_ADDRSTRLEN];
  char func_name[] = "lookup_in6_addr";

  if (!inet_ntop(AF_INET6, addr, ntop_buf, sizeof(ntop_buf)))
    err(1, "inet_ntop");

  debug("%s: Does interface %s has IPv6 address %s?", func_name, if_name,
        ntop_buf);

  if (getifaddrs(&ifap) != 0)
    err(1, "getifaddrs");

  for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

    if (strcmp(ifa->ifa_name, if_name)) {
      debug("%s: Skip interface %s", func_name, ifa->ifa_name);
      continue;
    }

    if (ifa->ifa_addr->sa_family == AF_INET6) {
      sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

      if (IN6_IS_ADDR_MULTICAST(&sin6->sin6_addr))
        continue;

      if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
        // Clear scope id from address
        sin6->sin6_scope_id = ntohs(*(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
        sin6->sin6_addr.s6_addr[2] = sin6->sin6_addr.s6_addr[3] = 0;
        // maybe we should skip.?
      }

      // address in this interface.
      debug("%s: check interface address", func_name);
      if (IN6_ARE_ADDR_EQUAL(&sin6->sin6_addr, addr)) {
        debug("%s: found in this interface", func_name);
        return 1;
      };

      // address in this subnet?
      debug("%s: check interface subnet", func_name);
      sin6_mask = (struct sockaddr_in6 *)ifa->ifa_netmask;
      for (i = 0; i < sizeof(struct in6_addr); i++) {
        if (((sin6->sin6_addr.s6_addr[i] ^ addr->s6_addr[i]) &
             sin6_mask->sin6_addr.s6_addr[i]) != 0)
          break;
      }
      if (i == sizeof(struct in6_addr)) {
        debug("%s: found in this subnet", func_name);
        found = 2;
      };
    }
  }
  freeifaddrs(ifap);

  return found;
}

/*
 * Check packet format of received packet. If it is valid NS packet then return 1. Otherwise return 0.
 */
int nd_ns_check(u_char *p, size_t len) {
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

/*
 * Read ND NS field parameters and send NA if required.
 * NA will be send on if all of the following conditions are met:
 * - Ethernet source address matches NS source link-layer address
 * - NS target address is global unicast address
 * - NS target address is not WAN interface address
 * - NS target address is LAN interface address or in LAN /64 subnet
 */
void nd_ns_process(u_char *p) {
  struct raw_nd_ns *ns = (struct raw_nd_ns *)p;
  char func_name[] = "nd_ns_process";

  // do sanity check
  // ethernet source address == nd_opt source link-layer address
  if (strncmp(ns->eth_hdr.ether_shost, (caddr_t)&ns->opt_lladr,
              ETHER_ADDR_LEN) != 0) {
    debug("%s: Ethernet source address does not match NS source link-layer address. NA will not be send.", func_name);
    return;
  };

  // Decide whether NS packet should be reflected.

  // NS target address is not unspecified
  if (IN6_IS_ADDR_UNSPECIFIED(&ns->ns_hdr.nd_ns_target)) {
    debug("%s: NS target address is unspecified. NA will not be send.", func_name);
    return;
  }

  // NS target address is not multicast
  if (IN6_IS_ADDR_MULTICAST(&ns->ns_hdr.nd_ns_target)) {
    debug("%s: NS target address is multicast address. NA will not be send.", func_name);
    return;
  }

  // NS target address is not link local
  if (IN6_IS_ADDR_LINKLOCAL(&ns->ns_hdr.nd_ns_target)) {
    debug("%s: NS target address is link local address. NA will not be send.", func_name);
    return;
  }

  // NS target address is not address of WAN if address
  if (lookup_in6_addr(wan.if_name, &ns->ns_hdr.nd_ns_target) == 1) {
    debug("%s: NS target address is WAN local address. NA will not be send.", func_name);
    return;
  };

  // NS target address is LAN if address or in LAN subnet /64.
  if (lookup_in6_addr(lan.if_name, &ns->ns_hdr.nd_ns_target) > 0) {
    debug("%s: NS target address is found in LAN if or subnet. NA will be send", func_name);

    nd_na_send((struct ether_addr *)ns->eth_hdr.ether_shost,
               &ns->ip6_hdr.ip6_src, &ns->ns_hdr.nd_ns_target);
  } else {
    debug("%s: NS target address is not found in LAN if or subnet. NA will not be send.", func_name);
  }
}

/*
 * Assemble raw NA packet and send it via BPF descriptor.
 */
void nd_na_send(struct ether_addr *dst_ll_addr, struct in6_addr *dest_addr,
                struct in6_addr *target_addr) {
  struct raw_nd_na na;
  ssize_t n;

  debug("Send ND_NA.");

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
    err(1, "write");
  }

  debug("Write %zd of %zd characters.", n, sizeof(na));
};

/*
 * Main loop to reflect NDP packet. This function receives NS packets and send NA packets.
 */
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
      err(1, "poll");
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
      err(1, "read");

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

/*
 * Print debug messages to stderr if the debug mode is enabled.
 */
void debug(const char *fmt, ...) {
  va_list ap;

  if (dflag) {
    va_start(ap, fmt);
    (void)fprintf(stderr, "%s: ", prog_name);
    (void)vfprintf(stderr, fmt, ap);
    va_end(ap);
    (void)fprintf(stderr, "\n");
  }
}
