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
  int bpf_fd;                      /* BPF file descriptor */
  char if_name[IFNAMSIZ];          /* if name, e.g. "en0" */
  u_char eth_addr[ETHER_ADDR_LEN]; /* Ethernet address of this iface */
  u_char *buf;                     // bpf read buffer
  size_t buf_max;                  // Allocated buffer size
} ii;

void lookup_addrs(char *);
int open_bpf(char *);
void ndp_show_loop(void);
void error(const char *, ...);
void errorx(const char *, ...);
void debug(const char *, ...);


int dflag = 1;

int main(int argc, char *argv[]) {
  char if_name[] = "hvn2";
  //lookup_addrs(if_name);
  ii.bpf_fd = open_bpf(if_name);
  ndp_show_loop();
  exit(0);
}

static struct bpf_insn insns[] = {
    /* Make sure this is an IPv6 packet. */
    BPF_STMT(BPF_LD + BPF_H + BPF_ABS, 12),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ETHERTYPE_IPV6, 0, 9),

    /* Make sure this is an ICMPv6 packet. */
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 20),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, IPPROTO_ICMPV6, 0, 7),

    /* Make sure this is an Neighbor Discovery packet. */
    BPF_STMT(BPF_LD + BPF_B + BPF_ABS, 54),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_SOLICIT, 4, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_ROUTER_ADVERT, 3, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_SOLICIT, 2, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_NEIGHBOR_ADVERT, 1, 0),
    BPF_JUMP(BPF_JMP + BPF_JEQ + BPF_K, ND_REDIRECT, 0, 1),

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
  debug("Allocate %zu Bytes buffer for BPF descriptor .", ii.buf_max);


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
  u_char *eaddr = ii.eth_addr;
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
        memcpy((caddr_t)eaddr, (caddr_t)LLADDR(sdl), ETHER_ADDR_LEN);
        debug("%s [Ethernet]: %02x:%02x:%02x:%02x:%02x:%02x", ifa->ifa_name,
              eaddr[0], eaddr[1], eaddr[2], eaddr[3], eaddr[4], eaddr[5]);
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

static int ndp_check(u_char *p, size_t len) {
  struct ether_header *ether = (struct ether_header *) p;
  struct ip6_hdr *ip6 = (struct ip6_hdr *) (p + sizeof(*ether));
  struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (p + sizeof(*ether) + sizeof(*ip6));

  debug("Receive a packet with captured length %zu", len);

  if (len < sizeof(*ether) + sizeof(*ip6) + sizeof(*icmp6)) {
    debug("Truncated packet");
    return 0;
  }

  if (ntohs(ether->ether_type) != ETHERTYPE_IPV6
      || ip6->ip6_nxt != IPPROTO_ICMPV6
      || (133 <= icmp6->icmp6_code && icmp6->icmp6_code <= 136)
      ) {
    debug("Failed sanity check.");
    return 0;
  }

  return 1;
}

void ndp_process(u_char *p) {
  char ntop_buf[INET6_ADDRSTRLEN];
  struct ether_header *ether = (struct ether_header *) p;
  struct ip6_hdr *ip6 = (struct ip6_hdr *) (p + sizeof(*ether));
  struct icmp6_hdr *icmp6 = (struct icmp6_hdr *) (p + sizeof(*ether) + sizeof(*ip6));
  struct nd_neighbor_solicit *nd_ns = (struct nd_neighbor_solicit *) (p + sizeof(*ether) + sizeof(*ip6));
  u_char *eth_addr;

  eth_addr = ether->ether_dhost;
  debug("[Dst MAC]: %02x:%02x:%02x:%02x:%02x:%02x", eth_addr[0], eth_addr[1], eth_addr[2], eth_addr[3], eth_addr[4], eth_addr[5]);

  eth_addr = ether->ether_shost;
  debug("[Src MAC]: %02x:%02x:%02x:%02x:%02x:%02x", eth_addr[0], eth_addr[1], eth_addr[2], eth_addr[3], eth_addr[4], eth_addr[5]);

  inet_ntop(AF_INET6, &ip6->ip6_src, ntop_buf, sizeof(ntop_buf));
  debug("[Src IPv6]: %s", ntop_buf);

  inet_ntop(AF_INET6, &ip6->ip6_dst, ntop_buf, sizeof(ntop_buf));
  debug("[Dst IPv6]: %s", ntop_buf);

  debug("[ICMPv6]: type: %u, code: %u", icmp6->icmp6_type, icmp6->icmp6_code);

  if(icmp6->icmp6_type == ND_NEIGHBOR_SOLICIT) {
    inet_ntop(AF_INET6, &nd_ns->nd_ns_target, ntop_buf, sizeof(ntop_buf));
    debug("[ND_NS]: target: %s", ntop_buf);

  }
}

void ndp_show_loop(void) {
  struct pollfd pfd;
  int ndfs, timeout = INFTIM;
  ssize_t length;
  u_char *buf, *buf_limit;
  struct bpf_hdr bh;

  pfd.fd = ii.bpf_fd;
  pfd.events = POLLIN;

  while (1) {

    ndfs = poll(&pfd, 1, -1);
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
      bh = *(struct bpf_hdr*)buf;
      /* memcpy(&bh, buf, sizeof(bh)); */

      debug("BPF header length: %u, captured length: %lu", bh.bh_hdrlen, bh.bh_caplen);

      if (ndp_check(buf + bh.bh_hdrlen, bh.bh_caplen))
        ndp_process(buf + bh.bh_hdrlen);

      buf += BPF_WORDALIGN(bh.bh_hdrlen + bh.bh_caplen);
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
