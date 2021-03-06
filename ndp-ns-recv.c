#include <sys/types.h>
#include <sys/socket.h>

#include <net/if.h>

#include <arpa/inet.h>

#include <netinet/in.h>
#include <netinet/ip6.h>
#include <netinet/icmp6.h>

#include <err.h>
#include <errno.h>
#include <poll.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>

void lookup_addrs(char *);

int main(int argc, char *argv[]) {
  int s;
  ssize_t cc;
  char buf[2048];
  char ifname[] = "hvn1";
  struct icmp6_filter filt;

  if ((s = socket(AF_INET6, SOCK_RAW, IPPROTO_ICMPV6)) == -1)
    err(1, "socket");
  printf("socket opened: %d\n", s);

  // ICMP6_FILTER
  ICMP6_FILTER_SETPASSALL(&filt);
  if (setsockopt(s, IPPROTO_ICMPV6, ICMP6_FILTER, &filt, sizeof(filt)) == -1)
    err(1, "setsockopt(ICMP6_FILTER)");

  // ICMP6_MULTICAST
  struct ipv6_mreq mreq;
  memset(&mreq, 0 , sizeof(mreq));
  unsigned int if_index;

  if ((mreq.ipv6mr_interface = if_nametoindex(ifname)) == 0)
    errx(1,"if_nametoindex");

  if (inet_pton(AF_INET6, "ff02::1", &mreq.ipv6mr_multiaddr.s6_addr) == -1)
    errx(1, "inet_pton");

  printf("if %s has index %d\n", ifname, mreq.ipv6mr_interface );

  if (setsockopt(s, IPPROTO_IPV6, IPV6_JOIN_GROUP, &mreq, sizeof(mreq)) == -1)
    err(1, "setsockopt(ICMP6_JOIN_GROUP)");

  // Recv packets
  for (;;) {
    struct pollfd pfd;
    int timeout = INFTIM;
    pfd.fd = s;
    pfd.events = POLLIN;

    if (poll(&pfd, 1, timeout) <= 0)
      continue;

    cc = recv(s, buf, sizeof(buf), 0);
    if (cc == -1) {
      if (errno != EINTR) {
        warn("recv");
        sleep(1);
      }
    } else if (cc < sizeof(struct icmp6_hdr)) {
      warnx("packet is too short: %zd [bytes]\n", cc);
    } else {
      struct icmp6_hdr *icp6 = NULL;
      icp6 = (struct icmp6_hdr *)buf;

      printf("Receive: bytes: %zd, type: %d, code %d, cksum %d\n", cc,
             icp6->icmp6_type, icp6->icmp6_code, icp6->icmp6_cksum);
    }
  }


  if (close(s) == -1)
    err(1, "close");

  exit(0);
}
