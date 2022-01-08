#include <sys/ioctl.h>
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
#include <signal.h>
#include <stdarg.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <syslog.h>
#include <unistd.h>

struct wan_if {
	char				 if_name[IFNAMSIZ];
	struct ether_addr		 eth_addr;
	struct sockaddr_in6		 sin6; /* Link-local address */
	int				 bpf_fd;
	u_char				*bpf_buf;
	size_t				 buf_max;
} wan;

struct lan_if {
	char				 if_name[IFNAMSIZ];
} lan;

struct raw_nd_ns {
	struct ether_header		 eth_hdr;
	struct ip6_hdr			 ip6_hdr;
	struct nd_neighbor_solicit	 ns_hdr;
	struct nd_opt_hdr		 opt_hdr;
	struct ether_addr		 opt_lladr;
} __packed;

struct raw_nd_na {
	struct ether_header		 eth_hdr;
	struct ip6_hdr			 ip6_hdr;
	struct nd_neighbor_advert	 na_hdr;
	struct nd_opt_hdr		 opt_hdr;
	struct ether_addr		 opt_lladr;
} __packed;

__dead void	 usage(void);
void		 terminate(int);
void		 init_wan_if_addr(struct wan_if *);
int		 open_bpf(char *);
int		 check_nd_ns_format(u_char *, size_t);
void		 print_nd_ns(u_char *);
void		 process_nd_ns(u_char *);
void		 send_nd_na(struct ether_addr *, struct in6_addr *,
		    struct in6_addr *);
void		 nd_reflect_loop(void);
char		*in6_ntoa(struct in6_addr *);
void		 log_warning(const char *, ...);
void		 log_info(const char *, ...);
void		 log_debug(const char *, ...);
__dead void	 error(const char *, ...);
__dead void	 errorx(const char *, ...);
void		 lookup_rib_init(void);
void		 lookup_rib(struct in6_addr *, char *);

int			 daemon_mode = 1;
// Enable monitor mode if set to 1. In monitor mode, this program receives ND NS
// packets, but not send ND NA packets.
int			 monitor_mode = 0;
int			 verbose_mode = 0;

volatile sig_atomic_t	 quit = 0;
static char		 ntop_buf[INET6_ADDRSTRLEN];

__dead void
usage(void)
{
	fprintf(stderr, "usage: %s [-dmv] wan_if lan_if\n", getprogname());
	exit(EXIT_FAILURE);
}

void
terminate(__attribute__((unused)) int sig)
{
	quit = 1;
}

int
main(int argc, char *argv[])
{
	extern int	 optind;
	int		 ch;

	openlog(getprogname(), LOG_PID, LOG_DAEMON);

	signal(SIGTERM, terminate);
	signal(SIGINT, terminate);

	while ((ch = getopt(argc, argv, "dmv")) != -1) {
		switch (ch) {
		case 'd':
			daemon_mode = 0;
			break;
		case 'm':
			monitor_mode = 1;
			break;
		case 'v':
			verbose_mode = 1;
			break;
		default:
			usage();
		}
	}
	argc -= optind;
	argv += optind;

	if (argc != 2)
		usage();

	if (unveil("/dev/bpf", "rw") == -1)
		error("unveil");
	if (unveil(NULL, NULL) == -1)
		error("unveil");

	strncpy(wan.if_name, argv[0], sizeof(wan.if_name));
	strncpy(lan.if_name, argv[1], sizeof(lan.if_name));

	log_info("started with wan_if: %s, lan_if: %s", wan.if_name,
	    lan.if_name);

	init_wan_if_addr(&wan);
	wan.bpf_fd = open_bpf(wan.if_name);

	if (daemon_mode)
		if (daemon(0, 0) == -1)
			error("daemon");

	lookup_rib_init();

	if (pledge("stdio", NULL) == -1)
		error("pledge");

	nd_reflect_loop();

	close(wan.bpf_fd);

	log_info("terminated");

	closelog();

	exit(EXIT_SUCCESS);
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
int
open_bpf(char *if_name)
{
	int		 fd, immediate, sz, flag;
	struct ifreq	 ifr;
	u_int		 dlt;

	if ((fd = open("/dev/bpf", O_RDWR)) == -1)
		error("open /dev/bpf:");

	log_debug("Open BPF file descriptor: %d", fd);

	/* Set immediate mode so packets are processed as they arrive. */
	immediate = 1;
	if (ioctl(fd, BIOCIMMEDIATE, &immediate) == -1)
		error("ioctl(BIOCIMMEDIATE)");

	/* Associate a hardware interface to BPF descriptor. */
	strncpy(ifr.ifr_name, if_name, sizeof(ifr.ifr_name));
	if (ioctl(fd, BIOCSETIF, (caddr_t)&ifr) == -1)
		error("ioctl(BIOCSETIF)");
	log_debug("Attach BPF descriptor to %s", if_name);

	/* Set promiscuous mode to receive ethernet multicast. */
	if (ioctl(fd, BIOCPROMISC) == -1)
		error("ioctl(BIOCPROMISC)");
	log_debug("Interface %s enter promiscuous mode.", if_name);

	/* Get the BPF buffer length. */
	if (ioctl(fd, BIOCGBLEN, &sz) == -1)
		error("ioctl(BIOCGBLEN)");

	/* Allocate buffer for BPF read */
	wan.buf_max = sz;
	wan.bpf_buf = malloc(wan.buf_max);
	if (!wan.bpf_buf)
		errorx("malloc for BFP buffer %zu byte", wan.buf_max);
	log_debug("Allocate %zu Bytes buffer for BPF descriptor.", wan.buf_max);

	/*
	 * Check that the data link layer is an Ethernet; this code won't work
	 * with anything else.
	 */
	if (ioctl(fd, BIOCGDLT, (caddr_t)&dlt) == -1)
		error("ioctl(BIOCGDLT)");
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
 * Initialize WAN interface's Ethernet address and IPv6 link local address.
 */
void
init_wan_if_addr(struct wan_if *wan)
{
	struct ifaddrs		 *ifap, *ifa;
	struct sockaddr_dl	 *sdl;
	struct sockaddr_in6	 *sin6;

	int			 found = 0, found_dl = 0, found_in6 = 0;

	log_debug("%s: initialize wan_if address information: %s.", __func__,
	    wan->if_name);

	if (getifaddrs(&ifap) != 0)
		error("getifaddrs");

	for (ifa = ifap; ifa; ifa = ifa->ifa_next) {

		if (strcmp(ifa->ifa_name, wan->if_name)) {
			continue;
		}

		found = 1;

		switch (ifa->ifa_addr->sa_family) {

		case AF_LINK:
			sdl = (struct sockaddr_dl *)ifa->ifa_addr;
			if (sdl->sdl_type == IFT_ETHER && sdl->sdl_alen == 6) {
				wan->eth_addr =
				    *(struct ether_addr *)LLADDR(sdl);
				log_debug("%s: %s [Ethernet]: %s", __func__,
				    ifa->ifa_name, ether_ntoa(&wan->eth_addr));
				found_dl = 1;
			}
			break;

		case AF_INET6:
			sin6 = (struct sockaddr_in6 *)ifa->ifa_addr;

			if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr)) {
				// Clear scope id from address
				sin6->sin6_scope_id = ntohs(
				    *(u_int16_t *)&sin6->sin6_addr.s6_addr[2]);
				sin6->sin6_addr.s6_addr[2] =
				    sin6->sin6_addr.s6_addr[3] = 0;
				wan->sin6 = *sin6;
				found_in6 = 1;
			}

			log_debug("%s: %s [IPv6]: %s, scope_id %u", __func__,
			    ifa->ifa_name, in6_ntoa(&sin6->sin6_addr),
			    sin6->sin6_scope_id);

			sin6 = (struct sockaddr_in6 *)ifa->ifa_netmask;
			log_debug("%s: %s [IPv6 netmask]: %s, scope_id %u",
			    __func__, ifa->ifa_name, in6_ntoa(&sin6->sin6_addr),
			    sin6->sin6_scope_id);

			break;
		}
	}
	freeifaddrs(ifap);

	if (!found)
		errorx("Interface not found %s", wan->if_name);

	if (!found_dl)
		errorx("Interface %s has no Ether address", wan->if_name);

	if (!found_in6)
		errorx("Interface %s has no IPv6 link local address",
		    wan->if_name);

	log_info("Got wan_if addresses: Eth=%s, IP=%s",
	    ether_ntoa(&wan->eth_addr), in6_ntoa(&wan->sin6.sin6_addr));
}

int
check_nd_ns_format(u_char *p, size_t len)
{
	struct raw_nd_ns *ns = (struct raw_nd_ns *)p;

	log_debug("Receive a packet with captured length %zu", len);

	if (len < sizeof(struct raw_nd_ns)) {
		log_debug("Truncated packet or NS with unspecified source IPv6"
		    " address.");
		return (1);
	}

	if (ntohs(ns->eth_hdr.ether_type) != ETHERTYPE_IPV6) {
		log_debug("Not an IPv6 packet.");
		return (1);
	}

	if (len != sizeof(struct ether_header) + sizeof(struct ip6_hdr) +
	    ntohs(ns->ip6_hdr.ip6_plen)) {
		log_debug("IPv6 payload length %u missmatches captured length.",
		    ntohs(ns->ip6_hdr.ip6_plen));
		return (1);
	}

	if (ns->ip6_hdr.ip6_nxt != IPPROTO_ICMPV6) {
		log_debug("Not an ICMPv6 packet.");
		return (1);
	}

	if (ns->ns_hdr.nd_ns_type != ND_NEIGHBOR_SOLICIT) {
		log_debug("Not a ND_NS packet.");
		return (1);
	}

	// ND_NS with specified address, that is no unspecified address, has at
	// least one ND option.
	if (len == sizeof(struct raw_nd_ns)) {
		if (ns->opt_hdr.nd_opt_type == ND_OPT_SOURCE_LINKADDR &&
		    ns->opt_hdr.nd_opt_len == 1)
			return (0);
		log_debug("Unsupported ND opton, type: %u, len %u",
		    ns->opt_hdr.nd_opt_type, ns->opt_hdr.nd_opt_len);
		return (1);
	}

	log_debug("More than one ND optoins.");
	return (1);
}

void
print_nd_ns(u_char *p)
{
	struct raw_nd_ns *ns = (struct raw_nd_ns *)p;

	log_debug("[Dst MAC]: %s",
	    ether_ntoa((struct ether_addr *)&ns->eth_hdr.ether_dhost));
	log_debug("[Src MAC]: %s",
	    ether_ntoa((struct ether_addr *)&ns->eth_hdr.ether_shost));

	log_debug("[Src IPv6]: %s", in6_ntoa(&ns->ip6_hdr.ip6_src));
	log_debug("[Dst IPv6]: %s", in6_ntoa(&ns->ip6_hdr.ip6_dst));

	log_debug("[ICMPv6]: type: %u, code: %u", ns->ns_hdr.nd_ns_type,
	    ns->ns_hdr.nd_ns_code);
	log_debug("[ND_NS]: target: %s", in6_ntoa(&ns->ns_hdr.nd_ns_target));

	// ND_NS may have a ND optoin
	if (ns->ip6_hdr.ip6_plen > sizeof(struct nd_neighbor_solicit)) {
		log_debug("[ND_OPT]: type: %d, len: %d",
		    ns->opt_hdr.nd_opt_type, ns->opt_hdr.nd_opt_len);
		log_debug("[ND_MAC]: %s", ether_ntoa(&ns->opt_lladr));
	}
}

/*
 * Read ND NS field parameters and send NA if required.
 * NA will be send only if all of the following conditions are met:
 * - Ethernet source address matches NS source link-layer address
 * - IPv6 source address is not unspecified (duplicate address detection)
 * - NS target address is global unicast address
 * - Packets destinated to NS target address are routed to LAN interface.
 */
void
process_nd_ns(u_char *p)
{
	struct raw_nd_ns	*ns = (struct raw_nd_ns *)p;
	struct in6_addr	*ip6_src = &ns->ip6_hdr.ip6_src;
	struct in6_addr	*nd_ns_target = &ns->ns_hdr.nd_ns_target;
	char			 dst_if_name[IFNAMSIZ], buf[INET6_ADDRSTRLEN];

	// do sanity check
	// ethernet source address == nd_opt source link-layer address
	if (strncmp(ns->eth_hdr.ether_shost, (caddr_t)&ns->opt_lladr,
	    ETHER_ADDR_LEN) != 0) {
		log_debug("%s: Ethernet source address does not match NS "
		    "source link-layer address.", __func__);
		return;
	};

	// Decide whether NS packet should be reflected.

	// IPv6 source address is not unspecified (Duplicate address detection)
	if (IN6_IS_ADDR_UNSPECIFIED(ip6_src)) {
		log_debug("%s: IPv6 source address is unspecified.", __func__);
		return;
	}

	// NS target address is not unspecified
	if (IN6_IS_ADDR_UNSPECIFIED(nd_ns_target)) {
		log_debug("%s: NS target address is unspecified.", __func__);
		return;
	}

	// NS target address is not multicast
	if (IN6_IS_ADDR_MULTICAST(nd_ns_target)) {
		log_debug("%s: NS target address is multicast address.",
		    __func__);
		return;
	}

	// NS target address is not link local
	if (IN6_IS_ADDR_LINKLOCAL(nd_ns_target)) {
		log_debug("%s: NS target address is link local address.",
		    __func__);
		return;
	}

	lookup_rib(nd_ns_target, dst_if_name);

	if (strncmp(lan.if_name, dst_if_name, IFNAMSIZ)) {
		log_debug("%s: NS target address is NOT routed to LAN interface"
		    "%s", __func__, lan.if_name);
		return;
	}

	log_debug("%s: NS target address is routed to LAN interface %s",
	    __func__, lan.if_name);

	// log NA packet info

	(void)strncpy(buf, in6_ntoa(ip6_src), sizeof(buf));
	log_debug("send NA with dest address %s, target address %s", buf,
	    in6_ntoa(nd_ns_target));

	if (monitor_mode) {
		log_debug("skip NA sending because of monitor mode");
		return;
	}

	send_nd_na((struct ether_addr *)ns->eth_hdr.ether_shost, ip6_src,
	    nd_ns_target);
}

/*
 * Assemble raw NA packet and send it via BPF descriptor.
 */
void
send_nd_na(struct ether_addr *dst_ll_addr, struct in6_addr *dest_addr,
    struct in6_addr *target_addr)
{
	struct raw_nd_na	 na;
	ssize_t		 n;

	// Assemble a raw ND_NA packet
	bzero(&na, sizeof(na));

	// Ether header. Kernel fill ethernet source address based on outgoing
	// interface, see BIOCSHDRMPLT in bpf(4).
	memcpy(&na.eth_hdr.ether_dhost, dst_ll_addr, ETHER_ADDR_LEN);
	na.eth_hdr.ether_type = htons(ETHERTYPE_IPV6);

	// IPv6 header
	na.ip6_hdr.ip6_vfc = IPV6_VERSION;
	na.ip6_hdr.ip6_plen =
		htons(sizeof(struct nd_neighbor_advert) +
		    sizeof(struct nd_opt_hdr) + sizeof(struct ether_addr));
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
		log_warning("Failed to write bpf %zd bytes: %s", sizeof(na),
		    strerror(errno));
	}

	log_debug("Write %zd of %zd characters.", n, sizeof(na));
}

/*
 * Main loop to reflect ND packet. This function receives NS packets and send
 * NA packets.
 */
void
nd_reflect_loop(void)
{
	struct pollfd		 pfd;
	int			 nfds, timeout = INFTIM;
	ssize_t		 length;
	u_char			 *buf, *buf_limit;
	struct bpf_hdr		 *bh;

	pfd.fd = wan.bpf_fd;
	pfd.events = POLLIN;

	while (!quit) {

		nfds = poll(&pfd, 1, timeout);
		if (nfds == -1) {
			log_warning("Failed to poll: %s", strerror(errno));
			continue;
		}
		if (nfds == 0) {
			log_debug("poll timeout");
			continue;
		}

	again:
		length = read(wan.bpf_fd, (char *)wan.bpf_buf, wan.buf_max);

		/* Don't choke when we get ptraced */
		if (length == -1 && errno == EINTR) {
			log_debug("EINTR while read.");
			goto again;
		}
		if (length == -1) {
			log_warning("Failed to read: %s", strerror(errno));
			continue;
		}

		buf = wan.bpf_buf;
		buf_limit = wan.bpf_buf + length;

		while (buf < buf_limit) {
			bh = (struct bpf_hdr *)buf;

			log_debug("BPF header length: %u, captured length: %lu",
			    bh->bh_hdrlen, bh->bh_caplen);

			if (!check_nd_ns_format(buf + bh->bh_hdrlen,
			    bh->bh_caplen)) {
				print_nd_ns(buf + bh->bh_hdrlen);
				process_nd_ns(buf + bh->bh_hdrlen);
			}

			buf += BPF_WORDALIGN(bh->bh_hdrlen + bh->bh_caplen);
		}
	}
}

char *
in6_ntoa(struct in6_addr *in6_addr)
{
	if (!inet_ntop(AF_INET6, in6_addr, ntop_buf, sizeof(ntop_buf)))
		log_warning("inet_ntop error: %s", strerror(errno));
	return ntop_buf;
}

void
vlog(int pri, const char *fmt, va_list ap)
{
	if (daemon_mode) {
		vsyslog(pri, fmt, ap);
	} else {
		vfprintf(stderr, fmt, ap);
		fprintf(stderr, "\n");
		fflush(stderr);
	}
}

void
log_warning(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LOG_WARNING, fmt, ap);
	va_end(ap);
}

void
log_info(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(LOG_INFO, fmt, ap);
	va_end(ap);
}

void
log_debug(const char *fmt, ...)
{
	va_list ap;

	if (verbose_mode) {
		va_start(ap, fmt);
		vlog(LOG_DEBUG, fmt, ap);
		va_end(ap);
	}
}

void
logit(int pri, const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	vlog(pri, fmt, ap);
	va_end(ap);
}

static void
verrorc(int code, const char *fmt, va_list ap)
{
	static char	 s[BUFSIZ];
	const char	*sep;

	if (fmt != NULL) {
		(void)vsnprintf(s, sizeof(s), fmt, ap);
		sep = ": ";
	} else {
		s[0] = '\0';
		sep = "";
	}
	if (code)
		logit(LOG_CRIT, "error: %s%s%s", s, sep, strerror(code));
	else
		logit(LOG_CRIT, "error%s%s", sep, s);
}

__dead void
error(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrorc(errno, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}

__dead void
errorx(const char *fmt, ...)
{
	va_list ap;

	va_start(ap, fmt);
	verrorc(0, fmt, ap);
	va_end(ap);
	exit(EXIT_FAILURE);
}
