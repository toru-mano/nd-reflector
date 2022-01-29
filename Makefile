BINDIR?=	/usr/local/sbin
MANDIR?=	/usr/local/man/man
PROG=		ndrd
SRCS=		ndrd.c lookup_rib.c

MAN=		doc/ndrd.8

#DEBUG=	-g -DDEBUG=3 -O0

CFLAGS+=	-Wall -I${.CURDIR}
CFLAGS+=	-Wstrict-prototypes -Wmissing-prototypes
CFLAGS+=	-Wmissing-declarations
CFLAGS+=	-Wshadow -Wpointer-arith
CFLAGS+=	-Wsign-compare -Wcast-qual

.include <bsd.prog.mk>
