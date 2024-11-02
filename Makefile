PREFIX?=/usr/local

CFLAGS+= -Wall -I${.CURDIR}
CFLAGS+= -Wstrict-prototypes -Wmissing-prototypes
CFLAGS+= -Wmissing-declarations
CFLAGS+= -Wshadow -Wpointer-arith
CFLAGS+= -Wsign-compare -Wcast-qual

ndrd: ndrd.c lookup_rib.c
	${CC} ${CFLAGS} ndrd.c lookup_rib.c -o $@

all: ndrd

clean:
	rm ndrd

install:
	groupinfo -e _ndrd || groupadd _ndrd
	userinfo -e _ndrd || useradd -g _ndrd -c 'ND Reflector Daemon' -d /var/empty -s /sbin/nologin _ndrd
	install -o root -g wheel -m 755 ndrd ${PREFIX}/sbin/ndrd
	install -o root -g wheel -m 555 script/ndrd ${DESTDIR}/etc/rc.d/ndrd
	install -o root -g wheel -m 555 doc/ndrd.8 ${PREFIX}/man/man8/ndrd.8

