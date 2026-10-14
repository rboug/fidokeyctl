PROG=	fidokeyctl
SRCS=	fidokeyctl.c
MAN=	fidokeyctl.1

BINDIR=	/usr/local/bin
MANDIR=	/usr/local/man/man

CFLAGS+= -Wall -Wextra -Werror
LDADD+= -lfido2 -lcbor -lcrypto -lz

.include <bsd.prog.mk>
