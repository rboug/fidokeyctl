PROG=	fidokeyctl
SRCS=	fidokeyctl.c
MAN=	fidokeyctl.1

CFLAGS+= -Wall -Wextra -Werror
LDADD+= -lfido2 -lcbor -lcrypto -lz

.include <bsd.prog.mk>
