CPP = gcc
CFLAGS = -g

rfc: rfc.c flow.c
	${CPP} ${CFLAGS} -o rfc rfc.c flow.c

all: rfc 


