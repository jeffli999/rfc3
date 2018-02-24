CPP = gcc
CFLAGS = -pg

rfc: rfc.c
	${CPP} ${CFLAGS} -o rfc rfc.c

all: rfc 


