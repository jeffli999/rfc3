CPP = gcc
CFLAGS = -g

rfc: rfc.c
	${CPP} ${CFLAGS} -o rfc rfc.c

all: rfc 


