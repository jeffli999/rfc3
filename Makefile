CPP = g++
CFLAGS = -g

rfc: rfc3.c
	${CPP} ${CFLAGS} -o rfc rfc3.c

all: rfc 


