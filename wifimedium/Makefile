#CC = gcc
CFLAGS =
LDFLAGS =
INCLUDES = 
SRC = wifimedium.c
TARGET = wifimedium

all: ${TARGET}

${TARGET}: ${SRC}
	${CC} ${CFLAGS} ${INCLUDES} -o ${TARGET} ${SRC} ${LDFLAGS}

clean:
	rm -rf *.o ${TARGET}

