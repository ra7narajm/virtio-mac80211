#CC = gcc
CFLAGS =
LDFLAGS =
INCLUDES = 

CM_SRC = client_monitor.c
CM_TARGET = climon

WM_SRC = wifimedium.c
WM_TARGET = wifimedium

all: ${WM_TARGET} ${CM_TARGET}

${CM_TARGET}: ${CM_SRC}
	${CC} ${CFLAGS} ${INCLUDES} -o ${CM_TARGET} ${CM_SRC} ${LDFLAGS}

${WM_TARGET}: ${WM_SRC}
	${CC} ${CFLAGS} ${INCLUDES} -o ${WM_TARGET} ${WM_SRC} ${LDFLAGS}

clean:
	rm -rf *.o ${WM_TARGET} ${CM_TARGET}

