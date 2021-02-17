SRC_DIR=\
	src

PNAME='srproc'

CFLAGS=-g -Wall

LIBS=-lsigrok -lsigrokdecode -lglib-2.0

all:
	cd $(SRC_DIR); echo "--- `pwd`"; gcc $(CFLAGS) `pkg-config --cflags --libs json-glib-1.0 gio-unix-2.0 glib-2.0` -o $(PNAME) main.c $(LIBS); cd ..;

clean:
	cd $(SRC_DIR); rm -f $(PNAME); cd ..; 

.PHONY: clean
