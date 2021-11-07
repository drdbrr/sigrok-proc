SRC_DIR=\
	src

PNAME='srproc'

CFLAGS=-g -Wno-implicit -Wno-int-conversion -Wno-format -Wno-incompatible-pointer-types -Wno-pointer-to-int-cast -Wno-deprecated-declarations -Wno-discarded-qualifiers #-Wall

LIBS=-lsigrok -lsigrokdecode -lglib-2.0 -lz

all:
	cd $(SRC_DIR); echo "--- `pwd`"; rm -f $(PNAME); clear; gcc $(CFLAGS) `pkg-config --cflags --libs json-glib-1.0 gio-unix-2.0 glib-2.0` -o $(PNAME) main.c $(LIBS); echo -e "\n******"; ls --color=always $(PNAME); echo -e "\n"; cd ..;

clean:
	cd $(SRC_DIR); rm -f $(PNAME); cd ..; 

.PHONY: clean
