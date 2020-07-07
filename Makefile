IBASE=		/opt/firebird

# ---------------------------------------------------------------------
# General Compiler and linker Defines for Linux
# ---------------------------------------------------------------------
CC=		gcc
LINK=		gcc
LIB_LINK=	ld
CFLAGS=		-c -w -I$(IBASE)/include 
LIB_CFLAGS=	-fPIC $(CFLAGS)
LINK_FLAGS=	-ldl -lcrypt -lmhash
LIB_LINK_FLAGS=	-shared -lib_util -lmhash
RM=		rm -f

.SUFFIXES: .o .c 


.c.o:
	$(CC) $< $(CFLAGS) $@



all:	fb_mhash

fb_mhash.o:fb_mhash.c config.h inc.uuencode.c inc.utils.c inc.keygen.c inc.hash.c inc.hmac.c
	$(CC) $< $(LIB_CFLAGS) -o $@

fb_mhash: fb_mhash.o
	$(LIB_LINK) $@.o -o $@ $(LIB_LINK_FLAGS)
	@echo ------------------------------------------------------
	@echo You need to copy fb_mhash to the interbase lib directory
	@echo in order for the server to load it. 
	@echo ------------------------------------------------------
