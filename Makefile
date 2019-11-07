#!/usr/bin/make -f

SRCDIR		:= src/pam_sandbox
MY_CFLAGS	:= -fPIC
MY_CFLAGS	+= -Wall -Wextra -Werror
MY_CFLAGS	+= $(shell pkg-config --cflags libsystemd)

CFLAGS += $(MY_CFLAGS)

LDLIBS	+= $(shell pkg-config --libs libsystemd)
LDFLAGS	+= -shared
SRC	:= $(SRCDIR)/pam_sandbox.c
OBJ	:= $(SRC:.c=.o)

TARGET_LIB	:= $(SRCDIR)/pam_sandbox.so

all: $(TARGET_LIB)

$(TARGET_LIB): $(OBJ)
	$(CC) $(CFLAGS) $(CPPFLAGS) $(OBJ) -o $(TARGET_LIB) $(LDFLAGS) $(LDLIBS)

%.o : %.c
	$(CC) -c $(CFLAGS) $(CPPFLAGS) $< -o $@

install: $(TARGET_LIB)
	mkdir -p $(DESTDIR)/lib/security
	install -m644 $(TARGET_LIB) $(DESTDIR)/lib/security
	mkdir -p $(DESTDIR)/opt/vyatta/share/pam-configs
	install -m644 $(SRCDIR)/pam-configs/sandbox \
		$(DESTDIR)/opt/vyatta//share/pam-configs/sandbox

clean:
	rm -f $(OBJ) $(TARGET_LIB)
