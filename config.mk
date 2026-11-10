# Psyche version
VERSION = 1.0

# Installation paths
PREFIX = /usr/local
MANPREFIX = $(PREFIX)/share/man

# Includes and library flags
INCS = -Isrc -I.
LIBS =

# C compiler flags and feature test macros
CPPFLAGS = -D_POSIX_C_SOURCE=200809L -D_DEFAULT_SOURCE -DVERSION=\"$(VERSION)\"
CFLAGS   = -std=c99 -pedantic -Wall -Wextra -O2 $(INCS) $(CPPFLAGS)
LDFLAGS  = $(LIBS)

# Compiler
CC = gcc
