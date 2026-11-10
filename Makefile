include config.mk

SRC = src/main.c \
      src/sub_parser.c \
      src/xray_config.c \
      src/tun_mgr.c \
      src/ping.c \
      src/tui.c \
      src/cJSON.c

OBJ = $(SRC:.c=.o)

all: psyche

config.h:
	cp -n config.def.h $@ 2>/dev/null || cp config.def.h $@

$(OBJ): config.h config.mk

.c.o:
	$(CC) -c $(CFLAGS) $< -o $@

psyche: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f psyche $(OBJ) config.h psyche-$(VERSION).tar.gz

dist: clean
	mkdir -p psyche-$(VERSION)
	cp -R Makefile config.mk config.def.h README.md LICENSE psyche.1 \
		.gitignore src psyche-$(VERSION)
	tar -czf psyche-$(VERSION).tar.gz psyche-$(VERSION)
	rm -rf psyche-$(VERSION)

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f psyche $(DESTDIR)$(PREFIX)/bin
	chmod 755 $(DESTDIR)$(PREFIX)/bin/psyche
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	sed "s/VERSION/$(VERSION)/g" < psyche.1 > $(DESTDIR)$(MANPREFIX)/man1/psyche.1
	chmod 644 $(DESTDIR)$(MANPREFIX)/man1/psyche.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/psyche \
		$(DESTDIR)$(MANPREFIX)/man1/psyche.1

.PHONY: all clean dist install uninstall
