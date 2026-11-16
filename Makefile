include config.mk

SRC = main.c ping.c sub_parser.c tui.c tun_mgr.c xray_config.c
OBJ = $(SRC:.c=.o)

all: psyche

config.h:
	cp config.def.h $@

$(OBJ): config.h config.mk

.c.o:
	$(CC) -c $(CFLAGS) $<

psyche: $(OBJ)
	$(CC) -o $@ $(OBJ) $(LDFLAGS)

clean:
	rm -f psyche $(OBJ) config.h psyche-$(VERSION).tar.gz

dist: clean
	mkdir -p psyche-$(VERSION)
	cp -R Makefile config.mk README.md LICENSE psyche.1 \
		.gitignore *.c *.h psyche-$(VERSION)
	tar -czf psyche-$(VERSION).tar.gz psyche-$(VERSION)
	rm -rf psyche-$(VERSION)

install: all
	mkdir -p $(DESTDIR)$(PREFIX)/bin
	cp -f psyche $(DESTDIR)$(PREFIX)/bin
	chmod 755 $(DESTDIR)$(PREFIX)/bin/psyche
	which setcap >/dev/null 2>&1 && setcap cap_net_admin,cap_net_bind_service+ep $(DESTDIR)$(PREFIX)/bin/psyche 2>/dev/null || true
	mkdir -p $(DESTDIR)$(MANPREFIX)/man1
	sed "s/VERSION/$(VERSION)/g" < psyche.1 > $(DESTDIR)$(MANPREFIX)/man1/psyche.1
	chmod 644 $(DESTDIR)$(MANPREFIX)/man1/psyche.1

uninstall:
	rm -f $(DESTDIR)$(PREFIX)/bin/psyche \
		$(DESTDIR)$(MANPREFIX)/man1/psyche.1

.PHONY: all clean dist install uninstall
