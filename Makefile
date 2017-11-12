PROG=sc
VERSION=1.5.8
ARCH=$(PROG)-$(VERSION)
SERVICE=$(PROG)

PREFIX?=/usr/local
SBINDIR?=$(PREFIX)/sbin
MANDIR?=$(PREFIX)/share/man
INITDIR?=/etc/init.d
CONFDIR?=/etc/$(PROG)

CLFILES?=$(PROG).8 $(PROG).conf.5 $(ARCH) *.batch


man: $(PROG).8 $(PROG).conf.5

$(PROG).8: $(PROG)
	pod2man --section=8 --release=" " \
		--center="Linux System Manager's Manual" $^ > $@

$(PROG).conf.5: $(PROG).conf.pod
	pod2man --section=5 --release=" " --center=" " $^ > $@

help:
	@echo "Targets:" ;\
	 echo "  clean      clean output files" ;\
	 echo "  install    install program" ;\
	 echo "  help       show this message" ;\
	 echo "  man        (default) generate manpages" ;\
	 echo "  srcdist    create archive with source distribution" ;\
	 echo "  uninstall  uninstall program"

install: $(PROG) $(PROG).init $(PROG).conf.5 $(PROG).8 $(PROG).conf
	install -D -m 755 $(PROG) $(DESTDIR)$(SBINDIR)
	install -D -m 644 $(PROG).8 $(DESTDIR)$(MANDIR)/man8/$(PROG).8
	install -D -m 644 $(PROG).conf.5 $(DESTDIR)$(MANDIR)/man5/$(PROG).conf.5
	install -D -m 755 $(PROG).init $(DESTDIR)$(INITDIR)/$(SERVICE)
	install -D -m 644 $(PROG).conf $(DESTDIR)$(CONFDIR)/$(PROG).conf.default

uninstall:
	-rm $(DESTDIR)$(SBINDIR)/$(PROG)
	-rm $(DESTDIR)$(INITDIR)/$(SERVICE)
	-rm $(DESTDIR)$(MANDIR)/man8/$(PROG).8
	-rm $(DESTDIR)$(MANDIR)/man5/$(PROG).conf.5

reinstall: uninstall install

clean:
	rm -f $(CLFILES)

srcdist:
	git archive --prefix=$(ARCH)/ --format=tar --output=$(ARCH).tar HEAD ;\
	tar -f $(ARCH).tar --delete $(ARCH)/.gitignore ;\
	bzip2 -9 $(ARCH).tar

