PROG=sc
VERSION=1.3.5
ARCH=$(PROG)-$(VERSION).tar.bz2

DESTDIR?=/usr/local/sbin
MANDIR?=/usr/local/share/man
INITDIR?=/etc/init.d
CFGDIR=/etc/sc

CLFILES?=sc.8 sc.conf.5 $(ARCH) *.batch


man: sc.8 sc.conf.5

sc.8: sc
	pod2man --section=8 --release=" " \
		--center="Linux System Manager's Manual" $^ > $@

sc.conf.5: sc.conf.pod
	pod2man --section=5 --release=" " --center=" " $^ > $@

help:
	@echo "Targets:" ;\
	 echo "  clean      clean output files" ;\
	 echo "  install    install program" ;\
	 echo "  help       show this message" ;\
	 echo "  man        (default) generate manpages" ;\
	 echo "  srcdist    create archive with source distribution" ;\
	 echo "  uninstall  uninstall program"

install: sc sc.init sc.conf.5 sc.8 sc.conf
	install -D -m 755 $(PROG) $(DESTDIR)
	install -D -m 755 $(PROG).init $(INITDIR)/$(PROG)
	install -D -m 644 sc.8 $(MANDIR)/man8/sc.8
	install -D -m 644 sc.conf.5 $(MANDIR)/man5/sc.conf.5
	install -D -m 644 sc.conf $(CFGDIR)/sc.conf.default

uninstall:
	-rm $(DESTDIR)/sc
	-rm $(INITDIR)/sc
	-rm $(MANDIR)/man8/sc.8
	-rm $(MANDIR)/man5/sc.conf.5
	-[ -f $(MANDIR)/man8/sc.8.gz ] && rm $(MANDIR)/man8/sc.8.gz
	-[ -f $(MANDIR)/man5/sc.conf.5.gz ] && rm $(MANDIR)/man5/sc.conf.5.gz

reinstall: uninstall install

clean:
	rm -f $(CLFILES)

srcdist:
	hg archive -t tbz2 -X .hgtags -X .hgignore -X .hg_archival.txt $(ARCH)

