PROG=sc
VERSION=1.3.3
ARCH=$(PROG)-$(VERSION).tar.bz2

DESTDIR?=/usr/local/sbin
MANDIR?=/usr/local/share/man
INITDIR?=/etc/init.d
CFGDIR=/etc/sc

CLFILES?=sc.8.gz sc.conf.5.gz $(ARCH) *.batch


man: sc.8.gz sc.conf.5.gz

sc.8.gz: sc
	pod2man --section=8 --release=" " \
		--center="Linux System Manager's Manual" $^ | gzip > $@

sc.conf.5.gz: sc.conf.pod
	pod2man --section=5 --release=" " --center=" " $^ | gzip > $@

help:
	@echo "Targets:" ;\
	 echo "  clean      clean output files" ;\
	 echo "  install    install program" ;\
	 echo "  help       show this message" ;\
	 echo "  man        (default) generate manpages" ;\
	 echo "  srcdist    create archive with source distribution" ;\
	 echo "  uninstall  uninstall program"

install: sc sc.init sc.conf.5.gz sc.8.gz sc.conf
	install -o root -g root -m 755 $(PROG) $(DESTDIR)
	install -o root -g root -m 755 $(PROG).init $(INITDIR)/$(PROG)
	install -o root -g root -m 644 sc.8.gz $(MANDIR)/man8
	install -o root -g root -m 644 sc.conf.5.gz $(MANDIR)/man5
	mkdir -p $(CFGDIR)
	if [ -f $(CFGDIR)/sc.conf ]; then \
		install -o root -g root -m 644 sc.conf $(CFGDIR)/sc.conf.default ;\
	else \
		install -o root -g root -m 644 sc.conf $(CFGDIR) ;\
	fi

uninstall:
	rm $(DESTDIR)/sc
	[ -f $(INITDIR)/sc ] && rm $(INITDIR)/sc
	rm $(MANDIR)/man8/sc.8.gz
	rm $(MANDIR)/man5/sc.conf.5.gz

clean:
	rm -f $(CLFILES)

srcdist:
	hg archive -t tbz2 -X .hgtags -X .hgignore -X .hg_archival.txt $(ARCH)

