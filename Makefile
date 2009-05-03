PROG=sc
VERSION=1.0.0
ARCH=$(PROG)-$(VERSION).tar.bz2

MANDIR?=/usr/local/share/man
DESTDIR?=/usr/local/sbin
INITDIR?=/etc/init.d
CFGDIR=/etc/sc

CLFILES?=sc.8.gz sc.conf.5.gz $(ARCH)

man: sc.8.gz sc.conf.5.gz

sc.8.gz: sc
	pod2man --section=8 --release=" " \
		--center="Linux System Manager's Manual" $^ | gzip > $@

sc.conf.5.gz: sc.conf.pod
	pod2man --section=5 --release=" " --center=" " $^ | gzip > $@

help:
	@echo "Targets:"
	@echo "  clean    clean output files"
	@echo "  install  install script and manpages"
	@echo "  man      (default) generate manual pages from POD-files"
	@echo "  help     show this message"

install: sc.conf.5.gz sc.8.gz
	cp -f sc.8.gz $(MANDIR)/man8
	cp -f sc.conf.5.gz $(MANDIR)/man5
	mkdir -p /etc/sc
	if [ -f $(CFGDIR)/sc.conf ]; then\
		cp -f sc.conf $(CFGDIR)/sc.conf.default ;\
	else \
		cp sc.conf $(CFGDIR) ;\
	fi
	cp -f sc $(DESTDIR)
	cp -f sc.init /etc/init.d/sc

clean:
	rm -f $(CLFILES)

srcdist:
	hg archive -t tbz2 -X .hgignore -X .hg_archival.txt $(ARCH)

