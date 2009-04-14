#
# Makefile for sc
#

PROG:=sc
MANDIR?=/usr/local/share/man
DESTDIR?=/usr/local/sbin
INITDIR?=/etc/init.d
CLFILES?=sc.8.gz sc.conf.5.gz


help:
	@echo "Targets:"
	@echo "  clean    Clean output files"
	@echo "  install  Install script and manpages"
	@echo "  man      Generate manual pages from POD-files"
	@echo "  help     Show this message"

man: sc.8.gz sc.conf.5.gz

sc.8.gz:
	@pod2man --section=8 --release=" " --center="Linux System Manager's Manual" sc | gzip > sc.8.gz

sc.conf.5.gz: sc sc.conf.pod
	@pod2man --section=5 --release=" " --center=" " sc.conf.pod | gzip > sc.conf.5.gz

install: sc.conf.5.gz sc.8.gz
	cp -f sc.8.gz $(MANDIR)/man8
	cp -f sc.conf.5.gz $(MANDIR)/man5
	cp -f sc $(DESTDIR)
	cp -f sc.init /etc/init.d/sc

clean:
	rm -f $(CLFILES)

