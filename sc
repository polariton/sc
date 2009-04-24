#!/usr/bin/perl

use strict;
use warnings;
use Carp;
use Getopt::Long qw( GetOptionsFromArray );
use DBI;
use Pod::Usage;
use Sys::Syslog;
use AppConfig;

##############################################################################
# Default values of configurable parameters
#

my $cfg_file = '/etc/sc/sc.conf';

my $iptables = '/sbin/iptables';
my $tc = '/sbin/tc';
my $ipset = '/usr/local/sbin/ipset';

my $DEBUG_OFF   = 0; # no debug output
my $DEBUG_ON    = 1; # print command line that caused error
my $DEBUG_PRINT = 2; # print all commands instead of executing them
my $debug = $DEBUG_OFF;

my $verbose = 0;
my $quiet = 0;
my $batch = 0;
my $joint = 0;

my $out_if = 'eth0';
my $in_if = 'eth1';

my $db_driver = 'sqlite';
my $db_host = '127.0.0.1';
my $db_user = 'username';
my $db_pass = 'password';
my $db_name = 'sc.db';

my $query_create = "CREATE TABLE rates (ip INTEGER PRIMARY KEY, ".
                   "rate INTEGER NOT NULL)";
my $query_load = "SELECT ip, rate FROM rates";
my $query_list = "SELECT ip, rate FROM rates WHERE ip=?";
my $query_add = "INSERT INTO rates VALUES (?, ?)";
my $query_del = "DELETE FROM rates WHERE ip=?";
my $query_change = "REPLACE INTO rates VALUES (?, ?)";

my $set_name = 'pass';
my $set_type = 'ipmap';
my $network = '172.16.0.0/16';
my $set_size = '65536';

my $chain_name = 'FORWARD';
my $quantum = '1500';
my $rate_unit = 'kibit';
my $leaf_qdisc = 'pfifo limit 50';

my $syslog = 0;
my $syslog_options = q{};
my $syslog_facility = 'user';

## end of configuration

##############################################################################
# Internal variables and constants
#

my $PROG = 'sc';
my $VERSION = '0.5.0';
my $VERSTR = "Shaper Control Tool (version $VERSION)";

# Loading flag
my $loading = 0;

# command dispatch table
my %cmdd = (
	'add' => {
		'handler' => \&cmd_add,
		'dbhandler' => \&cmd_dbadd,
		'par' => '<ip> <rate>',
		'desc' => 'Add rules',
		'priv' => 1,
	},
	'change|mod' => {
		'handler' => \&cmd_change,
		'dbhandler' => \&cmd_change,
		'par' => '<ip> <rate>',
		'desc' => 'Change rate for given IP',
		'priv' => 1,
	},
	'del|rm' => {
		'handler' => \&cmd_del,
		'dbhandler' => \&cmd_dbdel,
		'par' => '<ip>',
		'desc' => 'Delete rules for given IP',
		'priv' => 1,
	},
	'list|ls' => {
		'handler' => \&cmd_list,
		'par' => '[ip]',
		'desc' => 'List rules in human-readable form',
		'priv' => 1,
	},
	'help' => {
		'handler' => \&cmd_help,
		'par' => q{},
		'desc' => 'Show manpage',
		'priv' => 0,
	},
	'init' => {
		'handler' => \&cmd_init,
		'par' => '',
		'desc' => 'Initialization of firewall and QoS rules',
		'priv' => 1,
	},
	'sync' => {
		'handler' => \&cmd_sync,
		'par' => q{},
		'desc' => 'Synchronize rules with database',
		'priv' => 1,
	},
	'load|start' => {
		'handler' => \&cmd_load,
		'par' => q{},
		'desc' => 'Load rules from database',
		'priv' => 1,
	},
	'ratecvt' => {
		'handler' => \&cmd_ratecvt,
		'par' => '<rate> <unit>',
		'desc' => 'Convert rate unit',
		'priv' => 0,
	},
	'reload|restart' => {
		'handler' => \&cmd_reload,
		'par' => q{},
		'desc' => 'Delete all rules and load from database',
		'priv' => 1,
	},
	'reset|stop' => {
		'handler' => \&cmd_reset,
		'par' => q{},
		'desc' => 'Delete all sc-related rules',
		'priv' => 1,
	},
	'show' => {
		'handler' => \&cmd_show,
		'par' => '[ip]',
		'desc' => 'Show rules explicitly',
		'priv' => 1,
	},
	'status' => {
		'handler' => \&cmd_status,
		'par' => q{},
		'desc' => 'Show status of rules',
		'priv' => 1,
	},
	'version' => {
		'handler' => \&cmd_ver,
		'par' => q{},
		'desc' => 'Show version',
		'priv' => 0,
	},
	'dbadd' => {
		'handler' => \&cmd_dbadd,
		'par' => '<ip> <rate>',
		'desc' => 'Add database entry',
		'priv' => 0,
	},
	'dbdel|dbrm' => {
		'handler' => \&cmd_dbdel,
		'par' => '<ip>',
		'desc' => 'Delete database entry',
		'priv' => 0,
	},
	'dblist|dbls' => {
		'handler' => \&cmd_dblist,
		'par' => '[ip]',
		'desc' => 'List database entries',
		'priv' => 0,
	},
	'dbchange|dbmod' => {
		'handler' => \&cmd_dbchange,
		'par' => '<ip> <rate>',
		'desc' => 'Change database entry',
		'priv' => 0,
	},
	'dbcreate' => {
		'handler' => \&cmd_dbcreate,
		'par' => q{},
		'desc' => 'Create database and table',
		'priv' => 0,
	},
);

# rate unit transformation coefficients
my %units = (
# bit-based
	'bit' => 1,
	'kibit|Kibit' => 1024,
	'kbit|Kbit'   => 1000,
	'mibit|Mibit' => 1024*1024,
	'mbit|Mbit'   => 1_000_000,
	'gibit|Gibit' => 1024*1024*1024,
	'gbit|Gbit'   => 1_000_000_000,
# byte-based
	'bps|Bps'         => 8,
	'kib|kibps|KiBps' => 8*1024,
	'kb|kbps|KBps'    => 8_000,
	'mib|mibps|MiBps' => 8*1024*1024,
	'mb|mbps|MBps'    => 8_000_000,
	'gib|gibps|GiBps' => 8*1024*1024*1024,
	'gb|gbps|GBps'    => 8_000_000_000,
);

# Error codes
my $E_OK       = 0;
my $E_PARAM    = 1;
my $E_IP_COLL  = 2;
my $E_UNDEF    = 3;
my $E_NOTEXIST = 4;
my $E_CMD      = 5;
my $E_RUL      = 6;
my $E_PRIV     = 7;

# return value
my $RET = $E_OK;

# Preamble for usage and help message
my $usage_preamble = <<"EOF"
$VERSTR

Usage: $PROG [options] command <arguments>

EOF
;

# options dispatch table
my %optd = (
	'b|batch' => \$batch,
	'j|joint' => \$joint,
	'v|verbose!' => \$verbose,
	'd|debug=i' => \$debug,
	'S|syslog' => \$syslog,
	'f|config=s' => \$cfg_file,
	'o|out_if=s' => \$out_if,
	'i|in_if=s' => \$in_if,
	'c|chain=s' => \$chain_name,
	's|set_name=s' => \$set_name,
	'set_type=s' => \$set_type,
	'set_size=s' => \$set_size,
	'N|network=s' => \$network,
	'quantum=s' => \$quantum,
	'q|quiet!' => \$quiet,
	'u|rate_unit=s' => \$rate_unit,
	'leaf_qdisc=s' => \$leaf_qdisc,
	'db_driver=s' => \$db_driver,
	'db_host=s' => \$db_host,
	'db_name=s' => \$db_name,
	'db_user=s' => \$db_user,
	'db_pass=s' => \$db_pass,
	'query_create=s' => \$query_create,
	'query_load=s' => \$query_load,
	'query_list=s' => \$query_list,
	'query_add=s' => \$query_add,
	'query_del=s' => \$query_del,
	'query_change=s' => \$query_change,
	'syslog_options' => \$syslog_options,
	'syslog_facility=s' => \$syslog_facility,
	'iptables=s' => \$iptables,
	'tc=s' => \$tc,
	'ipset=s' => \$ipset,
);

my %db_data;
my %rul_data;

# handlers and pointers for batch execution
my ($TC_H, $IPS_H);
my $tc_ptr = \&tc_sys;
my $ips_ptr = \&ips_sys;

##############################################################################
# Main routine

# read configuration file
if (-T $cfg_file) {
	# process configuration file
	my @args = keys %optd;
	my @cargs = @args;

	my $cfg = AppConfig->new({ CASE => 1 });

	$cfg->define(@args);
	$cfg->file($cfg_file);
	# prepare list of configuration file parameters and get their values
	for my $i (0..$#cargs) {
		$cargs[$i] =~ s/^\w+\|//ixms;
		$cargs[$i] =~ s/[=!+].*$//ixms;
		${ $optd{ $args[$i] } } = $cfg->get( $cargs[$i] );
	}
}
else {
	log_carp("unable to read configuration file $cfg_file");
}

# get options from command line
GetOptions(%optd) or exit $E_PARAM;

# command queue for batch mode
my @queue;

if ($batch) {
	while(my $c = <>) {
		chomp $c;
		next if $c =~ /^\s*$/ixms;
		next if $c =~ /^\#/ixms;
		$c =~ s/\s+\#.*$//ixms;
		push @queue, $c;
	}
	foreach (@queue) {
		my @a = split /\ /ixms;
		$RET = main(@a);
	}
}
else {
	$RET = main(@ARGV);
}

exit $RET;

sub main
{
	my @argv = @_;

	if ($batch) {
		GetOptionsFromArray(\@argv, %optd) or return $E_PARAM;
	}

	my $cmd = $argv[0];
	shift @argv;

	usage($E_CMD) if !defined $cmd;

	my $ucmd = 1;
	foreach my $c (sort keys %cmdd) {
		if ($cmd =~ /^($c)/ixms) {
			if ($cmdd{$c}{'priv'} && !$debug && $>) {
				log_warn("you must run this command with root privileges\n");
				return $E_PRIV;
			}
			$RET = $cmdd{$c}{'handler'}->(@argv);
			if ($RET == $E_NOTEXIST) {
				log_carp("specified IP does not exist. Arguments: @argv");
			}
			if ($joint && defined $cmdd{$c}{'dbhandler'}) {
				$RET = $cmdd{$c}{'dbhandler'}->(@argv);
				if ($RET == $E_NOTEXIST) {
					log_carp(
						"database entry for specified IP does not exist. ".
						"Arguments: @argv"
					);
				}
			}
			$ucmd = 0;
			last;
		}
	}

	if ($ucmd) {
		log_warn("unknown command \'$cmd\'\n");
		$RET = $E_CMD;
	}
	return $RET;
}

##############################################################################
# Internal subroutines
#

sub nonempty
{
	my $str = shift;
	return (defined $str && $str ne q{});
}

sub is_ip
{
	my $ip = shift;

	if ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})/ixms) {
		if ($1 >  0 && $1 <  255 && $2 >= 0 && $2 <= 255 &&
			$3 >= 0 && $3 <= 255 && $4 >= 0 && $4 <  255) {
			return $ip;
		}
	}
	return 0;
}

sub is_rate
{
	my $rate = shift;
	my $result = 0;

	my ($num, $unit);

	if ($rate =~ /^(\d+)([A-Za-z]*)$/xms) {
		$num = $1;
		$unit = $2;
		return 0 if $num == 0;
		if (nonempty($unit)) {
			foreach my $u (keys %units) {
				if ($unit =~ /^($u)$/xms) {
					$result = $rate;
					last;
				}
			}
		}
		else {
			$result = $num . $rate_unit;
		}
	}
	else {
		return 0;
	}

	return $result;
}

sub arg_check
{
	my ($issub, $arg, $argname) = @_;
	my $result = 0;

	log_croak("$argname is undefined") if !defined $arg;
	$result = $issub->($arg);
	log_croak("$arg is invalid $argname") if !$result;
	return $result;
}

# calculate tc classid from text form of IP
sub ip_classid
{
	my $ip = shift;

	arg_check(\&is_ip, $ip, "IP");
	my @oct = split /\./ixms, $ip;
	my $cid;

	$oct[3]++;
	if ($oct[2] != 0) {
		$cid = sprintf "%x%02x", $oct[2], $oct[3];
	}
	else {
		$cid = sprintf "%x", $oct[3];
	}

	return $cid;
}

# convert IP from text to int form
sub ip_texttoint
{
	my $ip = shift;
	my @oct = split /\./ixms, $ip;
	my $int = 0;
	for my $i (0..3) {
		$int += $oct[$i]*2**(8*(3-$i));
	}
	return $int;
}

# convert IP from int to text form
sub ip_inttotext
{
	my $int = shift;
	my @oct;

	for my $i (0..3) {
		my $div = 2**(8*(3-$i));
		$oct[$i] = int($int/$div);
		$int %= $div;
	}

	return "$oct[0]\.$oct[1]\.$oct[2]\.$oct[3]";
}

# connect to database
sub db_connect
{
	my $dbh;

	if ($db_driver =~ /sqlite/ixms) {
		$dbh = DBI->connect(
			"DBI:SQLite:${db_name}",
			$db_user, $db_pass, { 'RaiseError' => 1, AutoCommit => 1 }
		);
	}
	else {
		$dbh = DBI->connect(
			"DBI:${db_driver}:dbname=$db_name;host=$db_host",
			$db_user, $db_pass, { 'RaiseError' => 1, AutoCommit => 1 }
		);
	}

	return $dbh;
}

sub log_syslog
{
	my ($severity, $msg) = @_;
	openlog($PROG, $syslog_options, $syslog_facility);
	syslog($severity, $msg);
	closelog();
	return $!;
}

# carp with logging
sub log_carp
{
	my $msg = shift;
	log_syslog('warn', $msg) if $syslog;
	if (!$quiet) {
		carp "$PROG: $msg";
	}
	return $!;
}

# croak with logging
sub log_croak
{
	my $msg = shift;
	log_syslog('err', $msg) if $syslog;
	if ($quiet) {
		exit $!;
	}
	else {
		croak "$PROG: $msg";
	}
}

# warn with logging
sub log_warn
{
	my $msg = shift;
	log_syslog('warning', $msg) if $syslog;
	print STDERR "$PROG: $msg\n";
	return $!;
}

# system with debug
sub sys
{
	my $c = shift;

	if ($debug == $DEBUG_PRINT) {
		print "$c\n";
	}
	else {
		if ($quiet) {
			system "$c >/dev/null 2>&1";
		}
		else {
			system "$c";
		}
	}
	if ($? && $debug == $DEBUG_ON) {
		print "$c\n";
	}

	return $?;
}

# silent system
sub ssys
{
	my $c = shift;
	system "$c >/dev/null 2>&1";
	return $?;
}

sub rul_add
{
	my ($ip, $classid, $rate) = @_;

	my $ceil = $rate;
	my $ret = 0;

	$tc_ptr->(
		"class add dev $out_if parent 1: classid 1:$classid htb rate $rate ".
		"ceil $ceil quantum $quantum"
	);
	$tc_ptr->(
		"class add dev $in_if parent 1: classid 1:$classid htb rate $rate ".
		"ceil $ceil quantum $quantum"
	);

	$tc_ptr->(
		"qdisc add dev $out_if parent 1:$classid handle $classid:0 $leaf_qdisc"
	);
	$tc_ptr->(
		"qdisc add dev $in_if parent 1:$classid handle $classid:0 $leaf_qdisc"
	);

	$ips_ptr->("-A $set_name $ip");

	return $E_OK;
}

sub rul_del
{
	my ($ip, $classid) = @_;

	if (!$loading || !$batch) {
		if (ssys("$ipset -T $set_name $ip")) {
			return $E_NOTEXIST;
		}
	}

	$ips_ptr->("-D $set_name $ip");

	$tc_ptr->("qdisc del dev $out_if parent 1:$classid handle $classid:0");
	$tc_ptr->("qdisc del dev $in_if parent 1:$classid handle $classid:0");

	$tc_ptr->("class del dev $out_if parent 1: classid 1:$classid");
	$tc_ptr->("class del dev $in_if parent 1: classid 1:$classid");

	return $?;
}

sub rul_change
{
	my ($ip, $classid, $rate) = @_;
	my $ceil = $rate;

	if (!$loading || !$batch) {
		if (ssys("$ipset -T $set_name $ip")) {
			return $E_NOTEXIST;
		}
	}

	$tc_ptr->(
		"class change dev $out_if parent 1:0 classid 1:$classid htb ".
		"rate $rate ceil $ceil quantum $quantum"
	);
	$tc_ptr->(
		"class change dev $in_if parent 1:0 classid 1:$classid htb ".
		"rate $rate ceil $ceil quantum $quantum"
	);

	return $?;
}

sub rul_load
{
	my ($ip, $classid, $rate);
	my $ret = 0;

	open my $TCH, '-|', "$tc class show dev $out_if"
		or log_croak("unable to open pipe for $tc");
	my @tcout = <$TCH>;
	close $TCH;
	foreach (@tcout) {
		if (/leaf\ (\w+):\ .* rate\ (\w+)/ixms) {
			($classid, $rate) = ($1, $2);
			$rate = rate_cvt($rate, $rate_unit);
			$rul_data{$classid}{'rate'} = $rate;
		}
	}

	open my $IPH, '-|', "$ipset -nsL $set_name" or
		log_croak("unable to start $ipset");
	my @ipsout = <$IPH>;
	close $IPH;
	foreach (@ipsout) {
		next unless /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/ixms;
		chomp;
		$ip = $_;
		$classid = ip_classid($ip);

		if (defined $rul_data{$classid}{'ip'}) {
			log_carp("IP-to-classid collision detected, skipping. OLD: ".
				$rul_data{$classid}{'ip'}.", NEW: $ip");
			$ret = $E_IP_COLL;
			next;
		}

		$rul_data{$classid}{'ip'} = $ip;
	}
	return $ret;
}

sub print_rule
{
	my ($comment, @cmds) = @_;
	my @out;
	my $LIST;
	my $ret = $E_OK;

	foreach my $c (@cmds) {
		open $LIST, '-|', $c or log_croak("unable to open pipe for $c");
		push @out, <$LIST>;
		close $LIST;
	}
	if (@out) {
		print "$comment\n" if nonempty($comment);
		print @out;
	}
	return $ret;
}

sub print_cmds
{
	my (@cmdargs, @descs, @lens);
	my ($i, $maxlen) = (0, 0);
	foreach my $key (sort keys %cmdd) {
		my @aliases = split /\|/ixms, $key;
		my $printcmd = "  $aliases[0]";
		if (defined $cmdd{$key}{'par'}) {
			$printcmd .= " $cmdd{$key}{'par'}";
		}
		push @cmdargs, $printcmd;
		push @descs, $cmdd{$key}{'desc'};
		my $len = length $cmdargs[$i];
		$lens[$i] = $len;
		$maxlen = $len if $len > $maxlen;
		$i++;
	}
	print "Commands:\n";
	for my $j (0..$#cmdargs) {
		print $cmdargs[$j], ' ' x ($maxlen - $lens[$j] + 2), $descs[$j], "\n";
	}
	return;
}

sub round
{
	my $n = shift;
	return int($n + .5*($n <=> 0));
}

sub rate_cvt
{
	my ($rate, $du) = @_;
	my ($num, $unit, $s_key, $d_key);

	if ($rate =~ /^(\d+)(\w*)$/xms) {
		$num = $1;
		$unit = nonempty($2) ? $2 : $rate_unit;
		return $rate if $unit eq $rate_unit;
		foreach my $u (keys %units) {
			if ($unit =~ /^($u)$/xms) {
				$s_key = $u;
				last;
			}
		}
	}
	else {
		log_croak("invalid rate specified");
	}
	log_croak("invalid source unit specified") if !defined $s_key;

	foreach my $u (keys %units) {
		if ($du =~ /^($u)$/xms) {
			$d_key = $u;
			last;
		}
	}
	log_croak("invalid destination unit specified") if !defined $d_key;

	my $dnum = round($num*$units{$s_key}/$units{$d_key});
	return "$dnum$du";
}

sub cmd_ratecvt
{
	my ($rate, $unit) = @_;
	my $result;
	log_croak("rate is undefined") if !defined $rate;
	log_croak("destination unit is undefined") if !defined $unit;

	$result = rate_cvt($rate, $unit);
	print "$result\n";
}

sub usage
{
	$RET = shift;

	print $usage_preamble;
	print_cmds();
	exit $RET;
}

sub tc_sys
{
	my $c = shift;
	return sys "$tc $c";
}

sub tc_batch
{
	my $c = shift;
	print $TC_H "$c\n";
	return;
}

sub ips_sys
{
	my $c = shift;
	return sys "$ipset $c";
}

sub ips_batch
{
	my $c = shift;
	print $IPS_H "$c\n";
	return
}

sub tc_batch_start
{
	if ($debug == $DEBUG_PRINT) {
		open $TC_H, '>', "tc.batch"
			or log_croak("unable to open tc.out");
	}
	else {
		open $TC_H, '|-', "$tc -batch"
			or log_croak("unable to create pipe for $tc");
	}

	$tc_ptr = \&tc_batch;

	return $TC_H;
}

sub ipset_batch_start
{
	if ($debug == $DEBUG_PRINT) {
		open $IPS_H, '>', "ipset.batch"
			or log_croak("unable to open ipset.out");
	}
	else {
		open $IPS_H, '|-', "$ipset --restore"
			or log_croak("unable to create pipe for $ipset");
	}

	$ips_ptr = \&ips_batch;

	return $IPS_H;
}

sub tc_batch_stop
{
	$tc_ptr = \&tc_sys;
	return close $TC_H;
}

sub ipset_batch_stop
{
	$ips_ptr = \&ips_sys;
	print $IPS_H "COMMIT\n";
	return close $IPS_H;
}

sub db_load
{
	my $dbh = db_connect();
	my $sth = $dbh->prepare($query_load);
	$sth->execute();

	my ($intip, $rate, $ip, $classid);
	while (my $ref = $sth->fetchrow_arrayref()) {
		($intip, $rate) = @{$ref};

		if (!defined $rate) {
			log_carp("IP $ip has undefined rate, skipping\n");
			$RET = $E_UNDEF;
			next;
		}

		$ip = ip_inttotext($intip);
		$classid = ip_classid($ip);

		$db_data{$classid}{'rate'} = $rate;
		$db_data{$classid}{'ip'} = $ip;
	}

	$sth->finish();
	$sth = undef; # hack for SQLite
	$dbh->disconnect();

	return $dbh;
}

sub tc_ipset_init
{
	# root qdiscs
	$tc_ptr->("qdisc add dev $out_if root handle 1: htb");
	$tc_ptr->("qdisc add dev $in_if root handle 1: htb");

	# filters
	$tc_ptr->(
		"filter add dev $out_if parent 1:0 protocol ip handle 1 pref 2 ".
		"flow map key src and 0xffff"
	);
	$tc_ptr->(
		"filter add dev $in_if parent 1:0 protocol ip handle 1 pref 2 ".
		"flow map key dst and 0xffff"
	);

	# create iphash and rules for allowed IP's
	if ($set_type eq 'ipmap') {
		$ips_ptr->("-N $set_name $set_type --network $network");
	} elsif ($set_type eq 'iphash') {
		$ips_ptr->("-N $set_name $set_type --hashsize $set_size");
	}
	return $?;
}

sub ipt_init
{
	sys("$iptables --policy FORWARD DROP");
	if ($chain_name ne 'FORWARD') {
		sys("$iptables --new-chain $chain_name");
		sys("$iptables -A FORWARD -j $chain_name");
	}

	sys("$iptables -A $chain_name -p all -m set --set $set_name src -j ACCEPT");
	sys("$iptables -A $chain_name -p all -m set --set $set_name dst -j ACCEPT");

	return $?;
}

##############################################################################
# Command handlers
#

sub cmd_init
{
	my @arg = @_;
	tc_ipset_init(@arg);
	ipt_init();

	return $?;
}

sub cmd_reset
{
	if ($chain_name ne 'FORWARD') {
		sys("$iptables --delete FORWARD -j $chain_name");
		sys("$iptables --flush $chain_name");
		sys("$iptables --delete-chain $chain_name");
	}
	else {
		sys("$iptables -D $chain_name -p all -m set --set $set_name src -j ACCEPT");
		sys("$iptables -D $chain_name -p all -m set --set $set_name dst -j ACCEPT");
	}

	sys("$ipset --flush $set_name");
	sys("$ipset --destroy $set_name");

	sys("$tc qdisc del dev $out_if root handle 1: htb");
	sys("$tc qdisc del dev $in_if root handle 1: htb");

	return $?;
}

sub cmd_add
{
	my ($ip, $rate) = @_;

	arg_check(\&is_ip, $ip, "IP");
	$rate = arg_check(\&is_rate, $rate, "rate");
	return rul_add($ip, ip_classid($ip), $rate);
}

sub cmd_del
{
	my ($ip) = @_;

	arg_check(\&is_ip, $ip, "IP");
	return rul_del($ip, ip_classid($ip));
}

sub cmd_list
{
	my $ip = shift;
	my $ret = rul_load();

	if (!defined $ip) {
		foreach my $cid (sort { hex $a <=> hex $b } keys %rul_data) {
			printf "%4s  %-15s %10s\n", $cid, $rul_data{$cid}{'ip'},
				$rul_data{$cid}{'rate'};
		}
	}
	else {
		my $classid = ip_classid($ip);
		if (defined $rul_data{$classid}) {
			printf "%4s  %-15s %10s\n", $classid, $rul_data{$classid}{'ip'},
				$rul_data{$classid}{'rate'};
		}
	}
	return $ret;
}

sub cmd_change
{
	my ($ip, $rate) = @_;

	arg_check(\&is_ip, $ip, "IP");
	$rate = arg_check(\&is_rate, $rate, "rate");
	return rul_change($ip, ip_classid($ip), $rate);
}

sub cmd_show
{
	my @ips = @_;
	my @out;

	if (!nonempty($ips[0])) {
		print "QDISCS:\n";
		sys "$tc -i -s -d qdisc show dev $in_if";
		sys "$tc -i -s -d qdisc show dev $out_if";
		print "\nCLASSES:\n";
		sys "$tc -i -s -d class show dev $in_if";
		sys "$tc -i -s -d class show dev $out_if";
		print "\nFILTERS:\n";
		sys "$tc -s -d filter show dev $in_if";
		sys "$tc -s -d filter show dev $out_if";
		print "\nIPTABLES RULES:\n";
		sys "$iptables -nL";

		return $?;
	}

	foreach my $ip (@ips) {
		my $classid = ip_classid($ip);

# tc qdisc
		print_rule(
			"\nTC rules for $ip\n\nInput qdisc [$in_if, $classid]:",
			"$tc -i -s -d qdisc show dev $in_if | ".
			"fgrep -w -A 2 \"$classid\: parent 1:$classid\""
		);
		print_rule(
			"\nOutput qdisc [$out_if, $classid]:",
			"$tc -i -s -d qdisc show dev $out_if | ".
			"fgrep -w -A 2 \"$classid\: parent 1:$classid\""
		);

# tc class
		print_rule(
			"\nInput class [$in_if, $classid]:",
			"$tc -i -s -d class show dev $in_if | ".
			"fgrep -w -A 3 \"leaf $classid\:\""
		);
		print_rule(
			"\nOutput class [$out_if, $classid]:",
			"$tc -i -s -d class show dev $out_if | ".
			"fgrep -w -A 3 \"leaf $classid\:\""
		);

# iptables
		print_rule("\nIPSet entry for $ip:", "$ipset -T $set_name $ip");
	}

	return $?;
}

sub cmd_sync
{
	my ($add, $del, $chg) = (0,0,0);

	rul_load();
	db_load();

	# delete rules for IP's that is not in database
	foreach my $rcid (keys %rul_data) {
		if (!defined $db_data{$rcid} && defined $rul_data{$rcid}) {
			my $ip = $rul_data{$rcid}{'ip'};
			print "- $ip\n" if $verbose;
			rul_del($ip, $rcid);
			$del++;
		}
	}

	foreach my $dcid (keys %db_data) {
		# delete entries with zero rates
		if ($db_data{$dcid}{'rate'} == 0) {
			my $ip = $db_data{$dcid}{'ip'};
			print "- $ip\n" if $verbose;
			rul_del($ip, $dcid);
			$del++;
			next;
		}
		my $db_rate = "$db_data{$dcid}{'rate'}$rate_unit";
		# add new entries
		if (!defined $rul_data{$dcid}) {
			my $ip = $db_data{$dcid}{'ip'};
			print "+ $ip\n" if $verbose;
			rul_add($ip, $dcid, $db_rate);
			$add++;
			next;
		}
		# change if rate in database is different
		my $rul_rate = $rul_data{$dcid}{'rate'};
		if ($rul_rate ne $db_rate) {
			my $ip = $db_data{$dcid}{'ip'};
			print "* $ip $rul_rate -> $db_rate\n" if $verbose;
			rul_change($ip, $dcid, $db_rate);
			$chg++;
		}
		else {
			next;
		}
	}
	return ($add, $del, $chg);
}

sub cmd_status
{
	my $ret = $E_OK;

	my @out;
	open my $PIPE, '-|', "$tc qdisc show dev $out_if | head -2"
		or log_croak("unable to open pipe for $tc");
	@out = <$PIPE>;
	close $PIPE;
	if ($out[0] =~ /^qdisc\ htb/xms) {
		my @lqd = split /\ /ixms, $leaf_qdisc;
		if ($out[1] =~ /^qdisc\ $lqd[0]/xms) {
			print "$PROG: shaping rules were successfully created\n";
		}
		else {
			print "$PROG: htb qdisc found but there is no child queues\n";
		}
	}
	else {
		print "$PROG: no shaping rules found\n";
	}
	return $ret;
}

sub cmd_ver
{
	print "$VERSTR\n";
	return $E_OK;
}

sub cmd_help
{
	pod2usage({ -exitstatus => 0, -verbose => 2 });
	return $E_OK;
}

sub cmd_dbcreate
{
	my $dbh = db_connect();
	$dbh->do($query_create);
	$dbh->disconnect();
	return $dbh;
}

sub cmd_load
{
	my $ret = $E_OK;

	$loading = 1;
	tc_batch_start();
	ipset_batch_start();
	tc_ipset_init();
	db_load();
	foreach my $cid (keys %db_data) {
		my $r = $db_data{$cid}{'rate'};
		rul_add($db_data{$cid}{'ip'}, $cid, "$r$rate_unit");
	}
	tc_batch_stop();
	ipset_batch_stop();

	ipt_init();
	$loading = 0;

	return $ret;
}

sub cmd_reload
{
	cmd_reset();
	return cmd_load();
}

sub cmd_dbadd
{
	my ($ip, $rate) = @_;

	arg_check(\&is_ip, $ip, "IP");
	my $dbh = db_connect();
	my $intip = ip_texttoint($ip);
	my $intrate = rate_cvt($rate, $rate_unit);
	$intrate =~ s/\D//gixms;
	my $sth = $dbh->prepare($query_add);
	$sth->execute($intip, $intrate);
	$sth->finish();
	$sth = undef;
	$dbh->disconnect();

	return $E_OK;
}

sub cmd_dbdel
{
	my @ips = @_;

	my $dbh = db_connect();
	my $sth;

	foreach my $ip (@ips) {
		arg_check(\&is_ip, $ip, 'IP');
		my $intip = ip_texttoint($ip);
		$sth = $dbh->prepare($query_del);
		$sth->execute($intip);
		$sth->finish();
	}
	$sth = undef;
	$dbh->disconnect();

	return $E_OK;
}

sub cmd_dbchange
{
	my ($ip, $rate) = @_;

	my $dbh = db_connect();
	my $intip = ip_texttoint($ip);
	my $intrate = rate_cvt($rate, $rate_unit);
	$intrate =~ s/\D//gsimx;
	my $sth = $dbh->prepare($query_change);
	$sth->execute($intip, $intrate);
	$sth->finish();
	$sth = undef;
	$dbh->disconnect();

	return $E_OK;
}

sub cmd_dblist
{
	my $ip = shift;
	my $ret = $E_OK;

	if (!defined $ip) {
		$ret = db_load();
		foreach my $cid (sort { hex $a <=> hex $b } keys %db_data) {
			printf "%-15s  %10s\n", $db_data{$cid}{'ip'},
				"$db_data{$cid}{'rate'}$rate_unit";
		}
	}
	else {
		my $intip = ip_texttoint($ip);
		my $rate;

		my $dbh = db_connect();
		my $sth = $dbh->prepare($query_list);
		$sth->execute($intip);
		while (my $ref = $sth->fetchrow_arrayref()) {
			($intip, $rate) = @$ref;
			printf "%-15s  %10s\n", $ip, $rate . $rate_unit;
		}
		$sth->finish();
		$sth = undef;
		$dbh->disconnect();
	}
	return $E_OK;
}

__END__

=head1 NAME

B<sc> - administration tool for ISP traffic shaper

=head1 SYNOPSIS

B<sc> [options] command [ip] [rate]

=head1 DESCRIPTION

B<sc> is a command-line tool intended to simplify administration of traffic
shaper for Internet service providers. ISP's usually work with the following
configuration: every customer has it's own IP-address and fixed bandwidth.
B<sc> works like a wrapper for tc(8), iptables(8) and ipset(8) abstracting you
from complexity of their rules, so you can think only about IP's and bandwidth
rates and almost forget about classid's, qdiscs, filters and IP hashes.

=head2 Features

=over

=item * Fast loading of large rulesets by using batch modes of tc(8) and
ipset(8).

=item * Loading and editing of IP's and rates from any relational database
supported by Perl B<DBI> module.

=item * Batch command execution mode for scripting purposes.

=item * Synchronization of rules with database.

=back

=head2 Details of realization

B<sc> uses B<flow> classifier that allows deterministic mapping of keys to
classes. IP-addresses must differ in two last octets, because they are used
for deterministic mapping to a tc classid's. Octets and classids are related
by the following equation:

  classid = third_octet * 0x100 + fourth_octet + 1

Example: for 172.16.1.12 address classid is 10d.

=head1 PREREQUISITES

=head2 Perl modules

=over 8

=item B<DBI> and corresponding database-dependent modules
(e.g. B<DBD::mysql> for MySQL or B<DBD::SQLite> for SQLite).

=item B<Pod::Usage> for compilation of manpage.

=item B<AppConfig> for configuration file parsing.

=back

=head2 Command-line tools

tc(8), iptables(8) and ipset(8).

=head2 Linux kernel configuration

=over 8

=item B<Flow> traffic classifier (option B<CONFIG_NET_CLS_FLOW>=m or y,
requires kernel version 2.6.25 or above).

=item B<IPSet> modules (see L<http://ipset.netfilter.org/>).

=back

=head1 COMMANDS

=over 16

=item B<add> <ip> <rate>

Add rules for specified IP

=item B<change | mod> <ip> <rate>

Change rate for given IP

=item B<dbadd> <ip> <rate>

Add database entry

=cut

=item B<dbchange | dbmod> <ip> <rate>

Change database entry

=item B<dbcreate>

Create database and table

=item B<dbdel | dbrm> <ip>

Delete database entry

=item B<dblist | dbls>

List database entries

=item B<del | rm> <ip>

Delete rules for given IP

=item B<help>

Show manpage

=item B<init>

Initialization of firewall and QoS rules. Only for manual rule editing.

=item B<list | ls> [ip]

List rules in human-readable form

=item B<load>

Load IP's and rates from database and create ruleset

=item B<reload>

Delete all rules and load from database

=item B<reset>

Delete all shaping rules

=item B<show> [ip]

Show rules explicitly

=item B<sync>

Synchronize rules with database

=item B<version>

Show version

=back

=head1 OPTIONS

=over 8

=item B<-b>, B<--batch>

Enter batch mode to read rules from STDIN

=item B<-j>, B<--joint>

Joint mode. Add, change and del commands will be applied to both rules and
database

=item B<-d>, B<--debug> level

Debugging level (from 0 to 2)

=item B<-v>, B<--verbose>

Enable additional output

=item B<-S>, B<--syslog>

Send errors and warnings to syslog

=item B<-f>, B<--config> file

Read configuration from specified file instead of F</etc/sc/sc.conf>

=item B<-o>, B<--out_if> if_name

Name of output network interface

=item B<-i>, B<--in_if> if_name

Name of input network interface

=item B<-c>, B<--chain> name

Name of iptables(8) chain for shaping rules

=item B<--set_name> name

Name of IP set

=item B<--set_type> type

Type of IP set (ipmap or iphash)

=item B<--set_size> size

Size of IP set (up to 65536)

=item B<-N, --network> net/mask

Network (used for ipmap set type)

=item B<-q>, B<--quiet>

Suppress output

=item B<--quantum> size

Size of quantum for child queues

=item B<-u>, B<--rate_unit> unit

Rate unit used by B<sc>

=item B<-l>, B<--leaf_qdisc> string

Leaf qdisc and parameters

=item B<--db_driver> name

Database driver

=item B<--db_host> host:port

Host of database server address or hostname

=item B<--db_name> name

Database name to use

=item B<--db_user> name

Database username

=item B<--db_pass> password

Database password

=back

=head1 EXAMPLES

=over 8

=item Loading of rules from database

C<sc load>

=item Add class for IP 172.16.0.1 with 10Mibit/s.

C<sc add 172.16.0.1 10Mibit>

=item Change rate to 20Mibit/s

C<sc change 172.16.0.1 20Mibit>

=item Delete class for 172.16.0.1

C<sc del 172.16.0.1>

=back

=head1 RATE UNITS

All rates should be specified as integer numbers, possibly followed
by a unit.

=over 22

=item bit

bit per second

=item kibit, Kibit or a bare number

kibibit per second 

=item kbit or Kbit

kilobit per second

=item mibit or Mibit

mibibit per second

=item mbit or Mbit

megabit per second

=item gibit or Gibit

gibibit per second

=item gbit or Gbit

gigabit per second

=item bps or Bps

byte per second

=item kib, kibps or KiBps

kibibyte per second

=item kb, kbps or KBps

kilobyte per second

=item mib, mibps or MiBps

mibibyte per second

=item mb, mbps or MBps

megabyte per second

=item gib, gibps or GiBps

gibibyte per second

=item gb, gbps or GBps

gigabyte per second

=back

=head1 CONFIGURATION

By default B<sc> reads F</etc/sc/sc.conf> file and uses SQLite database
F</etc/sc/sc.db>. See sc.conf(5) for details.

=head1 BUGS AND LIMITATIONS

Due to deterministic mapping of IP's to classid's B<sc> works
only with IP's that is distinguished by last two octets.

=head1 SEE ALSO

sc.conf(5), App::Config(3), Sys::Syslog(3), syslog(3), tc(8), iptables(8),
ipset(8).

=head1 AUTHOR

Stanislav Kruchinin <stanislav.kruchinin@gmail.com>

=head1 LICENSE AND COPYRIGHT

License: GPL v2 or later.

Copyright (c) 2008, 2009. Stanislav Kruchinin.

=cut

