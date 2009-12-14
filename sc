#!/usr/bin/perl

use strict;
use warnings;
use Carp;
use Getopt::Long qw( GetOptionsFromArray );
use DBI;
use Pod::Usage;
use Sys::Syslog;
use AppConfig qw( :expand );
use Term::ANSIColor;

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
my $colored = 'auto';
my $batch = 0;
my $joint = 0;

my $o_if = 'eth0';
my $i_if = 'eth1';

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
my $set_size = '65536';
my $chain_name = 'FORWARD';
my $quantum = '1500';
my $rate_unit = 'kibit';
my $leaf_qdisc = 'pfifo limit 50';
my $network = '172.16.0.0/16';
my $filter_network = $network;
my $filter_method = 'u32';
my (%filter_nets, %class_nets);

# leaf filter preference
my $u32_lpref = '20';
# parent hashing filter number
my $u32_pht = '400';

my $syslog = 0;
my $syslog_options = q{};
my $syslog_facility = 'user';

##############################################################################
# Internal variables and constants
#

my $PROG = 'sc';
my $VERSION = '1.1.0';
my $VERSTR = "Shaper Control Tool (version $VERSION)";

# command dispatch table
my %cmdd = (
	'add' => {
		# handler (points to function that performs action)
		'handler' => \&cmd_add,
		# database handler (optional)
		'dbhandler' => \&cmd_dbadd,
		# arguments (optional)
		'arg' => '<ip> <rate>',
		# command description
		'desc' => 'add rules',
		# check root privileges before execution (optional)
		'priv' => 1,
	},
	'calc' => {
		'handler' => \&cmd_calc,
		'arg' => '[ip]',
		'desc' => 'calculate and print internally used values',
		'priv' => 0,
	},
	'change|mod' => {
		'handler' => \&cmd_change,
		'dbhandler' => \&cmd_change,
		'arg' => '<ip> <rate>',
		'desc' => 'change rate',
		'priv' => 1,
	},
	'del|rm' => {
		'handler' => \&cmd_del,
		'dbhandler' => \&cmd_dbdel,
		'arg' => '<ip>',
		'desc' => 'delete rules',
		'priv' => 1,
	},
	'list|ls' => {
		'handler' => \&cmd_list,
		'arg' => '[ip]',
		'desc' => 'list current rules in human-readable form',
		'priv' => 1,
	},
	'help' => {
		'handler' => \&cmd_help,
		'desc' => 'show help and available database drivers',
		'priv' => 0,
	},
	'init' => {
		'handler' => \&cmd_init,
		'desc' => 'initialization of shaping rules',
		'priv' => 1,
	},
	'sync' => {
		'handler' => \&cmd_sync,
		'desc' => 'synchronize rules with database',
		'priv' => 1,
	},
	'load|start' => {
		'handler' => \&cmd_load,
		'desc' => 'load information from database and create all rules',
		'priv' => 1,
	},
	'ratecvt' => {
		'handler' => \&cmd_ratecvt,
		'arg' => '<rate> <unit>',
		'desc' => 'convert rate unit',
		'priv' => 0,
	},
	'reload|restart' => {
		'handler' => \&cmd_reload,
		'desc' => 'reset and load rules',
		'priv' => 1,
	},
	'reset|stop' => {
		'handler' => \&cmd_reset,
		'desc' => 'delete all shaping rules',
		'priv' => 1,
	},
	'show' => {
		'handler' => \&cmd_show,
		'arg' => '[ip]',
		'desc' => 'show rules explicitly',
		'priv' => 1,
	},
	'status' => {
		'handler' => \&cmd_status,
		'desc' => 'show status of rules',
		'priv' => 1,
	},
	'version' => {
		'handler' => \&cmd_ver,
		'desc' => 'output version',
		'priv' => 0,
	},
	'dbadd' => {
		'handler' => \&cmd_dbadd,
		'arg' => '<ip> <rate>',
		'desc' => 'add database entry',
		'priv' => 0,
	},
	'dbdel|dbrm' => {
		'handler' => \&cmd_dbdel,
		'arg' => '<ip>',
		'desc' => 'delete database entry',
		'priv' => 0,
	},
	'dblist|dbls' => {
		'handler' => \&cmd_dblist,
		'arg' => '[ip]',
		'desc' => 'list database entries',
		'priv' => 0,
	},
	'dbchange|dbmod' => {
		'handler' => \&cmd_dbchange,
		'arg' => '<ip> <rate>',
		'desc' => 'change database entry',
		'priv' => 0,
	},
	'dbcreate' => {
		'handler' => \&cmd_dbcreate,
		'desc' => 'create database and table',
		'priv' => 0,
	},
);

my ($rul_init, $rul_add, $rul_del, $rul_change, $rul_load,
	$rul_batch_start, $rul_batch_stop, $rul_show, $rul_reset);

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
	'bps|Bps'     => 8,
	'kibps|KiBps' => 8*1024,
	'kbps|KBps'   => 8_000,
	'mibps|MiBps' => 8*1024*1024,
	'mbps|MBps'   => 8_000_000,
	'gibps|GiBps' => 8*1024*1024*1024,
	'gbps|GBps'   => 8_000_000_000,
);

# Error codes
my $E_OK       = 0;
my $E_PARAM    = 1;
my $E_IP_COLL  = 2;
my $E_UNDEF    = 3;
my $E_EXIST    = 4;
my $E_NOTEXIST = 5;
my $E_CMD      = 6;
my $E_RUL      = 7;
my $E_PRIV     = 8;

# global return value
my $RET = $E_OK;

# Preamble for usage and help message
my $usage_preamble = <<"EOF"
$VERSTR

Usage: $PROG [options] command <arguments>

Commands:
EOF
;

# options dispatch table for AppConfig and Getopt::Long
my %optd = (
	'f|config=s'        => \$cfg_file,
	'iptables=s'        => \$iptables,
	'tc=s'              => \$tc,
	'ipset=s'           => \$ipset,
	'o|out_if=s'        => \$o_if,
	'i|in_if=s'         => \$i_if,
	'filter_method=s'   => \$filter_method,
	'd|debug=i'         => \$debug,
	'v|verbose!'        => \$verbose,
	'q|quiet!'          => \$quiet,
	'colored!'          => \$colored,
	'j|joint!'          => \$joint,
	'b|batch!'          => \$batch,
	's|set_name=s'      => \$set_name,
	'set_type=s'        => \$set_type,
	'set_size=s'        => \$set_size,
	'N|network=s'       => \$network,
	'filter_network=s'  => \$filter_network,
	'c|chain=s'         => \$chain_name,
	'quantum=s'         => \$quantum,
	'u|rate_unit=s'     => \$rate_unit,
	'leaf_qdisc=s'      => \$leaf_qdisc,
	'db_driver=s'       => \$db_driver,
	'db_host=s'         => \$db_host,
	'db_name=s'         => \$db_name,
	'db_user=s'         => \$db_user,
	'db_pass=s'         => \$db_pass,
	'query_create=s'    => \$query_create,
	'query_load=s'      => \$query_load,
	'query_list=s'      => \$query_list,
	'query_add=s'       => \$query_add,
	'query_del=s'       => \$query_del,
	'query_change=s'    => \$query_change,
	'S|syslog'          => \$syslog,
	'syslog_options'    => \$syslog_options,
	'syslog_facility=s' => \$syslog_facility,
);

my %db_data;
my %rul_data;

# handlers and pointers for command execution
my ($TC_H, $IPS_H);
my $TC = \&sys_tc;
my $IPS = \&sys_ips;
my $sys;

##############################################################################
# Main routine

# read configuration file
if (-T $cfg_file) {
	# process configuration file
	my @args = keys %optd;
	my @cargs = @args;

	my $cfg = AppConfig->new({
		CASE => 1,
		GLOBAL => {
			EXPAND => EXPAND_VAR | EXPAND_ENV
		}
	});

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

# autocompletion for commands
sub acomp_cmd
{
	my $input = shift;
	my @match;
	my @ambig;

	foreach my $key (keys %cmdd) {
		my @cmds = split /\|/ixms, $key;
		foreach my $a (@cmds) {
			if ($a =~ /^$input/xms) {
				push @match, $key;
				push @ambig, $a;
				last;
			}
		}
	}
	if ($#match == 0) {
		return $match[0];
	}
	elsif ($#match > 0) {
		log_warn("command \'$input\' is ambiguous:");
		print STDERR "    @ambig\n";
		return q{};
	}
	else {
		log_warn("unknown command \'$input\'\n");
		return;
	}
}

sub main
{
	my @argv = @_;
	my $ret = $E_OK;

	if ($batch) {
		GetOptionsFromArray(\@argv, %optd) or return $E_PARAM;
	}

	usage($E_CMD) if !defined $argv[0];
	my $cmd = acomp_cmd($argv[0]);
	usage($E_CMD) if !defined $cmd;
	return $E_CMD if $cmd eq q{};

	shift @argv;

	if ($cmdd{$cmd}{'priv'} && !$debug && $>) {
		log_warn("you must run this command with root privileges");
		return $E_PRIV;
	}

	set_ptrs();
	set_class_nets();
	set_filter_nets();

	$ret = $cmdd{$cmd}{'handler'}->(@argv);

	# process return values
	if ($ret == $E_NOTEXIST) {
		log_carp("specified IP does not exist. Arguments: @argv");
	}
	elsif ($ret == $E_EXIST) {
		log_carp("specified IP already exists. Arguments: @argv");
	}

	if ($joint && defined $cmdd{$cmd}{'dbhandler'}) {
		$ret = $cmdd{$cmd}{'dbhandler'}->(@argv);
		if ($ret == $E_NOTEXIST) {
			log_carp(
				"database entry for specified IP does not exist. ".
				"Arguments: @argv"
			);
		}
		elsif ($ret == $E_EXIST) {
			log_carp(
				"database entry for specified IP already exists. ".
				"Arguments: @argv"
			);
		}
	}

	return $ret;
}

# system wrappers for different debug modes
sub sys_quiet
{
	my $c = shift;
	return system "$c >/dev/null 2>&1";
}

sub sys_debug_print
{
	my $c = shift;
	print "$c\n";
	return 0;
}

sub sys_debug_on
{
	my $c = shift;
	system "$c";
	print "$c\n" if $?;
	return $?;
}

# set function pointers
sub set_ptrs
{
	if ($debug == $DEBUG_OFF) {
		$sys = ($quiet) ? \&sys_quiet : sub { return system @_ };
	}
	elsif ($debug == $DEBUG_ON) {
		$sys = \&sys_debug_on;
	}
	elsif ($debug == $DEBUG_PRINT) {
		$sys = \&sys_debug_print;
	}

	if ($filter_method eq 'flow') {
		$rul_init = \&rul_init_flow;
		$rul_add = \&rul_add_flow;
		$rul_del = \&rul_del_flow;
		$rul_change = \&rul_change_tc;
		$rul_batch_start = sub {
			if (!$verbose) {
				batch_start_tc();
				batch_start_ips();
			}
		};
		$rul_batch_stop = sub {
			if (!$verbose) {
				batch_stop_tc();
				batch_stop_ips();
			}
			rul_init_ipt();
		};
		$rul_load = \&rul_load_flow;
		$rul_show = \&rul_show_flow;
		$rul_reset = sub {
			rul_reset_ips();
			rul_reset_tc();
		};
	}
	elsif ($filter_method eq 'u32') {
		$rul_init = sub {
			rul_init_u32($o_if, 'src', 12);
			rul_init_u32($i_if, 'dst', 16);
		};
		$rul_add = \&rul_add_u32;
		$rul_del = \&rul_del_u32;
		$rul_change = \&rul_change_tc;
		$rul_batch_start = sub {
			batch_start_tc() if !$verbose;
		};
		$rul_batch_stop = sub {
			batch_stop_tc() if !$verbose;
		};
		$rul_load = \&rul_load_u32;
		$rul_show = \&rul_show_u32;
		$rul_reset = \&rul_reset_tc;
	}
	return;
}

# fill filter_nets hash
sub set_filter_nets {
	# I restrict this value to a 0x799 to avoid discontinuity of filter space.
	# Real maximum number of u32 hash tables is 0xfff.
	my $ht_max = 1945;

	# Initial numbers for hash tables of 1st and 2nd nesting levels
	#
	# Real minimal number of u32 hash tables is 1.
	# 0x100 is taken for simplicity.
	my $ht1 = 256;
	# Difference between initial numbers for hash tables of 1st and 2nd nesting
	# levels. Increase this value if you want to set more than 255 netmasks to
	# filter_network parameter.
	my $ht_21 = 256;
	my $ht2 = $ht1 + $ht_21;

	foreach my $n (split /\ /ixms, $filter_network) {
		my ($netip, $netmask) = split /\//ixms, $n;
		if ($netmask >= 24 && $netmask < 32) {
			$filter_nets{$n}{'leafht_i'} = $ht1;
		}
		elsif ($netmask >= 16 && $netmask < 24) {
			$filter_nets{$n}{'leafht_i'} = $ht2;
			$ht2 += 2**(24 - $netmask);
		}
		else {
			log_croak("network mask $netmask is not supported. Network: $n");
		}

		$filter_nets{$n}{'ip'} = $netip;
		$filter_nets{$n}{'mask'} = $netmask;
		my $invmask = 2**(32 - $netmask) - 1;
		my $intmask = 2**32 - 1 - $invmask;
		my $ip_i = ip_texttoint($netip) & $intmask;
		$filter_nets{$n}{'invmask'} = $invmask;
		$filter_nets{$n}{'intip_i'} = $ip_i;
		$filter_nets{$n}{'intip_f'} = $ip_i + $invmask;
		$filter_nets{$n}{'ht'} = $ht1;

		++$ht1;
		log_croak("network $n overfulls filter space")
			if ($ht2 > $ht_max);
	}
	return;
}

sub set_class_nets
{
	my $cid_min = 2;
	my $cid_max = 65535;
	my $cid_i = $cid_min;

	foreach my $n (split /\ /ixms, $network) {
		my ($netip, $netmask) = split /\//ixms, $n;

		log_croak("network mask $netmask is not supported. Network: $n")
			if $netmask < 16;

		$class_nets{$n}{'ip'} = $netip;
		$class_nets{$n}{'mask'} = $netmask;
		my $invmask = 2**(32 - $netmask) - 1;
		my $intmask = 2**32 - 1 - $invmask;
		my $ip_i = ip_texttoint($netip) & $intmask;
		$class_nets{$n}{'invmask'} = $invmask;
		$class_nets{$n}{'intip_i'} = $ip_i;
		$class_nets{$n}{'intip_f'} = $ip_i + $invmask;

		$class_nets{$n}{'classid_i'} = $cid_i;
		$cid_i += $invmask + 1;
		log_croak("network $n overfulls classid space")
			if ($cid_i - $cid_min - 1 > $cid_max);
	}
	return;
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
	chomp $ip;

	if ($ip =~ /^(\d{1,3})\.(\d{1,3})\.(\d{1,3})\.(\d{1,3})$/ixms) {
		if ($1 >  0 && $1 <  255 && $2 >= 0 && $2 <= 255 &&
			$3 >= 0 && $3 <= 255 && $4 >= 0 && $4 <= 255) {
			return $ip;
		}
	}
	return 0;
}

sub is_rate
{
	my $rate = shift;
	chomp $rate;
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

# sort by hash table
sub by_ht
{
	return $filter_nets{$a}{'ht'} <=> $filter_nets{$b}{'ht'};
}

# calculate tc classid from text form of IP
sub ip_classid
{
	my $ip = shift;
	my $intip = ip_texttoint($ip);
	my $cid;

	foreach my $n (keys %class_nets) {
		if ($intip >= $class_nets{$n}{'intip_i'} &&
			$intip <= $class_nets{$n}{'intip_f'}) {
			my $offset = $intip & $class_nets{$n}{'invmask'};
			$cid = sprintf "%x", $class_nets{$n}{'classid_i'} + $offset;
		}
	}
	log_croak(
		"$ip does not belong to any of specified networks: $network"
	) if !defined $cid;

	return $cid;
}

# calculate leaf hash table and bucket number
#
# input: IP address
# output: leaf hash key and bucket number
sub ip_leafht_key
{
	my $ip = shift;
	my $intip = ip_texttoint($ip);
	my ($leafht, $key);

	foreach my $n (keys %filter_nets) {
		if ($intip >= $filter_nets{$n}{'intip_i'} &&
			$intip <= $filter_nets{$n}{'intip_f'}) {
			# 3rd octet
			my $ht_offset = ($intip & $filter_nets{$n}{'invmask'}) >> 8;
			# 4th octet
			$key = $intip & 0xff;
			$leafht = $filter_nets{$n}{'leafht_i'} + $ht_offset;
			last;
		}
	}
	log_croak(
		"$ip does not belong to any of specified networks: $network"
	) if !defined $leafht;

	return (sprintf('%x', $leafht), sprintf('%x', $key));
}

# calculate divisor and hashkey mask from netmask
#
# netmask = mask in numeric form
# n = number of octet to be used in filter
sub div_hmask_u32
{
	my ($netmask, $n) = @_;

	log_croak("$n is invalid number of octet") if ($n < 1 || $n > 4);
	# get n-th byte from netmask
	my $inthmask = (2**(32 - $netmask) - 1) & (0xff << 8*(4-$n));
	my $hmask = sprintf '0x%08x', $inthmask;
	my $div = ($inthmask >> 8*(4-$n)) + 1;

	return ($div, $hmask);
}

# convert IP from text to int form
sub ip_texttoint
{
	my $ip = shift;
	my @oct = split /\./ixms, $ip;
	my $int = 0;
	for my $i (0..3) {
		$int += $oct[$i]*( 1 << 8*(3-$i) );
	}
	return $int;
}

# convert IP from int to text form
sub ip_inttotext
{
	my $int = shift;
	my @oct;

	for my $i (0..3) {
		my $div = 1 << 8*(3-$i);
		$oct[$i] = int($int/$div);
		$int %= $div;
	}

	return join '.', @oct;
}

sub log_syslog
{
	my ($severity, $msg) = @_;
	openlog($PROG, $syslog_options, $syslog_facility);
	syslog($severity, $msg);
	closelog();
	return $!;
}

sub log_carp
{
	my $msg = shift;
	log_syslog('warn', $msg) if $syslog;
	if (!$quiet) {
		carp "$PROG: $msg";
	}
	return $!;
}

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

sub log_warn
{
	my $msg = shift;
	log_syslog('warning', $msg) if $syslog;
	print STDERR "$PROG: $msg\n";
	return $!;
}

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

sub db_load
{
	my $dbh = db_connect();
	my $sth = $dbh->prepare($query_load);
	$sth->execute();

	my ($intip, $rate, $ip, $cid);
	while (my $ref = $sth->fetchrow_arrayref()) {
		($intip, $rate) = @$ref;

		if (!defined $rate) {
			log_carp("IP $ip has undefined rate, skipping\n");
			$RET = $E_UNDEF;
			next;
		}

		$ip = ip_inttotext($intip);
		$cid = ip_classid($ip);

		$db_data{$cid}{'rate'} = $rate;
		$db_data{$cid}{'ip'} = $ip;
	}

	$sth->finish();
	$sth = undef; # hack for SQLite
	$dbh->disconnect();

	return $dbh;
}

sub rul_add_flow
{
	my ($ip, $cid, $rate) = @_;

	my $ceil = $rate;
	my $ret = 0;

	$TC->(
		"class replace dev $o_if parent 1: classid 1:$cid htb rate $rate ".
		"ceil $ceil quantum $quantum"
	);
	$TC->(
		"class replace dev $i_if parent 1: classid 1:$cid htb rate $rate ".
		"ceil $ceil quantum $quantum"
	);

	$TC->(
		"qdisc replace dev $o_if parent 1:$cid handle $cid:0 $leaf_qdisc"
	);
	$TC->(
		"qdisc replace dev $i_if parent 1:$cid handle $cid:0 $leaf_qdisc"
	);

	$IPS->("-A $set_name $ip");

	return $?;
}

sub rul_add_u32
{
	my ($ip, $cid, $rate) = @_;
	my ($ht, $key) = ip_leafht_key($ip);
	my $ceil = $rate;

	$TC->(
		"class replace dev $o_if parent 1: classid 1:$cid htb rate $rate ".
		"ceil $ceil quantum $quantum"
	);
	$TC->(
		"class replace dev $i_if parent 1: classid 1:$cid htb rate $rate ".
		"ceil $ceil quantum $quantum"
	);

	$TC->(
		"qdisc replace dev $o_if parent 1:$cid handle $cid:0 $leaf_qdisc"
	);
	$TC->(
		"qdisc replace dev $i_if parent 1:$cid handle $cid:0 $leaf_qdisc"
	);

	$TC->(
		"filter replace dev $o_if parent 1: pref 20 u32 ht $ht:$key: ".
		"match ip src $ip flowid 1:$cid"
	);
	$TC->(
		"filter replace dev $i_if parent 1: pref 20 u32 ht $ht:$key: ".
		"match ip dst $ip flowid 1:$cid"
	);

	return $?;
}

sub rul_del_flow
{
	my ($ip, $cid) = @_;

	$IPS->("-D $set_name $ip");

	$TC->("qdisc del dev $o_if parent 1:$cid handle $cid:0");
	$TC->("qdisc del dev $i_if parent 1:$cid handle $cid:0");

	$TC->("class del dev $o_if parent 1: classid 1:$cid");
	$TC->("class del dev $i_if parent 1: classid 1:$cid");

	return $?;
}

sub rul_del_u32
{
	my ($ip, $cid) = @_;
	my ($ht, $key) = ip_leafht_key($ip);

	$TC->(
		"filter del dev $o_if protocol ip parent 1: pref 10 ".
		"handle $ht:$key:800 u32"
	);
	$TC->("qdisc del dev $o_if parent 1:$cid handle $cid:0");
	$TC->("class del dev $o_if parent 1: classid 1:$cid");

	$TC->(
		"filter del dev $i_if protocol ip parent 1: pref 10 ".
		"handle $ht:$key:800 u32"
	);
	$TC->("qdisc del dev $i_if parent 1:$cid handle $cid:0");
	$TC->("class del dev $i_if parent 1: classid 1:$cid");

	return $?
}

sub rul_change_tc
{
	my ($ip, $cid, $rate) = @_;
	my $ceil = $rate;

	$TC->(
		"class change dev $o_if parent 1:0 classid 1:$cid htb ".
		"rate $rate ceil $ceil quantum $quantum"
	);
	$TC->(
		"class change dev $i_if parent 1:0 classid 1:$cid htb ".
		"rate $rate ceil $ceil quantum $quantum"
	);

	return $?;
}

sub rul_load_flow
{
	my ($ip, $cid, $rate);
	my $ret = 0;

	open my $IPH, '-|', "$ipset -nsL $set_name" or
		log_croak("unable to open pipe for $ipset");
	my @ipsout = <$IPH>;
	close $IPH or log_carp("unable to close pipe for $ipset");
	foreach (@ipsout) {
		next unless /^\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}/xms;
		chomp;
		$ip = $_;
		$cid = ip_classid($ip);

		if (defined $rul_data{$cid}{'ip'}) {
			log_carp("IP-to-classid collision detected, skipping. OLD: ".
				$rul_data{$cid}{'ip'}.", NEW: $ip");
			$ret = $E_IP_COLL;
			next;
		}

		$rul_data{$cid}{'ip'} = $ip;
	}

	open my $TCH, '-|', "$tc class show dev $i_if"
		or log_croak("unable to open pipe for $tc");
	my @tcout = <$TCH>;
	close $TCH or log_carp("unable to close pipe for $tc");
	foreach (@tcout) {
		if (/leaf\ ([0-9a-f]+):\ .* rate\ (\w+)/xms) {
			($cid, $rate) = ($1, $2);
			next if !defined $rul_data{$cid};
			$rate = rate_cvt($rate, $rate_unit);
			$rul_data{$cid}{'rate'} = $rate;
		}
	}

	return $ret;
}

sub rul_load_u32
{
	my ($ip, $cid, $rate);
	my $ret = 0;

	open my $TCFH, '-|', "$tc -p filter show dev $i_if"
		or log_croak("unable to open pipe for $tc");
	my @tcout = <$TCFH>;
	close $TCFH or log_carp("unable to close pipe for $tc");
	for my $i (0 .. $#tcout) {
		chomp $tcout[$i];
		if ($tcout[$i] =~
				/match\ IP\ .*\ (\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})\/32/xms) {
			$ip = $1;
			if ($tcout[$i-1] =~ /flowid\ 1:([0-9a-f]+)/xms) {
				$cid = $1;
				$rul_data{$cid}{'ip'} = $ip;
			}
		}
	}

	open my $TCCH, '-|', "$tc class show dev $i_if"
		or log_croak("unable to open pipe for $tc");
	@tcout = <$TCCH>;
	close $TCCH or log_carp("unable to close pipe for $tc");
	foreach (@tcout) {
		if (/leaf\ ([0-9a-f]+):\ .* rate\ (\w+)/xms) {
			($cid, $rate) = ($1, $2);
			next if !defined $rul_data{$cid};
			$rate = rate_cvt($rate, $rate_unit);
			$rul_data{$cid}{'rate'} = $rate;
		}
	}

	return $ret;
}

sub rul_init_flow
{
	$TC->("qdisc add dev $o_if root handle 1: htb");
	$TC->(
		"filter add dev $o_if parent 1:0 protocol ip handle 1 pref 10 ".
		"flow map key src and 0xffff"
	);

	$TC->("qdisc add dev $i_if root handle 1: htb");
	$TC->(
		"filter add dev $i_if parent 1:0 protocol ip handle 1 pref 10 ".
		"flow map key dst and 0xffff"
	);

	# create iphash and rules for allowed IPs
	if ($set_type eq 'ipmap') {
		$IPS->("-N $set_name $set_type --network $network");
	}
	elsif ($set_type eq 'iphash') {
		$IPS->("-N $set_name $set_type --hashsize $set_size");
	}
	else {
		log_croak("unknown set type \'$set_type\' specified");
	}

	return $?;
}

sub rul_init_ipt
{
	$sys->("$iptables --policy FORWARD DROP");
	if ($chain_name ne 'FORWARD') {
		$sys->("$iptables --new-chain $chain_name");
		$sys->("$iptables -A FORWARD -j $chain_name");
	}
	$sys->(
		"$iptables -A $chain_name -p all -m set --set $set_name src -j ACCEPT"
	);
	$sys->(
		"$iptables -A $chain_name -p all -m set --set $set_name dst -j ACCEPT"
	);

	return $?;
}

sub rul_init_u32
{
	my ($dev, $match, $offset) = @_;

	# root qdisc
	$TC->("qdisc add dev $dev root handle 1: htb");

	# hashing filters
	$TC->(
		"filter add dev $dev parent 1:0 pref 10 protocol ip u32"
	);

	foreach my $net (sort by_ht keys %filter_nets) {
		my $ht1 = sprintf '%x', $filter_nets{$net}{'ht'};
		my $netmask = $filter_nets{$net}{'mask'};

		if ($netmask >= 24 && $netmask < 31) {
			my ($div1, $hmask1) = div_hmask_u32($netmask, 4);

			$TC->(
				"filter add dev $dev parent 1:0 pref 10 handle $ht1: ".
				"protocol ip u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent 1:0 pref 10 protocol ip u32 ".
				"ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);
		}
		elsif ($netmask >= 16 && $netmask < 24) {
			my @oct = split /\./ixms, $filter_nets{$net}{'ip'};
			my ($div1, $hmask1) = div_hmask_u32($netmask, 3);

			# parent filter
			$TC->(
				"filter add dev $dev parent 1:0 pref 10 handle $ht1: ".
				"protocol ip u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent 1:0 pref 10 protocol ip u32 ".
				"ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);

			# child filters
			my ($div2, $hmask2) = div_hmask_u32($netmask, 4);
			for my $i (0 .. $div1 - 1) {
				my $key = sprintf '%x', $i;
				my $ht2 = sprintf '%x', $filter_nets{$net}{'leafht_i'} + $i;
				my $net2 = "$oct[0].$oct[1].$i.0/24";

				$TC->(
					"filter add dev $dev parent 1:0 pref 10 handle $ht2: ".
					"protocol ip u32 divisor $div2"
				);
				$TC->(
					"filter add dev $dev parent 1:0 pref 10 protocol ip ".
					"u32 ht $ht1:$key: match ip $match $net2 ".
					"hashkey mask $hmask2 at $offset link $ht2:"
				);
			}
		}
		else {
			log_croak("network mask $netmask is not supported");
		}
	}

	$TC->(
		"filter add dev $dev parent 1:0 protocol ip pref 30 u32 ".
		"match u32 0x0 0x0 at 0 police mtu 1 action drop"
	);

	return $?;
}

sub rul_show_flow
{
	my @ips = @_;
	my @out;

	if (!nonempty($ips[0])) {
		cprint('bold', "QDISCS:\n");
		system "$tc -i -s -d qdisc show dev $i_if";
		system "$tc -i -s -d qdisc show dev $o_if";
		cprint('bold', "\nCLASSES:\n");
		system "$tc -i -s -d class show dev $i_if";
		system "$tc -i -s -d class show dev $o_if";
		cprint('bold', "\nFILTERS:\n");
		system "$tc -s -d filter show dev $i_if";
		system "$tc -s -d filter show dev $o_if";
		cprint('bold', "\nIPTABLES RULES:\n");
		system "$iptables -nL";

		return $?;
	}

	foreach my $ip (@ips) {
		my $cid = ip_classid($ip);

		# tc qdisc
		print_rules(
			"TC rules for $ip\n\nInput qdisc [$i_if, $cid]:",
			"$tc -i -s -d qdisc show dev $i_if | ".
			"fgrep -w -A 2 \"$cid\: parent 1:$cid\""
		);
		print_rules(
			"\nOutput qdisc [$o_if, $cid]:",
			"$tc -i -s -d qdisc show dev $o_if | ".
			"fgrep -w -A 2 \"$cid\: parent 1:$cid\""
		);

		# tc class
		print_rules(
			"\nInput class [$i_if, $cid]:",
			"$tc -i -s -d class show dev $i_if | ".
			"fgrep -w -A 3 \"leaf $cid\:\""
		);
		print_rules(
			"\nOutput class [$o_if, $cid]:",
			"$tc -i -s -d class show dev $o_if | ".
			"fgrep -w -A 3 \"leaf $cid\:\""
		);

		# ipset
		print_rules("\nIPSet entry for $ip:", "$ipset -T $set_name $ip");
		print "\n";
	}

	return $?;
}

sub rul_show_u32
{
	my @ips = @_;
	my @out;

	if (!nonempty($ips[0])) {
		cprint('bold', "QDISCS:\n");
		system "$tc -i -s -d qdisc show dev $i_if";
		system "$tc -i -s -d qdisc show dev $o_if";
		cprint('bold', "\nCLASSES:\n");
		system "$tc -i -s -d class show dev $i_if";
		system "$tc -i -s -d class show dev $o_if";
		cprint('bold', "\nFILTERS:\n");
		system "$tc -s -d filter show dev $i_if";
		system "$tc -s -d filter show dev $o_if";

		return $?;
	}

	foreach my $ip (@ips) {
		my $cid = ip_classid($ip);

		# tc qdisc
		print_rules(
			"Input qdisc [$i_if, $cid]:",
			"$tc -i -s -d qdisc show dev $i_if | ".
			"fgrep -w -A 2 \"$cid\: parent 1:$cid\""
		);
		print_rules(
			"\nOutput qdisc [$o_if, $cid]:",
			"$tc -i -s -d qdisc show dev $o_if | ".
			"fgrep -w -A 2 \"$cid\: parent 1:$cid\""
		);

		# tc class
		print_rules(
			"\nInput class [$i_if, $cid]:",
			"$tc -i -s -d class show dev $i_if | ".
			"fgrep -w -A 3 \"leaf $cid\:\""
		);
		print_rules(
			"\nOutput class [$o_if, $cid]:",
			"$tc -i -s -d class show dev $o_if | ".
			"fgrep -w -A 3 \"leaf $cid\:\""
		);
		# tc filter
		print_rules(
			"\nInput filter [$i_if, $cid]:",
			"$tc -p -s filter show dev $i_if | ".
			"fgrep -w -B 1 \"match IP dst $ip/32\""
		);
		print_rules(
			"\nOutput filter [$o_if, $cid]:",
			"$tc -p -s filter show dev $o_if | ".
			"fgrep -w -B 1 \"match IP src $ip/32\""
		);
		print "\n";
	}

	return $?;
}

sub rul_reset_ips
{
	if ($chain_name ne 'FORWARD') {
		$sys->("$iptables --delete FORWARD -j $chain_name");
		$sys->("$iptables --flush $chain_name");
		$sys->("$iptables --delete-chain $chain_name");
	}
	else {
		$sys->("$iptables -D $chain_name -p all -m set --set $set_name src ".
			"-j ACCEPT");
		$sys->("$iptables -D $chain_name -p all -m set --set $set_name dst ".
			"-j ACCEPT");
	}

	$sys->("$ipset --flush $set_name");
	$sys->("$ipset --destroy $set_name");

	return $?;
}

sub rul_reset_tc
{
	$sys->("$tc qdisc del dev $o_if root handle 1: htb");
	$sys->("$tc qdisc del dev $i_if root handle 1: htb");

	return $?;
}

# colored print with autodetection of non-tty handle
sub cprint
{
	my ($color, $msg) = @_;

	use POSIX 'isatty';

	if ($colored && isatty(\*STDOUT) ne q{}) {
		print colored [$color], $msg;
	}
	else {
		print $msg;
	}
	return;
}

sub print_rules
{
	my ($comment, @cmds) = @_;
	my @out;
	my $PIPE;

	foreach my $c (@cmds) {
		open $PIPE, '-|', $c or log_croak("unable to open pipe for $c");
		push @out, <$PIPE>;
		close $PIPE or log_croak("unable to close pipe for $c");
	}
	if (@out) {
		cprint('bold', "$comment\n") if nonempty($comment);
		print @out;
	}
	return $?;
}

sub print_cmds
{
	my @cmds = sort keys %cmdd;
	my ($maxcmdlen, $maxarglen) = (0, 0);
	my @colspace = (2, 2, 3);
	my ($al, $cl);
	my %lengths;

	# find maximum length of command and arguments
	foreach my $key (@cmds) {
		my @aliases = split /\|/ixms, $key;
		$lengths{$key}{'cmd'} = $aliases[0];

		$cl = length $aliases[0];
		$lengths{$key}{'cmdl'} = $cl;
		$maxcmdlen = $cl if $maxcmdlen < $cl;

		$al = (defined $cmdd{$key}{'arg'})
			? length $cmdd{$key}{'arg'} : 0;
		$lengths{$key}{'argl'} = $al;
		$maxarglen = $al if $maxarglen < $al;
	}

	foreach my $key (@cmds) {
		next unless nonempty($cmdd{$key}{'desc'});
		print ' ' x $colspace[0], $lengths{$key}{'cmd'},
		      ' ' x ($maxcmdlen - $lengths{$key}{'cmdl'} + $colspace[1]);
		print $cmdd{$key}{'arg'} if defined $cmdd{$key}{'arg'};
		print ' ' x ($maxarglen - $lengths{$key}{'argl'} + $colspace[2]),
		      $cmdd{$key}{'desc'}, "\n";
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
	my ($rate, $dst_unit) = @_;
	my ($num, $unit, $s_key, $d_key);

	if ($rate =~ /^(\d+)([a-zA-Z]+)$/xms) {
		$num = $1;
		$unit = nonempty($2) ? $2 : $rate_unit;
		return $rate if $unit eq $dst_unit;
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
		if ($dst_unit =~ /^($u)$/xms) {
			$d_key = $u;
			last;
		}
	}
	log_croak("invalid destination unit specified") if !defined $d_key;

	my $dnum = round($num * $units{$s_key} / $units{$d_key});
	return "$dnum$dst_unit";
}

sub usage
{
	$RET = shift;

	print $usage_preamble;
	print_cmds();
	print "\n";
	exit $RET;
}

sub sys_tc
{
	my $c = shift;
	return $sys->("$tc $c");
}

sub batch_tc
{
	my $c = shift;
	print $TC_H "$c\n";
	return 0;
}

sub batch_start_tc
{
	if ($debug == $DEBUG_PRINT) {
		open $TC_H, '>', "tc.batch"
			or log_croak("unable to open tc.out");
	}
	else {
		open $TC_H, '|-', "$tc -batch"
			or log_croak("unable to create pipe for $tc");
	}

	$TC = \&batch_tc;

	return $TC_H;
}

sub batch_stop_tc
{
	$TC = \&sys_tc;
	return close $TC_H;
}

sub sys_ips
{
	my $c = shift;
	return $sys->("$ipset $c");
}

sub batch_ips
{
	my $c = shift;
	print $IPS_H "$c\n";
	return
}

sub batch_start_ips
{
	if ($debug == $DEBUG_PRINT) {
		open $IPS_H, '>', "ipset.batch"
			or log_croak("unable to open ipset.out");
	}
	else {
		open $IPS_H, '|-', "$ipset --restore"
			or log_croak("unable to create pipe for $ipset");
	}

	$IPS = \&batch_ips;

	return $IPS_H;
}

sub batch_stop_ips
{
	$IPS = \&sys_ips;
	print $IPS_H "COMMIT\n";
	return close $IPS_H;
}

##############################################################################
# Command handlers
#

sub cmd_init
{
	my $ret = $E_OK;

	$rul_batch_start->();
	$ret = $rul_init->();
	$rul_batch_stop->();

	return $ret;
}

sub cmd_reset
{
	return $rul_reset->();
}

sub cmd_add
{
	my ($ip, $rate) = @_;

	arg_check(\&is_ip, $ip, "IP");
	$rate = arg_check(\&is_rate, $rate, "rate");
	my $cid = ip_classid($ip);
	return $rul_add->($ip, $cid, $rate);
}

sub cmd_del
{
	my ($ip) = @_;

	arg_check(\&is_ip, $ip, "IP");
	my $cid = ip_classid($ip);
	return $rul_del->($ip, $cid);
}

sub cmd_change
{
	my ($ip, $rate) = @_;

	arg_check(\&is_ip, $ip, "IP");
	$rate = arg_check(\&is_rate, $rate, "rate");
	my $cid = ip_classid($ip);
	return $rul_change->($ip, $cid, $rate);
}

sub cmd_list
{
	my $ip = shift;
	my $ret = $rul_load->();

	if (!defined $ip) {
		foreach my $cid (sort { hex $a <=> hex $b } keys %rul_data) {
			printf "%4s  %-15s %10s\n", $cid, $rul_data{$cid}{'ip'},
				$rul_data{$cid}{'rate'};
		}
	}
	else {
		arg_check(\&is_ip, $ip, "IP");
		my $cid = ip_classid($ip);
		if (defined $rul_data{$cid}) {
			printf "%4s  %-15s %10s\n", $cid, $rul_data{$cid}{'ip'},
				$rul_data{$cid}{'rate'};
		}
	}
	return $ret;
}

sub cmd_load
{
	my $ret = $E_OK;

	$rul_batch_start->();
	$ret = $rul_init->();
	db_load();
	foreach my $cid (keys %db_data) {
		my $r = $db_data{$cid}{'rate'};
		$rul_add->($db_data{$cid}{'ip'}, $cid, "$r$rate_unit");
	}
	$rul_batch_stop->();

	return $ret;
}

sub cmd_show
{
	return $rul_show->(@_);
}

sub cmd_sync
{
	my ($add, $del, $chg) = (0,0,0);

	$rul_load->();
	db_load();

	# delete rules for IPs that is not in database
	foreach my $rcid (keys %rul_data) {
		if (!defined $db_data{$rcid} && defined $rul_data{$rcid}) {
			my $ip = $rul_data{$rcid}{'ip'};
			print "- $ip\n" if $verbose;
			$rul_del->($ip, $rcid);
			$del++;
		}
	}

	foreach my $dcid (keys %db_data) {
		# delete entries with zero rates
		if ($db_data{$dcid}{'rate'} == 0) {
			my $ip = $db_data{$dcid}{'ip'};
			print "- $ip\n" if $verbose;
			$rul_del->($ip, $dcid);
			$del++;
			next;
		}
		my $db_rate = "$db_data{$dcid}{'rate'}$rate_unit";
		# add new entries
		if (!defined $rul_data{$dcid}) {
			my $ip = $db_data{$dcid}{'ip'};
			print "+ $ip\n" if $verbose;
			$rul_add->($ip, $dcid, $db_rate);
			$add++;
			next;
		}
		# change if rate in database is different
		my $rul_rate = $rul_data{$dcid}{'rate'};
		if ($rul_rate ne $db_rate) {
			my $ip = $db_data{$dcid}{'ip'};
			print "* $ip $rul_rate -> $db_rate\n" if $verbose;
			$rul_change->($ip, $dcid, $db_rate);
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
	my @out;
	open my $PIPE, '-|', "$tc qdisc show dev $o_if"
		or log_croak("unable to open pipe for $tc");
	@out = <$PIPE>;
	close $PIPE or log_croak("unable to close pipe for $tc");

	if ($out[0] !~ /^qdisc\ htb/xms) {
		print STDERR "$PROG: no shaping rules found\n";
		return 1;
	}

	my @lqd = split /\ /xms, $leaf_qdisc;
	my $lqdisk = $lqd[0];
	shift @out;

	foreach my $s (@out) {
		chomp $s;
		if ($s =~ /qdisc\ $lqdisk\ ([0-9a-f]+):/xms) {
			print STDERR "$PROG: shaping rules were successfully created\n";
			return 0;
		}
	}
	print STDERR "$PROG: htb qdisc found but there is no child queues\n";
	return 2;
}

sub cmd_ver
{
	print "$VERSTR\n";
	return $E_OK;
}

sub cmd_help
{
	if ($verbose) {
		pod2usage({ -exitstatus => 0, -verbose => 2 });
	}
	else {
		print "$VERSTR\n\n";
		pod2usage({ -exitstatus => "NOEXIT", -verbose => 99,
			-sections => "SYNOPSIS|COMMANDS|OPTIONS", -output => \*STDOUT });
		print "Available database drivers:\n";
		print map { "    $_\n" } DBI->available_drivers;
		print "\n";
	}
	return $E_OK;
}

sub cmd_dbcreate
{
	my $dbh = db_connect();
	$dbh->do($query_create);
	$dbh->disconnect();
	return $dbh;
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

sub cmd_ratecvt
{
	my ($rate, $unit) = @_;
	my $result;
	log_croak("rate is undefined") if !defined $rate;
	log_croak("destination unit is undefined") if !defined $unit;

	$result = rate_cvt($rate, $unit);
	print "$result\n";
	return $E_OK;
}

sub cmd_calc
{
	use Data::Dumper;

	my $ip = shift;
	if (!defined $ip) {
		print Dumper(\%filter_nets);
		print Dumper(\%class_nets);
		return $E_OK;
	}
	my $n;

	arg_check(\&is_ip, $ip, "IP");
	my $cid = ip_classid($ip);
	my ($ht, $key) = ip_leafht_key($ip);
	print "classid = $cid, leaf ht = $ht, key = $key\n";

	return $E_OK;
}


__END__

=head1 NAME

B<sc> - administration tool for ISP traffic shaper

=head1 SYNOPSIS

B<sc> [I<options>] B<command> [I<ip>] [I<rate>]

=head1 DESCRIPTION

B<sc> is a command-line tool intended to simplify administration of traffic
shaper for Internet service providers. ISP's usually work with the following
configuration: every customer has it's own IP-address and fixed bandwidth.
B<sc> works like a wrapper for tc(8), iptables(8) and ipset(8) abstracting you
from complexity of their rules, so you can think only about IPs and bandwidth
rates and almost forget about classid's, qdiscs, filters and other stuff.

=head2 Features

=over

=item * Fast loading of large rulesets by using batch modes of tc(8) and
ipset(8).

=item * Effective per-user classification using u32 hashing filters or flow
classifier.

=item * Loading and editing of IPs and rates from any relational database
supported by Perl B<DBI> module.

=item * Synchronization of rules with database.

=item * Batch command execution mode for scripting purposes.

=back


=head1 PREREQUISITES

=head2 Perl modules

DBI and corresponding database-dependent module (e.g. DBD::Pg for PostgreSQL,
DBD::SQLite for SQLite, etc), AppConfig, Carp, Getopt::Long, Pod::Usage,
Sys::Syslog, Term::ANSIColor.

=head2 Command-line tools

tc(8) from B<iproute2> suite.

=head2 Linux kernel configuration

=over

=item B<u32> classifier (option B<CONFIG_NET_CLS_U32>=m or y)

=item Traffic control actions (B<CONFIG_NET_CLS_ACT>=y and
B<CONFIG_NET_CLS_GACT>=m or y)

=head1 COREQUISITES

If you prefer to use B<flow> filtering method, you will need to install
iptables(8) and ipset(8), B<flow> classifier (kernel version 2.6.25 or above,
option B<CONFIG_NET_CLS_FLOW>=m or y), and B<ipset> kernel modules (see
L<http://ipset.netfilter.org/> for details).


=head1 COMMANDS

=over 16

=item B<add> <I<ip>> <I<rate>>

Add rules for specified IP

=item B<calc> [I<ip>]

Calculate and print internally used variables: classids, hash table numbers
and keys.

=item B<change> | B<mod> <I<ip>> <I<rate>>

Change rate for specified IP

=item B<dbadd> <I<ip>> <I<rate>>

Add database entry

=cut

=item B<dbchange> | B<dbmod> <I<ip>> <I<rate>>

Change database entry

=item B<dbcreate>

Create database and table

=item B<dbdel> | B<dbrm> <I<ip>>

Delete database entry

=item B<dblist> | B<dbls> [I<ip>]

List database entries. If no IP specified, all entries are listed.

=item B<del> | B<rm> <I<ip>>

Delete rules

=item B<help>

Show help for commands, options and list available database drivers

=item B<init>

Initialization of firewall and QoS rules. Use it only for manual rule editing.

=item B<list> | B<ls> [I<ip>]

List rules in human-readable form. If no IP specified, all entries are listed.

=item B<load> | B<start>

Load IPs and rates from database and create ruleset

=item B<ratecvt> <I<rate>> <I<unit>>

Convert rate from one unit to another

=item B<reload> | B<restart>

Reset rules and load database

=item B<reset> | B<stop>

Delete all shaping rules

=item B<show> [I<ip>]

Show rules explicitly. If no IP specified, all entries are listed.

=item B<status>

Show status of shaping rules

=item B<sync>

Synchronize rules with database

=item B<version>

Output version

=back


=head1 OPTIONS

=over 8

=item B<-b>, B<--batch>

Batch mode. Sc will read commands and options from STDIN.

=item B<-j>, B<--joint>

Joint mode. Add, change and del commands will be applied to rules and database
entries simultaneously.

=item B<-d>, B<--debug> I<level>

Set debugging level (from 0 to 2)

=item B<-v>, B<--verbose>

Enable additional output during execution, turn off piping of tc(8) and
ipset(8) rules, generate and show manpage using C<help> command.

=item B<-S>, B<--syslog>

Send errors and warnings to syslog

=item B<-f>, B<--config> I<file>

Read configuration from specified file instead of F</etc/sc/sc.conf>

=item B<-o>, B<--out_if> I<if_name>

Name of output network interface

=item B<-i>, B<--in_if> I<if_name>

Name of input network interface

=item B<-N, --network> "I<net/mask> ..."

Network(s) for classid calculation or for C<ipmap> set (see sc.conf(5) for
details).

=item B<--filter_network> "I<net/mask> ..."

Network(s) for hashing filter generation (see sc.conf(5) for details).

=item B<-c>, B<--chain> I<name>

Name of iptables(8) chain to use

=item B<--set_name> I<name>

Name of IP set for storage of allowed IPs

=item B<--set_type> I<type>

Type of IP set (ipmap or iphash)

=item B<--set_size> I<size>

Size of IP set (up to 65536)

=item B<-q>, B<--quiet>

Suppress output of error messages

=item B<--quantum> I<size>

Size of quantum for child queues

=item B<-u>, B<--rate_unit> I<unit>

Default rate unit

=item B<-l>, B<--leaf_qdisc> I<string>

Leaf qdisc and parameters

=item B<--db_driver> I<name>

Database driver

=item B<--db_host> I<host:port>

Database server address or hostname

=item B<--db_name> I<name>

Database name to use

=item B<--db_user> I<name>

Database username

=item B<--db_pass> I<password>

Database password

=back


=head1 RATE UNITS

All rates should be specified as integer numbers, possibly followed by a unit.
Bare number means that you use the default unit, i.e. kibit.
You can set another default unit by changing C<rate_unit> parameter in
configuration file or by setting the similar command line option.

=over 18

=item bit

bit per second

=item kibit, Kibit

kibibit per second (1024)

=item kbit or Kbit

kilobit per second (1000)

=item mibit or Mibit

mebibit per second (1 048 576)

=item mbit or Mbit

megabit per second (10^6)

=item gibit or Gibit

gibibit per second (1 073 741 824)

=item gbit or Gbit

gigabit per second (10^9)

=item bps or Bps

byte per second

=item kibps or KiBps

kibibyte per second

=item kbps or KBps

kilobyte per second

=item mibps or MiBps

mebibyte per second

=item mbps or MBps

megabyte per second

=item gibps or GiBps

gibibyte per second

=item gbps or GBps

gigabyte per second

=back


=head1 USAGE

=over

=item Load accounts from database and create all rules

C<sc load>

=item Add class for IP 172.16.0.1 with 256kibit/s.

C<sc add 172.16.0.1 256kibit>

=item Change rate to 512kibit/s

C<sc change 172.16.0.1 512kibit>

=item Delete rules for 172.16.0.1

C<sc del 172.16.0.1>

=back


=head1 CONFIGURATION

By default B<sc> reads F</etc/sc/sc.conf> file and uses SQLite database
F</etc/sc/sc.db>. See sc.conf(5) for details.


=head1 BUGS

Return values are not always processed accurately and no checks are performed
before execution of any commands due to performance reasons.


=head1 RESTRICTIONS

Due to limited number of classids (from 2 to ffff) you can only shape 65534
different hosts on a single interface.
You can overcome this limitation with virtual interfaces (IFB or IMQ).

C<Flow> classifier works only with IPs that have different last two
octets.

For simplicity of filter hash table numbers calculation, the maximum number of
different entries in C<filter_network> is set to 255.

Script does not perform checks for existence of IP addresses, classes, filters
due to performance reasons.


=head1 SEE ALSO

sc.conf(5), tc(8), tc-htb(8), iptables(8), ipset(8),
L<http://lartc.org/howto/lartc.adv-filter.hashing.html>,
L<http://www.mail-archive.com/netdev@vger.kernel.org/msg60638.html>.


=head1 AUTHOR

Stanislav Kruchinin <stanislav.kruchinin@gmail.com>


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2008, 2009. Stanislav Kruchinin.

License: GPL v2 or later.


=head1 README

Administration tool for Linux-based ISP traffic shaper.


=pod OSNAMES

linux

=pod SCRIPT CATEGORIES

Networking
UNIX/System_administration

=cut

