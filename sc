#!/usr/bin/perl

use strict;
use warnings;
use Carp;
use Getopt::Long qw( GetOptionsFromArray );
use DBI;
use Pod::Usage;
use Sys::Syslog;
use AppConfig qw( :expand );
use Term::ANSIColor qw( :constants );
use POSIX qw( isatty );

##############################################################################
# Configurable parameters
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
my $colored = 1;
my $batch = 0;
my $joint = 0;

my $o_if = 'eth0';
my $i_if = 'eth1';

my $db_driver = 'sqlite';
my $db_host = '127.0.0.1';
my $db_user = 'username';
my $db_pass = 'password';
my $db_name = 'sc.db';

my $query_create = 'CREATE TABLE rates (ip INTEGER PRIMARY KEY, '.
                   'rate INTEGER NOT NULL)';
my $query_load = 'SELECT ip, rate FROM rates';
my $query_list = 'SELECT ip, rate FROM rates WHERE ip=?';
my $query_add = 'INSERT INTO rates VALUES (?, ?)';
my $query_del = 'DELETE FROM rates WHERE ip=?';
my $query_change = 'REPLACE INTO rates VALUES (?, ?)';

my $set_name = 'pass';
my $set_type = 'ipmap';
my $set_size = '65536';
my $chain_name = 'FORWARD';
my $policer_burst = '1500k';
my $quantum = '1500';
my $rate_unit = 'kibit';
my $leaf_qdisc = 'pfifo limit 50';
my $network = '172.16.0.0/16';
my $filter_network = $network;
my $filter_method = 'u32';
my $limit_method = 'shaping';

my (%filter_nets, %class_nets);

my $syslog = 0;
my $syslog_options = q{};
my $syslog_facility = 'user';

##############################################################################
# Internal variables and constants
#

my $PROG = 'sc';
my $VERSION = '1.2.0';
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
		'arg'     => '[ip]',
		'desc'    => 'calculate and print internally used values',
		'priv'    => 0,
	},
	'change|mod' => {
		'handler'   => \&cmd_change,
		'dbhandler' => \&cmd_change,
		'arg'       => '<ip> <rate>',
		'desc'      => 'change rate',
		'priv'      => 1,
	},
	'del|rm' => {
		'handler'   => \&cmd_del,
		'dbhandler' => \&cmd_dbdel,
		'arg'       => '<ip>',
		'desc'      => 'delete rules',
		'priv'      => 1,
	},
	'list|ls' => {
		'handler' => \&cmd_list,
		'arg'     => '[ip]',
		'desc'    => 'list current rules in human-readable form',
		'priv'    => 1,
	},
	'help' => {
		'handler' => \&cmd_help,
		'desc'    => 'show help and available database drivers',
		'priv'    => 0,
	},
	'init' => {
		'handler' => \&cmd_init,
		'desc'    => 'initialization of rules',
		'priv'    => 1,
	},
	'sync' => {
		'handler' => \&cmd_sync,
		'desc'    => 'synchronize rules with database',
		'priv'    => 1,
	},
	'load|start' => {
		'handler' => \&cmd_load,
		'desc'    => 'load information from database and create all rules',
		'priv'    => 1,
	},
	'ratecvt' => {
		'handler' => \&cmd_ratecvt,
		'arg'     => '<rate> <unit>',
		'desc'    => 'convert rate unit',
		'priv'    => 0,
	},
	'reload|restart' => {
		'handler' => \&cmd_reload,
		'desc'    => 'reset and load rules',
		'priv'    => 1,
	},
	'reset|stop' => {
		'handler' => \&cmd_reset,
		'desc'    => 'delete all shaping rules',
		'priv'    => 1,
	},
	'show' => {
		'handler' => \&cmd_show,
		'arg'     => '[ip]',
		'desc'    => 'show rules explicitly',
		'priv'    => 1,
	},
	'status' => {
		'handler' => \&cmd_status,
		'desc'    => 'show status of rules',
		'priv' => 1,
	},
	'version' => {
		'handler' => \&cmd_ver,
		'desc'    => 'output version and copyright information',
		'priv'    => 0,
	},
	'dbadd' => {
		'handler' => \&cmd_dbadd,
		'arg'     => '<ip> <rate>',
		'desc'    => 'add database entry',
		'priv'    => 0,
	},
	'dbdel|dbrm' => {
		'handler' => \&cmd_dbdel,
		'arg'     => '<ip>',
		'desc'    => 'delete database entry',
		'priv'    => 0,
	},
	'dblist|dbls' => {
		'handler' => \&cmd_dblist,
		'arg'     => '[ip]',
		'desc'    => 'list database entries',
		'priv'    => 0,
	},
	'dbchange|dbmod' => {
		'handler' => \&cmd_dbchange,
		'arg'     => '<ip> <rate>',
		'desc'    => 'change database entry',
		'priv'    => 0,
	},
	'dbcreate' => {
		'handler' => \&cmd_dbcreate,
		'desc'    => 'create database and table',
		'priv'    => 0,
	},
);

# pointer
my ($rul_init, $rul_add, $rul_del, $rul_change, $rul_load,
	$rul_batch_start, $rul_batch_stop, $rul_show, $rul_reset);

# rate unit transformation coefficients
my %units = (
# bit-based
	'bit'         => 1,
	'kibit|Kibit' => 2**10,
	'kbit|Kbit'   => 1_000,
	'mibit|Mibit' => 2**20,
	'mbit|Mbit'   => 10**6,
	'gibit|Gibit' => 2**30,
	'gbit|Gbit'   => 10**9,
# byte-based
	'bps|Bps'     => 8,
	'kibps|KiBps' => 2**13,
	'kbps|KBps'   => 8_000,
	'mibps|MiBps' => 2**23,
	'mbps|MBps'   => 8*10**6,
	'gibps|GiBps' => 2**33,
	'gbps|GBps'   => 8*10**9,
);

# Error codes
my $E_OK       = 0;
my $E_PARAM    = 1;
my $E_IP_COLL  = 2;
my $E_UNDEF    = 3;
my $E_EXIST    = 4;
my $E_NOTEXIST = 5;
my $E_CMD      = 6;
my $E_PRIV     = 7;

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
	'limit_method=s'    => \$limit_method,
	'd|debug=i'         => \$debug,
	'v|verbose!'        => \$verbose,
	'q|quiet!'          => \$quiet,
	'c|colored!'        => \$colored,
	'j|joint!'          => \$joint,
	'b|batch!'          => \$batch,
	'N|network=s'       => \$network,
	'filter_network=s'  => \$filter_network,
	'policer_burst=s'   => \$policer_burst,
	'quantum=s'         => \$quantum,
	'u|rate_unit=s'     => \$rate_unit,
	'leaf_qdisc=s'      => \$leaf_qdisc,
	'chain=s'           => \$chain_name,
	's|set_name=s'      => \$set_name,
	'set_type=s'        => \$set_type,
	'set_size=s'        => \$set_size,
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

# handlers and pointers for execution of external commands
my ($TC_H, $IPS_H);
my $TC = \&sys_tc;
my $IPS = \&sys_ips;
my $sys;

# pref values for different types of tc filters
my $pref_hash = 10; # hashing filters and flow
my $pref_leaf = 20; # hash table entries
my $pref_default = 30; # default rule
my $ip_re = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';

##############################################################################
# Main routine

# read configuration file
if (-T $cfg_file) {
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
		${ $optd{$args[$i]} } = $cfg->get( $cargs[$i] );
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

## end of main routine

# autocompletion for commands
sub acomp_cmd
{
	my ($input) = @_;
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
		log_warn("command \'$input\' is ambiguous:\n    @ambig");
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

	# process command line
	if ($batch) {
		GetOptionsFromArray(\@argv, %optd) or return $E_PARAM;
	}
	usage($E_CMD) if !defined $argv[0];
	my $cmd = acomp_cmd($argv[0]);
	usage($E_CMD) if !defined $cmd;
	return $E_CMD if $cmd eq q{};

	if ($cmdd{$cmd}{'priv'} && !$debug && $>) {
		log_warn('you must run this command with root privileges');
		return $E_PRIV;
	}

	# prepare all settings
	set_ptrs();
	set_class_nets();
	set_filter_nets();
	local $ENV{ANSI_COLORS_DISABLED} = 1 if !($colored && isatty(\*STDOUT));

	# call handler
	shift @argv;
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
				'database entry for specified IP does not exist. '.
				"Arguments: @argv"
			);
		}
		elsif ($ret == $E_EXIST) {
			log_carp(
				'database entry for specified IP already exists. '.
				"Arguments: @argv"
			);
		}
	}

	return $ret;
}

# system wrappers for different debug modes
sub sys_quiet
{
	my ($c) = @_;
	return system "$c >/dev/null 2>&1";
}

sub sys_debug_print
{
	my ($c) = @_;
	return print "$c\n";
}

sub sys_debug_on
{
	my ($c) = @_;
	print "$c\n" if system $c;
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
	elsif ($filter_method eq 'u32' && $limit_method eq 'shaping') {
		$rul_init = sub {
			rul_init_u32($o_if, 'src', 12);
			rul_init_u32($i_if, 'dst', 16);
		};
		$rul_add = \&rul_add_u32;
		$rul_del = \&rul_del_u32;
		$rul_change = \&rul_change_tc;
		$rul_batch_start = sub { batch_start_tc() if !$verbose; };
		$rul_batch_stop = sub { batch_stop_tc() if !$verbose; };
		$rul_load = \&rul_load_u32;
		$rul_show = \&rul_show_u32;
		$rul_reset = \&rul_reset_tc;
	}
	elsif ($filter_method eq 'u32' && $limit_method eq 'policing') {
		$rul_init = sub {
			rul_init_policer($o_if, 'dst', 16);
			rul_init_policer($i_if, 'src', 12);
		};
		$rul_add = \&rul_add_policer;
		$rul_del = \&rul_del_policer;
		$rul_change = \&rul_add_policer;
		$rul_batch_start = sub { batch_start_tc() if !$verbose; };
		$rul_batch_stop = sub { batch_stop_tc() if !$verbose; };
		$rul_load = \&rul_load_policer;
		$rul_show = \&rul_show_policer;
		$rul_reset = \&rul_reset_policer;
	}
	elsif ($limit_method eq 'policing' && $filter_method ne 'u32') {
		log_croak(
			'Policing can be used only when filter_method = u32'
		);
	}
	elsif ($limit_method ne 'policing' || $limit_method ne 'shaping') {
		log_croak(
			"\'$limit_method\' is invalid value for limit_method parameter"
		);
	}
	else {
		log_croak(
			"\'$filter_method\' is invalid value for filter_method parameter"
		);
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
	# Real minimal number of u32 hash tables is 1.  0x100 is taken for
	# simplicity.
	my $ht1 = 256;
	# Difference between initial numbers for hash tables of 1st and 2nd
	# nesting levels. Increase this value if you want to set more than 255
	# netmasks to filter_network parameter.
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
			if $ht2 > $ht_max;
	}
	return;
}

sub set_class_nets
{
	my $cid_min = 2;
	my $cid_max = 65_535;
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
			if $cid_i - $cid_min - 1 > $cid_max;
	}

	return;
}

sub nonempty
{
	my ($str) = @_;
	return (defined $str && $str ne q{});
}

sub is_ip
{
	my ($ip) = @_;

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
	my ($rate) = @_;
	chomp $rate;
	my $result = 0;
	my ($num, $unit);

	if (($num, $unit) = $rate =~ /^([0-9]+)([A-z]*)$/xms) {
		return 0 if $num == 0;
		if (nonempty($unit)) {
			foreach my $u (keys %units) {
				if ($unit =~ /^(?:$u)$/xms) {
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
	my ($ip) = @_;
	my $intip = ip_texttoint($ip);
	my $cid;

	foreach my $n (keys %class_nets) {
		if ($intip >= $class_nets{$n}{'intip_i'} &&
			$intip <= $class_nets{$n}{'intip_f'}) {
			my $offset = $intip & $class_nets{$n}{'invmask'};
			$cid = sprintf '%x', $class_nets{$n}{'classid_i'} + $offset;
			last;
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
	my ($ip) = @_;
	my $intip = ip_texttoint($ip);
	my ($leafht, $key);

	foreach my $n (keys %filter_nets) {
		if ($intip >= $filter_nets{$n}{'intip_i'} &&
			$intip <= $filter_nets{$n}{'intip_f'}) {
			# 3rd octet
			my $ht_offset = ($intip & $filter_nets{$n}{'invmask'}) >> 8;
			# 4th octet
			$key = sprintf '%x', $intip & 0xff;
			$leafht = sprintf '%x', $filter_nets{$n}{'leafht_i'} + $ht_offset;
			last;
		}
	}
	log_croak(
		"$ip does not belong to any of specified networks: $network"
	) if !defined $leafht;

	return ($leafht, $key);
}

# calculate divisor and hashkey mask
#
# netmask = mask in decimal form
# n = number of octet
sub div_hmask_u32
{
	my ($netmask, $n) = @_;

	log_croak("$n is invalid number of octet") if $n < 1 || $n > 4;
	# get n-th byte from netmask
	my $inthmask = (2**(32 - $netmask) - 1) & (0xff << 8*(4-$n));
	my $hmask = sprintf '0x%08x', $inthmask;
	my $div = ($inthmask >> 8*(4-$n)) + 1;

	return ($div, $hmask);
}

# convert IP from text to int form
sub ip_texttoint
{
	my ($ip) = @_;
	my @oct = split /\./ixms, $ip;
	my $int = 0;

	for my $i (0..3) {
		$int += $oct[$i] * (1 << 8*(3-$i));
	}

	return $int;
}

# convert IP from int to text form
sub ip_inttotext
{
	my ($int) = @_;
	my @oct;

	for my $i (0..3) {
		my $div = 1 << 8*(3-$i);
		$oct[$i] = int $int/$div;
		$int %= $div;
	}

	return join q{.}, @oct;
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
	my ($msg) = @_;

	log_syslog('warn', $msg) if $syslog;
	carp "$PROG: $msg" if !$quiet;
	return $!;
}

sub log_croak
{
	my ($msg) = @_;

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
	my ($msg) = @_;

	log_syslog('warn', $msg) if $syslog;
	print {*STDERR} "$PROG: $msg\n" if !$quiet;
	return $!;
}

sub db_connect
{
	my $dbh;

	if ($db_driver =~ /sqlite/ixms) {
		$dbh = DBI->connect(
			"DBI:SQLite:${db_name}",
			$db_user, $db_pass, { RaiseError => 1, AutoCommit => 1 }
		);
	}
	else {
		$dbh = DBI->connect(
			"DBI:${db_driver}:dbname=$db_name;host=$db_host",
			$db_user, $db_pass, { RaiseError => 1, AutoCommit => 1 }
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
		($intip, $rate) = @{$ref};
		if (!defined $rate) {
			log_carp("IP $ip has undefined rate, skipping\n");
			next;
		}
		$ip = ip_inttotext($intip);
		$cid = ip_classid($ip);
		$db_data{$cid}{'rate'} = $rate;
		$db_data{$cid}{'ip'} = $ip;
	}
	$sth->finish();
	undef $sth;
	$dbh->disconnect();

	return $dbh;
}

sub rul_add_flow
{
	my ($ip, $cid, $rate) = @_;
	my $ceil = $rate;

	$TC->(
		"class replace dev $o_if parent 1: classid 1:$cid ".
		"htb rate $rate ceil $ceil quantum $quantum"
	);
	$TC->(
		"class replace dev $i_if parent 1: classid 1:$cid ".
		"htb rate $rate ceil $ceil quantum $quantum"
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
		"class replace dev $o_if parent 1: classid 1:$cid ".
		"htb rate $rate ceil $ceil quantum $quantum"
	);
	$TC->(
		"qdisc replace dev $o_if parent 1:$cid handle $cid:0 $leaf_qdisc"
	);
	$TC->(
		"filter replace dev $o_if parent 1: pref $pref_leaf ".
		"handle $ht:$key u32 ht $ht:$key: match ip src $ip flowid 1:$cid"
	);

	$TC->(
		"class replace dev $i_if parent 1: classid 1:$cid ".
		"htb rate $rate ceil $ceil quantum $quantum"
	);
	$TC->(
		"qdisc replace dev $i_if parent 1:$cid handle $cid:0 $leaf_qdisc"
	);
	$TC->(
		"filter replace dev $i_if parent 1: pref $pref_leaf ".
		"handle $ht:$key u32 ht $ht:$key: match ip dst $ip flowid 1:$cid"
	);

	return $?;
}

sub rul_add_policer
{
	my ($ip, $cid, $rate) = @_;
	my ($ht, $key) = ip_leafht_key($ip);
	my $ceil = $rate;

	$TC->(
		"filter replace dev $o_if parent ffff: pref $pref_leaf ".
		"handle $ht:$key u32 ht $ht:$key: match ip dst $ip ".
		"police rate $rate burst $policer_burst drop flowid ffff:"
	);

	$TC->(
		"filter replace dev $i_if parent ffff: pref $pref_leaf ".
		"handle $ht:$key u32 ht $ht:$key: match ip src $ip ".
		"police rate $rate burst $policer_burst drop flowid ffff:"
	);

	return $?;
}

sub rul_del_flow
{
	my ($ip, $cid) = @_;

	$IPS->("-D $set_name $ip");

	$TC->("qdisc del dev $o_if parent 1:$cid handle $cid:0");
	$TC->("class del dev $o_if parent 1: classid 1:$cid");

	$TC->("qdisc del dev $i_if parent 1:$cid handle $cid:0");
	$TC->("class del dev $i_if parent 1: classid 1:$cid");

	return $?;
}

sub rul_del_u32
{
	my ($ip, $cid) = @_;
	my ($ht, $key) = ip_leafht_key($ip);

	$TC->(
		"filter del dev $o_if parent 1: pref $pref_hash ".
		"handle $ht:$key u32"
	);
	$TC->("qdisc del dev $o_if parent 1:$cid handle $cid:0");
	$TC->("class del dev $o_if parent 1: classid 1:$cid");

	$TC->(
		"filter del dev $i_if parent 1: pref $pref_hash ".
		"handle $ht:$key u32"
	);
	$TC->("qdisc del dev $i_if parent 1:$cid handle $cid:0");
	$TC->("class del dev $i_if parent 1: classid 1:$cid");

	return $?
}

sub rul_del_policer
{
	my ($ip, $cid) = @_;
	my ($ht, $key) = ip_leafht_key($ip);

	$TC->(
		"filter del dev $o_if parent ffff: pref $pref_hash ".
		"handle $ht:$key u32"
	);

	$TC->(
		"filter del dev $i_if parent ffff: pref $pref_hash ".
		"handle $ht:$key u32"
	);

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
	my $ret = $E_OK;

	open my $IPH, '-|', "$ipset -nsL $set_name" or
		log_croak("unable to open pipe for $ipset");
	my @ipsout = <$IPH>;
	close $IPH or log_carp("unable to close pipe for $ipset");
	foreach (@ipsout) {
		next unless /^$ip_re/xms;
		chomp;
		$ip = $_;
		$cid = ip_classid($ip);
		if (defined $rul_data{$cid}{'ip'}) {
			log_carp('IP-to-classid collision detected, skipping. OLD: '.
				$rul_data{$cid}{'ip'}.", NEW: $ip");
			$ret = $E_IP_COLL;
			next;
		}
		$rul_data{$cid}{'ip'} = $ip;
	}

	open my $TCCH, '-|', "$tc class show dev $i_if"
		or log_croak("unable to open pipe for $tc");
	my @tcout = <$TCCH>;
	close $TCCH or log_carp("unable to close pipe for $tc");
	foreach (@tcout) {
		if (($cid, $rate) = /leaf\ ([0-9a-f]+):\ .*\ rate\ (\w+)/xms) {
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
	my $ret = $E_OK;

	open my $TCFH, '-|', "$tc -p filter show dev $i_if"
		or log_croak("unable to open pipe for $tc");
	my @tcout = <$TCFH>;
	close $TCFH or log_carp("unable to close pipe for $tc");
	for my $i (0 .. $#tcout) {
		chomp $tcout[$i];
		if (($ip) = $tcout[$i] =~ /match\ IP\ .*\ ($ip_re)\/32/xms) {
			if (($cid) = $tcout[$i-1] =~ /flowid\ 1:([0-9a-f]+)/xms) {
				$rul_data{$cid}{'ip'} = $ip;
			}
		}
	}

	open my $TCCH, '-|', "$tc class show dev $i_if"
		or log_croak("unable to open pipe for $tc");
	@tcout = <$TCCH>;
	close $TCCH or log_carp("unable to close pipe for $tc");
	foreach (@tcout) {
		if (($cid, $rate) = /leaf\ ([0-9a-f]+):\ .*\ rate\ (\w+)/xms) {
			next if !defined $rul_data{$cid};
			$rate = rate_cvt($rate, $rate_unit);
			$rul_data{$cid}{'rate'} = $rate;
		}
	}

	return $ret;
}

sub rul_load_policer
{
	my ($ip, $cid, $rate);
	my $ret = $E_OK;

	open my $TCFH, '-|', "$tc -p -iec filter show dev $i_if parent ffff:"
		or log_croak("unable to open pipe for $tc");
	my @tcout = <$TCFH>;
	close $TCFH or log_carp("unable to close pipe for $tc");
	for my $i (0 .. $#tcout) {
		chomp $tcout[$i];
		if (($ip) = $tcout[$i] =~ /match\ IP\ .*\ ($ip_re)\/32/xms) {
			$cid = ip_classid($ip);
			if (($rate) = $tcout[$i+1] =~ /rate\ ([0-9A-z]+)/xms) {
				$rate = rate_cvt($rate, $rate_unit);
				$rul_data{$cid}{'ip'} = $ip;
				$rul_data{$cid}{'rate'} = $rate;
			}
		}
	}

	open my $TCCH, '-|', "$tc class show dev $i_if"
		or log_croak("unable to open pipe for $tc");
	@tcout = <$TCCH>;
	close $TCCH or log_carp("unable to close pipe for $tc");
	foreach (@tcout) {
		if (($cid, $rate) = /leaf\ ([0-9a-f]+):\ .*\ rate\ (\w+)/xms) {
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
		"filter add dev $o_if parent 1:0 protocol ip pref $pref_hash ".
		"handle 1 flow map key src and 0xffff"
	);

	$TC->("qdisc add dev $i_if root handle 1: htb");
	$TC->(
		"filter add dev $i_if parent 1:0 protocol ip pref $pref_hash ".
		"handle 1 flow map key dst and 0xffff"
	);

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

	$TC->("qdisc add dev $dev root handle 1: htb");
	$TC->("filter add dev $dev parent 1:0 protocol ip pref $pref_hash u32");
	foreach my $net (sort {$filter_nets{$a}{'ht'} <=> $filter_nets{$b}{'ht'}}
	  keys %filter_nets) {
		my $ht1 = sprintf '%x', $filter_nets{$net}{'ht'};
		my $netmask = $filter_nets{$net}{'mask'};

		if ($netmask >= 24 && $netmask < 31) {
			my ($div1, $hmask1) = div_hmask_u32($netmask, 4);
			$TC->(
				"filter add dev $dev parent 1:0 protocol ip pref $pref_hash ".
				"handle $ht1: u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent 1:0 protocol ip pref $pref_hash ".
				"u32 ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);
		}
		elsif ($netmask >= 16 && $netmask < 24) {
			my @oct = split /\./ixms, $filter_nets{$net}{'ip'};
			my ($div1, $hmask1) = div_hmask_u32($netmask, 3);

			# parent filter
			$TC->(
				"filter add dev $dev parent 1:0 protocol ip pref $pref_hash ".
				"handle $ht1: u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent 1:0 protocol ip pref $pref_hash ".
				"u32 ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);

			# child filters
			my ($div2, $hmask2) = div_hmask_u32($netmask, 4);
			for my $i (0 .. $div1 - 1) {
				my $key = sprintf '%x', $i;
				my $ht2 = sprintf '%x', $filter_nets{$net}{'leafht_i'} + $i;
				my $j = $oct[2] + $i;
				my $net2 = "$oct[0].$oct[1].$j.0/24";

				$TC->(
					"filter add dev $dev parent 1:0 protocol ip ".
					"pref $pref_hash handle $ht2: u32 divisor $div2"
				);
				$TC->(
					"filter add dev $dev parent 1:0 protocol ip ".
					"pref $pref_hash u32 ht $ht1:$key: ".
					"match ip $match $net2 ".
					"hashkey mask $hmask2 at $offset link $ht2:"
				);
			}
		}
		else {
			log_croak("network mask \'\/$netmask\' is not supported");
		}
	}

	# block all other traffic
	$TC->(
		"filter add dev $dev parent 1:0 protocol ip pref $pref_default ".
		'u32 match u32 0x0 0x0 at 0 police mtu 1 action drop'
	);

	return $?;
}

sub rul_init_policer
{
	my ($dev, $match, $offset) = @_;

	$TC->("qdisc add dev $dev handle ffff: ingress");
	$TC->("filter add dev $dev parent ffff: protocol ip pref $pref_hash u32");
	foreach my $net (sort {$filter_nets{$a}{'ht'} <=> $filter_nets{$b}{'ht'}}
	  keys %filter_nets) {
		my $ht1 = sprintf '%x', $filter_nets{$net}{'ht'};
		my $netmask = $filter_nets{$net}{'mask'};

		if ($netmask >= 24 && $netmask < 31) {
			my ($div1, $hmask1) = div_hmask_u32($netmask, 4);
			$TC->(
				"filter add dev $dev parent ffff: protocol ip ".
				"pref $pref_hash handle $ht1: u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent ffff: protocol ip ".
				"pref $pref_hash u32 ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);
		}
		elsif ($netmask >= 16 && $netmask < 24) {
			my @oct = split /\./ixms, $filter_nets{$net}{'ip'};
			my ($div1, $hmask1) = div_hmask_u32($netmask, 3);

			# parent filter
			$TC->(
				"filter add dev $dev parent ffff: protocol ip ".
				"pref $pref_hash handle $ht1: u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent ffff: protocol ip ".
				"pref $pref_hash u32 ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);

			# child filters
			my ($div2, $hmask2) = div_hmask_u32($netmask, 4);
			for my $i (0 .. $div1 - 1) {
				my $key = sprintf '%x', $i;
				my $ht2 = sprintf '%x', $filter_nets{$net}{'leafht_i'} + $i;
				my $j = $oct[2] + $i;
				my $net2 = "$oct[0].$oct[1].$j.0/24";

				$TC->(
					"filter add dev $dev parent ffff: protocol ip ".
					"pref $pref_hash handle $ht2: u32 divisor $div2"
				);
				$TC->(
					"filter add dev $dev parent ffff: protocol ip ".
					"pref $pref_hash u32 ht $ht1:$key: ".
					"match ip $match $net2 ".
					"hashkey mask $hmask2 at $offset link $ht2:"
				);
			}
		}
		else {
			log_croak("network mask \'\/$netmask\' is not supported");
		}
	}

	# block all other traffic
	$TC->(
		"filter add dev $dev parent ffff:0 protocol ip pref $pref_default ".
		'u32 match u32 0x0 0x0 at 0 police mtu 1 action drop'
	);

	return $?;
}

sub rul_show_flow
{
	my @ips = @_;

	if (nonempty($ips[0])) {
		foreach my $ip (@ips) {
			my $cid = ip_classid($ip);
			print_rules(
				"TC rules for $ip\n\nInput class [$i_if]:",
				"$tc -i -s -d class show dev $i_if | ".
				"grep -F -w -A 3 \"leaf $cid\:\""
			);
			print_rules(
				"\nOutput class [$o_if]:",
				"$tc -i -s -d class show dev $o_if | ".
				"grep -F -w -A 3 \"leaf $cid\:\""
			);
			print_rules(
				"\nInput qdisc [$i_if]:",
				"$tc -i -s -d qdisc show dev $i_if | ".
				"grep -F -w -A 2 \"$cid\: parent 1:$cid\""
			);
			print_rules(
				"\nOutput qdisc [$o_if]:",
				"$tc -i -s -d qdisc show dev $o_if | ".
				"grep -F -w -A 2 \"$cid\: parent 1:$cid\""
			);
			print_rules("\nIPSet entry for $ip:", "$ipset -T $set_name $ip");
			print "\n";
		}
	}
	else {
		print BOLD, "FILTERS:\n", RESET;
		system "$tc -p -s filter show dev $i_if";
		system "$tc -p -s filter show dev $o_if";
		print BOLD, "\nCLASSES:\n", RESET;
		system "$tc -i -s -d class show dev $i_if";
		system "$tc -i -s -d class show dev $o_if";
		print BOLD, "\nQDISCS:\n", RESET;
		system "$tc -i -s -d qdisc show dev $i_if";
		system "$tc -i -s -d qdisc show dev $o_if";
		print BOLD, "\nIPTABLES RULES:\n", RESET;
		system "$iptables -nL";
	}
	return $?;
}

sub rul_show_u32
{
	my @ips = @_;

	if (nonempty($ips[0])) {
		foreach my $ip (@ips) {
			arg_check(\&is_ip, $ip, 'IP');
			my $cid;

			open my $TCFH, '-|', "$tc -p -s filter show dev $i_if"
				or log_croak("unable to open pipe for $tc");
			my @tcout = <$TCFH>;
			close $TCFH or log_carp("unable to close pipe for $tc");
			for my $i (0 .. $#tcout) {
				chomp $tcout[$i];
				if ($tcout[$i] =~ /match\ IP\ .*\ $ip\/32/xms) {
					if (($cid) = $tcout[$i-1] =~ /flowid\ 1:([0-9a-f]+)/xms) {
						print BOLD, "Input filter [$i_if]:\n", RESET;
						print "$tcout[$i-1]\n$tcout[$i]\n";
						print_rules(
							"\nOutput filter [$o_if]:",
							"$tc -p -s filter show dev $o_if | ".
							"grep -F -w -B 1 \"match IP src $ip/32\""
						);
						# tc class
						print_rules(
							"\nInput class [$i_if]:",
							"$tc -i -s -d class show dev $i_if | ".
							"grep -F -w -A 3 \"leaf $cid\:\""
						);
						print_rules(
							"\nOutput class [$o_if]:",
							"$tc -i -s -d class show dev $o_if | ".
							"grep -F -w -A 3 \"leaf $cid\:\""
						);
						# tc qdisc
						print_rules(
							"\nInput qdisc [$i_if]:",
							"$tc -i -s -d qdisc show dev $i_if | ".
							"grep -F -w -A 2 \"$cid\: parent 1:$cid\""
						);
						print_rules(
							"\nOutput qdisc [$o_if]:",
							"$tc -i -s -d qdisc show dev $o_if | ".
							"grep -F -w -A 2 \"$cid\: parent 1:$cid\""
						);
						print "\n";
						last;
					}
				}
			}
		}
	}
	else {
		print BOLD, "FILTERS:\n", RESET;
		system "$tc -p -s filter show dev $i_if";
		system "$tc -p -s filter show dev $o_if";
		print BOLD, "\nCLASSES:\n", RESET;
		system "$tc -i -s -d class show dev $i_if";
		system "$tc -i -s -d class show dev $o_if";
		print BOLD, "\nQDISCS:\n", RESET;
		system "$tc -i -s -d qdisc show dev $i_if";
		system "$tc -i -s -d qdisc show dev $o_if";
		return $?;
	}
	return $?;
}

sub rul_show_policer
{
	my @ips = @_;

	if (nonempty($ips[0])) {
		foreach my $ip (@ips) {
			arg_check(\&is_ip, $ip, 'IP');
			my $cid;
			my @tcout;

			open my $TCFH, '-|',
				"$tc -p -s -iec filter show dev $i_if parent ffff:"
				or log_croak("unable to open pipe for $tc");
			@tcout = <$TCFH>;
			close $TCFH or log_carp("unable to close pipe for $tc");
			for my $i (0 .. $#tcout) {
				chomp $tcout[$i];
				if ($tcout[$i] =~ /match\ IP\ .*\ $ip\/32/xms) {
					print BOLD, "Input filter [$i_if]:\n", RESET;
					for my $j ($i-1 .. $i+1) {
						print "$tcout[$j]\n";
					}
					last;
				}
			}
			open $TCFH, '-|',
				"$tc -p -s -iec filter show dev $o_if parent ffff:"
				or log_croak("unable to open pipe for $tc");
			@tcout = <$TCFH>;
			close $TCFH or log_carp("unable to close pipe for $tc");
			for my $i (0 .. $#tcout) {
				chomp $tcout[$i];
				if ($tcout[$i] =~ /match\ IP\ .*\ $ip\/32/xms) {
					print BOLD, "Output filter [$o_if]:\n", RESET;
					for my $j ($i-1 .. $i+1) {
						print "$tcout[$j]\n";
					}
					last;
				}
			}
		}
	}
	else {
		print BOLD, "POLICYING FILTERS [$i_if]:\n", RESET;
		system "$tc -p -s filter show dev $i_if parent ffff:";
		print BOLD, "POLICYING FILTERS [$o_if]:\n", RESET;
		system "$tc -p -s filter show dev $o_if parent ffff:";
		return $?;
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
		$sys->(
			"$iptables -D $chain_name -p all -m set --set $set_name src ".
			"-j ACCEPT"
		);
		$sys->(
			"$iptables -D $chain_name -p all -m set --set $set_name dst ".
			"-j ACCEPT"
		);
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

sub rul_reset_policer
{
	$sys->("$tc qdisc del dev $o_if handle ffff: ingress");
	$sys->("$tc qdisc del dev $i_if handle ffff: ingress");
	return $?;
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
		print BOLD, "$comment\n", RESET if nonempty($comment);
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
		print q{ } x $colspace[0], $lengths{$key}{'cmd'},
		      q{ } x ($maxcmdlen - $lengths{$key}{'cmdl'} + $colspace[1]);
		print $cmdd{$key}{'arg'} if defined $cmdd{$key}{'arg'};
		print q{ } x ($maxarglen - $lengths{$key}{'argl'} + $colspace[2]),
		      $cmdd{$key}{'desc'}, "\n";
	}
	return;
}

sub round
{
	my ($n) = @_;
	return int($n + .5*($n <=> 0));
}

sub rate_cvt
{
	my ($rate, $dst_unit) = @_;
	my ($num, $unit, $s_key, $d_key);

	if (($num) = $rate =~ /^([0-9]+)([A-z]*)$/xms) {
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
		log_croak('invalid rate specified');
	}
	log_croak('invalid source unit specified') if !defined $s_key;

	foreach my $u (keys %units) {
		if ($dst_unit =~ /^($u)$/xms) {
			$d_key = $u;
			last;
		}
	}
	log_croak('invalid destination unit specified') if !defined $d_key;
	my $dnum = round($num * $units{$s_key} / $units{$d_key});
	return "$dnum$dst_unit";
}

sub usage
{
	my ($ret) = @_;
	print $usage_preamble;
	print_cmds();
	print "\n";
	exit $ret;
}

sub sys_tc
{
	my ($c) = @_;
	return $sys->("$tc $c");
}

sub batch_tc
{
	my ($c) = @_;
	return print {$TC_H} "$c\n";
}

sub batch_start_tc
{
	if ($debug == $DEBUG_PRINT) {
		open $TC_H, '>', 'tc.batch'
			or log_croak('unable to open tc.batch');
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
	my ($c) = @_;
	return $sys->("$ipset $c");
}

sub batch_ips
{
	my ($c) = @_;
	return print {$IPS_H} "$c\n";
}

sub batch_start_ips
{
	if ($debug == $DEBUG_PRINT) {
		open $IPS_H, '>', 'ipset.batch'
			or log_croak('unable to open ipset.batch');
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

	arg_check(\&is_ip, $ip, 'IP');
	$rate = arg_check(\&is_rate, $rate, 'rate');
	my $cid = ip_classid($ip);
	return $rul_add->($ip, $cid, $rate);
}

sub cmd_del
{
	my ($ip) = @_;

	arg_check(\&is_ip, $ip, 'IP');
	my $cid = ip_classid($ip);
	return $rul_del->($ip, $cid);
}

sub cmd_change
{
	my ($ip, $rate) = @_;

	arg_check(\&is_ip, $ip, 'IP');
	$rate = arg_check(\&is_rate, $rate, 'rate');
	my $cid = ip_classid($ip);
	return $rul_change->($ip, $cid, $rate);
}

sub cmd_list
{
	my @ips = @_;
	my $ret = $rul_load->();
	my $fmt = "%4s  %-15s %11s\n";

	if (nonempty($ips[0])) {
		foreach my $ip (@ips) {
			arg_check(\&is_ip, $ip, 'IP');
			my $cid = ip_classid($ip);
			if (defined $rul_data{$cid}) {
				printf $fmt, $cid, $rul_data{$cid}{'ip'},
					$rul_data{$cid}{'rate'};
			}
		}
	}
	else {
		foreach my $cid (sort { hex $a <=> hex $b } keys %rul_data) {
			printf $fmt, $cid, $rul_data{$cid}{'ip'}, $rul_data{$cid}{'rate'};
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
	my $PIPE;
	open $PIPE, '-|', "$tc qdisc show dev $o_if"
		or log_croak("unable to open pipe for $tc");
	@out = <$PIPE>;
	close $PIPE or log_croak("unable to close pipe for $tc");

	my $rqdisc;
	if ($out[0] =~ /^qdisc\ htb/xms) {
		$rqdisc = 'htb';
	}
	elsif (defined $out[1]) {
		if ($out[1] =~ /^qdisc\ ingress/xms) {
			$rqdisc = 'ingress';
		}
	}
	else {
		log_warn('no shaping rules found');
		return $E_UNDEF;
	}

	if ($rqdisc eq 'htb') {
		my @lqd = split /\ /xms, $leaf_qdisc;
		my $lqdisk = $lqd[0];
		shift @out;
		foreach my $s (@out) {
			chomp $s;
			if ($s =~ /qdisc\ $lqdisk\ ([0-9a-f]+):/xms) {
				log_warn('shaping rules were successfully created');
				return $E_OK;
			}
		}
		log_warn('htb qdisc found but there is no child queues');
	}
	elsif ($rqdisc eq 'ingress') {
		open $PIPE, '-|', "$tc -p filter show dev $o_if parent ffff:"
			or log_croak("unable to open pipe for $tc");
		@out = <$PIPE>;
		close $PIPE or log_croak("unable to close pipe for $tc");
		foreach my $s (@out) {
			if ($s =~ /match\ IP.*\/32/xms) {
				log_warn('shaping rules were successfully created');
				return $E_OK;
			}
		}
		log_warn('ingress qdisc found but there is no filters for IPs');
		return $E_UNDEF;
	}
	return $E_UNDEF;
}

sub cmd_ver
{
	print "$VERSTR\n\n";

	pod2usage({ -exitstatus => 'NOEXIT', -verbose => 99,
		-sections => 'LICENSE AND COPYRIGHT' });
	return $E_OK;
}

sub cmd_help
{
	if ($verbose) {
		pod2usage({ -exitstatus => 0, -verbose => 2 });
	}
	else {
		my $linewidth = 80;
		my $indent = "\ \ \ \ ";

		print "$VERSTR\n\n";
		pod2usage({ -exitstatus => 'NOEXIT', -verbose => 99,
			-sections => 'SYNOPSIS|COMMANDS|OPTIONS', -output => \*STDOUT });
		print "Available database drivers:\n";
		my $drv = join q{ }, DBI->available_drivers;
		$drv =~ s/([^\n]{1,$linewidth})(?:\b\s*|\n)/$indent$1\n/goixms;
		print "$drv\n";
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

	arg_check(\&is_ip, $ip, 'IP');
	my $dbh = db_connect();
	my $intip = ip_texttoint($ip);
	my $intrate = rate_cvt($rate, $rate_unit);
	$intrate =~ s/\D//gixms;
	my $sth = $dbh->prepare($query_add);
	$sth->execute($intip, $intrate);
	$sth->finish();
	undef $sth;
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
	undef $sth;
	$dbh->disconnect();
	return $E_OK;
}

sub cmd_dbchange
{
	my ($ip, $rate) = @_;

	my $dbh = db_connect();
	my $intip = ip_texttoint($ip);
	my $intrate = rate_cvt($rate, $rate_unit);
	$intrate =~ s/\D//gixms;
	my $sth = $dbh->prepare($query_change);
	$sth->execute($intip, $intrate);
	$sth->finish();
	undef $sth;
	$dbh->disconnect();
	return $E_OK;
}

sub cmd_dblist
{
	my ($ip) = @_;
	my $ret = $E_OK;

	if (!defined $ip) {
		$ret = db_load();
		foreach my $cid (sort { hex $a <=> hex $b } keys %db_data) {
			printf "%-15s  %10s\n", $db_data{$cid}{'ip'},
				"$db_data{$cid}{'rate'}$rate_unit";
		}
	}
	else {
		arg_check(\&is_ip, $ip, 'IP');
		my $intip = ip_texttoint($ip);
		my $rate;
		my $dbh = db_connect();
		my $sth = $dbh->prepare($query_list);
		$sth->execute($intip);
		while (my $ref = $sth->fetchrow_arrayref()) {
			($intip, $rate) = @{$ref};
			printf "%-15s  %10s\n", $ip, $rate . $rate_unit;
		}
		$sth->finish();
		undef $sth;
		$dbh->disconnect();
	}
	return $E_OK;
}

sub cmd_ratecvt
{
	my ($rate, $unit) = @_;

	log_croak('rate is undefined') if !defined $rate;
	log_croak('destination unit is undefined') if !defined $unit;
	my $result;
	$result = rate_cvt($rate, $unit);
	print "$result\n";
	return $E_OK;
}

sub cmd_calc
{
	my ($ip) = @_;

	if (!defined $ip) {
		use Data::Dumper;
		print Dumper(\%filter_nets);
		print Dumper(\%class_nets);
		return $E_OK;
	}
	arg_check(\&is_ip, $ip, 'IP');
	my $cid = ip_classid($ip);
	my ($ht, $key) = ip_leafht_key($ip);
	print "classid = $cid, leaf ht = $ht, key = $key\n";
	return $E_OK;
}


__END__

=head1 NAME

B<sc> - administration tool for ISP traffic shaper

=head1 SYNOPSIS

B<sc> [options] B<command> [ip] [rate]

=head1 DESCRIPTION

B<sc> is a command-line tool intended to simplify administration of traffic
shaper for Internet service providers. ISP's usually work with the following
configuration: every customer has it's own IP-address and fixed bandwidth.
B<sc> works like a wrapper for tc(8), iptables(8) and ipset(8) abstracting you
from complexity of their rules, so you can think only about IPs and bandwidth
rates and almost forget about classid's, qdiscs, filters and other stuff.

=head2 Main features

=over

=item * Fast loading of large rulesets by using batch modes of tc(8) and
ipset(8).

=item * Effective classification with u32 hashing filters or flow classifier.

=item * Loading of IPs and rates from any relational database supported by
Perl DBI module.

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

=item * B<u32> classifier (option B<CONFIG_NET_CLS_U32>=m or y)

=item * Traffic control actions (B<CONFIG_NET_CLS_ACT>=y and
B<CONFIG_NET_ACT_GACT>=m or y)

=back


=head1 COREQUISITES

If you want to use B<flow> filtering method, you should install iptables(8)
and ipset(8), B<flow> classifier (kernel version 2.6.25 or above, option
B<CONFIG_NET_CLS_FLOW>=m or y), and B<ipset> kernel modules (see
L<http://ipset.netfilter.org/> for details).

If you prefer policing rather than shaping, you should enable the kernel
option B<CONFIG_NET_ACT_POLICE>.


=head1 COMMANDS

=over 30

=item B<add> <ip> <rate>

Add rules for specified IP

=item B<calc> [ip]

Calculate and print internally used variables: classids, hash table numbers
and keys.

=item B<change> | B<mod> <ip> <rate>

Change rate for specified IP

=item B<dbadd> <ip> <rate>

Add database entry

=item B<dbchange> | B<dbmod> <ip> <rate>

Change database entry

=item B<dbcreate>

Create database and table

=item B<dbdel> | B<dbrm> <ip>

Delete database entry

=item B<dblist> | B<dbls> [ip]

List database entries. If no IP specified, all entries are listed.

=item B<del> | B<rm> <ip>

Delete rules

=item B<help>

Show help for commands, options and list available database drivers. Generate
and show manpage if B<-v> option is specified.

=item B<init>

Initialization of firewall and QoS rules. Should be used only for manual rule
editing.

=item B<list> | B<ls> [ip]

List rules in a short and human-readable form. If no IP specified, all entries
are listed.

=item B<load> | B<start>

Load IPs and rates from database and create ruleset

=item B<ratecvt> <rate> <unit>

Convert rate from one unit to another

=item B<reload> | B<restart>

Reset rules and load database

=item B<reset> | B<stop>

Delete all shaping rules

=item B<show> [ip]

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

=item B<-f>, B<--config> file

Read configuration from specified file

=item B<-o>, B<--out_if> if_name

Name of output network interface

=item B<-i>, B<--in_if> if_name

Name of input network interface

=item B<-d>, B<--debug> mode

Possible values:

=over

=item B<0>

no debug (default value),

=item B<1>

print command lines with nonzero return values,

=item B<2>

print all command lines without execution.

=back

=item B<-v>, B<--verbose>

Enable additional output during execution, turn off usage of tc(8) and
ipset(8) batch modes, generate and show manpage using C<help> command.

=item B<-q>, B<--quiet>

Suppress output of error messages

=item B<-c>, B<--colored>

Colorize output of some commands

=item B<-j>, B<--joint>

Joint mode. Add, change and del commands will be applied to rules and database
entries simultaneously.

=item B<-b>, B<--batch>

Batch mode. Commands and options will be read from STDIN.

=item B<-N, --network> "net/mask ..."

Network(s) for classid calculation or for C<ipmap> set (see sc.conf(5) for
details).

=item B<--filter_network> "net/mask ..."

Network(s) for hashing filter generation (see sc.conf(5) for details).

=item B<--policer_burst> size

Amount of bytes to buffer for every filter with policing rules.

=item B<--quantum> size

Amount of bytes a stream is allowed to dequeue before the next queue gets a
turn.

=item B<-u>, B<--rate_unit> unit

Default rate unit

=item B<-l>, B<--leaf_qdisc> string

Leaf qdisc and parameters

=item B<-c>, B<--chain> name

Name of iptables(8) chain to use

=item B<-s>, B<--set_name> name

Name of IP set for storage of allowed IPs

=item B<--set_type> type

Type of IP set (ipmap or iphash)

=item B<--set_size> size

Size of IP set (up to 65536)

=item B<--db_driver> name

Database driver

=item B<--db_host> host:port

Database server address or hostname

=item B<--db_name> name

Database name to use

=item B<--db_user> name

Database username

=item B<--db_pass> password

Database password. Remember that it is insecure to specify password here.

=item B<-S>, B<--syslog>

Send errors and warnings to syslog

=back


=head1 RATE UNITS

All rates should be specified as integer numbers, possibly followed by a unit.
Bare number implies default unit (kibit).
You may use another unit by changing C<rate_unit> parameter in configuration
file or by setting the similar command line option.

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

C<sc load> or C<sc start>

=item Add class for IP 172.16.0.1 with 256kibit/s.

C<sc add 172.16.0.1 256kibit>

=item Change rate to 512kibit/s

C<sc change 172.16.0.1 512kibit>

=item Delete rules for 172.16.0.1

C<sc del 172.16.0.1>

=item Reset all rules

C<sc reset>

=back


=head1 CONFIGURATION

By default B<sc> reads configuration from F</etc/sc/sc.conf> file and uses
SQLite database at F</etc/sc/sc.db>.
See sc.conf(5) for details.

=head1 DIAGNOSTICS

The error messages are printed to standard error.
To print the command lines that return nonzero error codes, use B<-d 1>
option.
To print all command lines without execution, use B<-d 2>.
To disable usage of batch modes of tc(8) and ipset(8), use B<-v> key.

Program may return one of the following exit codes or the exit code of the
failed command line that aborted the execution:

=over 4

=item B<0>

correct functioning

=item B<1>

incorrect parameter

=item B<2>

IP-to-classid collision

=item B<3>

parameter is undefined

=item B<4>

IP already exists

=item B<5>

IP does not exist

=item B<6>

incorrect command

=item B<7>

insufficient privileges

=back


=head1 BUGS

For performance reasons, script does not perform checks that require
additional executions of external programs.


=head1 RESTRICTIONS

Due to limited number of classids (from 2 to ffff) you can create only 65534
classes on a single interface.
For similar reasons sc(8) only supports networks with masks from /16 to /31.
u32 classifier allows you to create several hashing filters for /16-/31
networks, but flow classifier works only with single /16 network.
IPs from the different /16 networks with the same last two octets will be
assigned to the same class.

For simplicity of u32 hash table numbers calculation, the maximum number of
entries in C<filter_network> parameter is 255, and the number of hashing
filters is limited by 0x799.


=head1 SEE ALSO

sc.conf(5), tc(8), tc-htb(8), iptables(8), ipset(8), Getopt::Long(3),
AppConfig(3),
http://lartc.org/howto/lartc.adv-filter.hashing.html,
http://www.mail-archive.com/netdev@vger.kernel.org/msg60638.html.


=head1 AUTHOR

Stanislav Kruchinin <stanislav.kruchinin@gmail.com>


=head1 LICENSE AND COPYRIGHT

Copyright (c) 2008-2010. Stanislav Kruchinin.

License: GNU GPL version 2 or later

This is free software: you are free to change and redistribute it.
There is NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

=cut

