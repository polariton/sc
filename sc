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
use Socket;
require 'sys/ioctl.ph';

#
# Configurable parameters
#

my $cfg_file = '/etc/sc/sc.conf';
my $tc = '/sbin/tc';

use constant {
	DEBUG_OFF   => 0, # no debug output
	DEBUG_ON    => 1, # print command line that caused error
	DEBUG_PRINT => 2, # print all commands instead of executing them
};
my $debug = DEBUG_OFF;

use constant {
	VERB_OFF => 0,     # no verbose messages
	VERB_ON => 1,      # enable messages
	VERB_NOBATCH => 2, # disable batch mode of tc
};
my $verbose = VERB_OFF;

my $quiet = 0;
my $colored = 1;
my $batch = 0;
my $joint = 0;

my $o_if = 'eth0';
my $i_if = 'eth1';
my $o_if_enabled = 1;
my $i_if_enabled = 1;
my $if_disabled_keyword = 'disable';

my $db_driver = 'sqlite';
my $db_host = '127.0.0.1';
my $db_user = 'username';
my $db_pass = 'password';
my $db_name = 'sc.db';

my $query_create = 'CREATE TABLE rates (ip UNSIGNED INTEGER PRIMARY KEY, '.
                   'rate UNSIGNED INTEGER NOT NULL)';
my $query_load = 'SELECT ip, rate FROM rates';
my $query_list = 'SELECT ip, rate FROM rates WHERE ip=?';
my $query_add = 'INSERT INTO rates VALUES (?, ?)';
my $query_del = 'DELETE FROM rates WHERE ip=?';
my $query_change = 'REPLACE INTO rates VALUES (?, ?)';

my $policer_burst_ratio = 0.2;
my $quantum = '1500';
my $rate_unit = 'kibit';
my $rate_ratio = 1.0;
my $default_cid = 'fffe';
my $ingress_cid = 'ffff';
my $root_qdisc = 'htb';
my $leaf_qdisc = 'pfifo limit 100';
my $network = '10.0.0.0/16';
my $filter_network = $network;
my $default_policy = 'block';
my $default_rate = '1gibit';
my $default_ceil = '1gibit';
my $bypass_int = q{};
my $bypass_ext = q{};
my $limit_method = 'shaping';
my $classid = q{};

my (%filter_nets, %class_nets);

my $syslog_enable = 0;
my $syslog_options = q{};
my $syslog_facility = 'user';

#
# Internal variables and constants
#

my $PROG = 'sc';
our $VERSION = '1.5.8';
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
		'arg'     => '[ip] ...',
		'desc'    => 'list current rules',
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
		'desc'    => 'convert rate to specified units',
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
		'arg'     => '[ip] ...',
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
	'dbcreate' => {
		'handler' => \&cmd_dbcreate,
		'desc'    => 'create database and table',
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
		'desc'    => 'change rate in the database',
		'priv'    => 0,
	},
);

# pointers to functions for rule handling
my ($rul_batch_start, $rul_batch_stop, $rul_init, $rul_add, $rul_del,
	$rul_change, $rul_load, $rul_show, $rul_reset,
	$shaper_dev_add_class, $shaper_dev_change_class);

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
use constant {
	E_OK       => 0,
	E_PARAM    => 1,
	E_IP_COLL  => 2,
	E_UNDEF    => 3,
	E_EXIST    => 4,
	E_NOTEXIST => 5,
	E_CMD      => 6,
	E_PRIV     => 7,
};

# global return value
my $RET = E_OK;

# Preamble for usage and help message
my $usage_preamble = <<"EOF"
$VERSTR

Usage: $PROG [options] command <arguments>

Commands:
EOF
;

# options dispatch table for AppConfig and Getopt::Long
my %optd = (
	'f|config=s'            => \$cfg_file,
	'tc=s'                  => \$tc,
	'o|out_if=s'            => \$o_if,
	'i|in_if=s'             => \$i_if,
	'd|debug=i'             => \$debug,
	'v|verbose=i'           => \$verbose,
	'q|quiet!'              => \$quiet,
	'c|colored!'            => \$colored,
	'j|joint!'              => \$joint,
	'b|batch!'              => \$batch,
	'N|network=s'           => \$network,
	'C|cid=s'               => \$classid,
	'filter_network=s'      => \$filter_network,
	'limit_method=s'        => \$limit_method,
	'default_policy=s'      => \$default_policy,
	'default_rate=s'        => \$default_rate,
	'default_ceil=s'        => \$default_ceil,
	'bypass_int=s'          => \$bypass_int,
	'bypass_ext=s'          => \$bypass_ext,
	'policer_burst_ratio=s' => \$policer_burst_ratio,
	'Q|quantum=s'           => \$quantum,
	'u|rate_unit=s'         => \$rate_unit,
	'r|rate_ratio=f'        => \$rate_ratio,
	'R|root_qdisc=s'        => \$root_qdisc,
	'L|leaf_qdisc=s'        => \$leaf_qdisc,
	'db_driver=s'           => \$db_driver,
	'db_host=s'             => \$db_host,
	'db_name=s'             => \$db_name,
	'db_user=s'             => \$db_user,
	'db_pass=s'             => \$db_pass,
	'query_create=s'        => \$query_create,
	'query_load=s'          => \$query_load,
	'query_list=s'          => \$query_list,
	'query_add=s'           => \$query_add,
	'query_del=s'           => \$query_del,
	'query_change=s'        => \$query_change,
	'S|syslog_enable!'      => \$syslog_enable,
	'syslog_options=s'      => \$syslog_options,
	'syslog_facility=s'     => \$syslog_facility,
);

my %db_data;
my %rul_data;

# handlers and pointers for execution of external commands
my $TC_H;
my $TC = \&tc_sys;
my $sys;

# pref values for different types of tc filters
my $pref_bypass = 9; # bypassed networks
my $pref_hash = 10; # hashing filters
my $pref_leaf = 20; # leaf hashing filters
my $pref_default = 30; # default rule

my $ip_re = '\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}';

#
# Main routine
#

# parse command line to get the name of configuration file properly
my @argv = @ARGV;
GetOptionsFromArray(\@argv, %optd) or exit E_PARAM;
my $batch_cl = $batch;

# read configuration file
if (-T $cfg_file) {
	my @args = sort keys %optd;
	my @cargs = @args;

	my $cfg = AppConfig->new({
		CASE => 1, GLOBAL => { EXPAND => EXPAND_VAR | EXPAND_ENV }
	});

	# define configuration file parameters
	for my $i (0..$#cargs) {
		$cargs[$i] =~ s/^\w+\|//ixms;
		my ($a) = $cargs[$i] =~ s/([=!+].*)$//ixms;
		$cfg->define($cargs[$i], { ARGS => $a,
			DEFAULT => ${ $optd{$args[$i]} } });
	}
	$cfg->file($cfg_file);

	# parse configuration file
	for my $i (0..$#cargs) {
		${ $optd{$args[$i]} } = $cfg->get( $cargs[$i] );
		print "$cargs[$i] = ${ $optd{$args[$i]} }\n"
			if $verbose & VERB_NOBATCH;
	}
}
else {
	log_carp("unable to read configuration file $cfg_file");
}

# override values that we have read from file by the command line parameters
GetOptions(%optd) or exit E_PARAM;

if ($batch) {
	# command queue for batch mode
	my @queue;

	while (my $c = <>) {
		chomp $c;
		next if $c =~ /^\s*$/ixms;
		next if $c =~ /^\#/ixms;
		$c =~ s/\s+\#.*$//ixms;
		push @queue, $c;
	}
	for (@queue) {
		my @a = split /\ /ixms;
		$RET = main(@a);
	}
}
else {
	$RET = main(@ARGV);
}

exit $RET;

## end of main routine

sub main
{
	my @args = @_;
	my $ret = E_OK;

	# process command line in batch mode
	if ($batch) {
		GetOptionsFromArray(\@args, %optd) or return E_PARAM;
	}
	usage(E_CMD) if !defined $args[0];
	my $cmd = acomp_cmd($args[0]);
	usage(E_CMD) if !defined $cmd;
	return E_CMD if $cmd eq q{};

	if ($cmdd{$cmd}{'priv'} && !$debug && $>) {
		log_warn('you must run this command with root privileges');
		return E_PRIV;
	}

	# prepare all settings
	set_ptrs();
	set_class_nets();
	set_filter_nets();
	local $ENV{ANSI_COLORS_DISABLED} = 1 if !($colored && isatty(\*STDOUT));

	$i_if_enabled = ($i_if ne $if_disabled_keyword);
	if (!$i_if_enabled && $limit_method eq 'hybrid') {
		log_croak("in_if must be enabled for hybrid rate limiting method");
	}

	$o_if_enabled = ($o_if ne $if_disabled_keyword);
	if (!$i_if_enabled && !$o_if_enabled) {
		log_croak("at least one of the interfaces must be enabled");
	}

	# call main handler
	shift @args;
	$ret = $cmdd{$cmd}{'handler'}->(@args);

	# process return values
	if (!defined $ret) {
		$ret = -1;
		return $ret;
	}
	elsif ($ret == E_NOTEXIST) {
		log_carp("specified IP does not exist. Arguments: @args");
	}
	elsif ($ret == E_EXIST) {
		log_carp("specified IP already exists. Arguments: @args");
	}

	# call database handler
	if ($joint && defined $cmdd{$cmd}{'dbhandler'}) {
		$ret = $cmdd{$cmd}{'dbhandler'}->(@args);
		if ($ret == E_NOTEXIST) {
			log_carp(
				'database entry for specified IP does not exist. '.
				"Arguments: @args"
			);
		}
		elsif ($ret == E_EXIST) {
			log_carp(
				'database entry for specified IP already exists. '.
				"Arguments: @args"
			);
		}
	}
	return $ret;
}

sub usage
{
	my ($ret) = @_;
	print $usage_preamble;
	print_cmds();
	print "\n";
	exit $ret;
}

sub print_cmds
{
	my @cmds = sort keys %cmdd;
	my ($maxcmdlen, $maxarglen) = (0, 0);
	my @colspace = (2, 2, 3);
	my ($al, $cl);
	my %lengths;

	# find maximum length of command and arguments
	for my $key (@cmds) {
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

	for my $key (@cmds) {
		next unless nonempty($cmdd{$key}{'desc'});
		print q{ } x $colspace[0], $lengths{$key}{'cmd'},
		      q{ } x ($maxcmdlen - $lengths{$key}{'cmdl'} + $colspace[1]);
		print $cmdd{$key}{'arg'} if defined $cmdd{$key}{'arg'};
		print q{ } x ($maxarglen - $lengths{$key}{'argl'} + $colspace[2]),
		      $cmdd{$key}{'desc'}, "\n";
	}
	return;
}

sub set_ptrs
{
	if ($debug == DEBUG_OFF) {
		$sys = ($quiet)
		     ? sub { return system "@_ >/dev/null 2>&1"; }
		     : sub { return system @_; };
	}
	elsif ($debug == DEBUG_ON) {
		$sys = sub {
			my ($c) = @_;
			print RED, "$c\n", RESET if system $c;
			return $?;
		}
	}
	elsif ($debug == DEBUG_PRINT) {
		$sys = sub { return print "@_\n"; }
	}

	$rul_batch_start = sub {
		tc_batch_start() unless $verbose & VERB_NOBATCH;
	};
	$rul_batch_stop = sub {
		tc_batch_stop() unless $verbose & VERB_NOBATCH;
	};

	if ($limit_method eq 'shaping') {
		$rul_init   = \&shaper_init;
		$rul_add    = \&shaper_add;
		$rul_del    = \&shaper_del;
		$rul_change = \&shaper_change;
		$rul_load   = \&shaper_load;
		$rul_show   = \&shaper_show;
		$rul_reset  = \&shaper_reset;
	}
	elsif ($limit_method eq 'policing') {
		$rul_init   = \&policer_init;
		$rul_add    = \&policer_add;
		$rul_del    = \&policer_del;
		$rul_change = \&policer_add;
		$rul_load   = \&policer_load;
		$rul_show   = \&policer_show;
		$rul_reset  = \&policer_reset;
	}
	elsif ($limit_method eq 'hybrid') {
		$rul_init   = \&hybrid_init;
		$rul_add    = \&hybrid_add;
		$rul_del    = \&hybrid_del;
		$rul_change = \&hybrid_change;
		$rul_load   = \&policer_load;
		$rul_show   = \&hybrid_show;
		$rul_reset  = \&hybrid_reset;
	}
	else {
		log_croak(
			"\'$limit_method\' is invalid value for limit_method"
		);
	}

	if ($root_qdisc eq 'htb') {
		$shaper_dev_add_class = \&htb_dev_add_class;
		$shaper_dev_change_class = \&htb_dev_change_class;
	}
	elsif ($root_qdisc eq 'hfsc') {
		$shaper_dev_add_class = \&hfsc_dev_add_class;
		$shaper_dev_change_class = \&hfsc_dev_change_class;
	}
	else {
		log_croak("\'$root_qdisc\' is unsupported root qdisc");
	}

	return;
}

sub nonempty
{
	my ($str) = @_;
	return (defined $str && $str ne q{});
}

sub round
{
	my ($n) = @_;
	return int($n + .5*($n <=> 0));
}

sub acomp_cmd
{
	my ($input) = @_;
	my @match;
	my @ambig;

	for my $key (keys %cmdd) {
		my @cmds = split /\|/ixms, $key;
		for my $a (@cmds) {
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

	log_syslog('warn', $msg) if $syslog_enable;
	carp "$PROG: $msg" if !$quiet;
	return $!;
}

sub log_croak
{
	my ($msg) = @_;

	log_syslog('err', $msg) if $syslog_enable;
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

	log_syslog('warn', $msg) if $syslog_enable;
	print {*STDERR} "$PROG: $msg\n" if !$quiet;
	return $!;
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
	return 0 if !defined $rate;
	chomp $rate;
	my $result = 0;
	my ($num, $unit);

	if (($num, $unit) = $rate =~ /^([0-9]+)([A-z]*)$/xms) {
		return 0 if $num == 0;
		if (nonempty($unit)) {
			for my $u (keys %units) {
				if ($unit =~ /^(?:$u)$/xms) {
					$result = $rate;
					last;
				}
			}
		}
		else {
			$result = $num.$rate_unit;
		}
	}
	else {
		return 0;
	}
	return $result;
}

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

sub rate_cvt
{
	my ($rate, $dst_unit) = @_;
	my ($num, $unit, $s_key, $d_key);

	if (($num) = $rate =~ /^([0-9]+)([A-z]*)$/xms) {
		$unit = nonempty($2) ? $2 : $rate_unit;
		return $rate if $unit eq $dst_unit;
		for my $u (keys %units) {
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

	for my $u (keys %units) {
		if ($dst_unit =~ /^($u)$/xms) {
			$d_key = $u;
			last;
		}
	}
	log_croak('invalid destination unit specified') if !defined $d_key;
	my $dnum = round($num * $units{$s_key} / $units{$d_key});
	return "$dnum$dst_unit";
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
	elsif ($db_driver =~ /csv/ixms) {
		$dbh = DBI->connect(
			"DBI:CSV:",
			$db_user, $db_pass, {
				f_dir => $db_name,
				f_ext => ".csv",
				csv_sep_char => ";",
				csv_eol => "\n",
				RaiseError => 1, PrintError => 1,
				AutoCommit => 1 }
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
	my $ret = E_OK;
	my $dbh = db_connect() or return E_UNDEF;
	my $sth = $dbh->prepare($query_load);
	$sth->execute();
	my ($intip, $rate, $ip, $cid);

	while (my $ref = $sth->fetchrow_arrayref()) {
		($intip, $rate) = @{$ref};
		if (!nonempty($rate)) {
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
	return $ret;
}

sub get_iface_ip
{
	my ($iface) = @_;
	my $socket;
	socket($socket, PF_INET, SOCK_STREAM, (getprotobyname('tcp'))[2])
		or log_carp("unable to create a socket: $!\n");
	my $buf = pack('a256', $iface);
	if (ioctl($socket, SIOCGIFADDR(), $buf) && (my @ip = unpack('x20 C4', $buf))) {
		return join('.', @ip);
	}
}

#
# Common rule processing functions
#

sub set_class_nets
{
	my $cid_min = 2;
	my $cid_max = 0xFFFF;
	my $cid_i = $cid_min;

	for my $n (split /\ /ixms, $network) {
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

sub ip_classid
{
	my ($ip) = @_;
	my $intip = ip_texttoint($ip);
	my $cid;

	for my $n (keys %class_nets) {
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

sub print_rules
{
	my ($comment, @cmds) = @_;
	my @out;
	my $PIPE;

	for my $c (@cmds) {
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

sub tc_sys
{
	my ($c) = @_;
	return $sys->("$tc $c");
}

sub tc_batch
{
	my ($c) = @_;
	return print {$TC_H} "$c\n";
}

sub tc_batch_start
{
	if ($debug == DEBUG_PRINT) {
		open $TC_H, '>', 'tc.batch'
			or log_croak('unable to open tc.batch');
	}
	else {
		open $TC_H, '|-', "$tc -batch -"
			or log_croak("unable to create pipe for $tc");
	}
	$TC = \&tc_batch;
	return $TC_H;
}

sub tc_batch_stop
{
	$TC = \&tc_sys;
	return close $TC_H;
}

sub bypass_init
{
	my ($dev, $match, $parent) = @_;

	if (nonempty($bypass_int)) {
		for my $n (split /\ /ixms, $bypass_int) {
			$TC->(
				"filter add dev $dev parent $parent: protocol ip ".
				"pref $pref_bypass u32 match ip $match $n action pass"
			);
		}
	}

	if (nonempty($bypass_ext)) {
		my $rev_match = ($match eq 'src') ? 'dst' : 'src';
		for my $n (split /\ /ixms, $bypass_ext) {
			$TC->(
				"filter add dev $dev parent $parent: protocol ip ".
				"pref $pref_bypass u32 match ip $rev_match $n action pass"
			);
		}
	}
	return $?;
}

#
# u32 hashing filters functions
#

sub set_filter_nets
{
	# I restrict this value to a 0x7ff to avoid discontinuity of the filter
	# space. Real maximum number of u32 hash tables is 0xfff.
	my $ht_max = 0x7ff;

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

	for my $n (split /\ /ixms, $filter_network) {
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

# calculate leaf hash table and bucket number
#
# input: IP address
# output: leaf hash key, bucket number
sub ip_leafht_key
{
	my ($ip) = @_;
	my $intip = ip_texttoint($ip);
	my ($leafht, $key);

	for my $n (keys %filter_nets) {
		if ($intip >= $filter_nets{$n}{'intip_i'} &&
			$intip <= $filter_nets{$n}{'intip_f'}) {
			# 3rd octet
			my $ht_offset = ($intip & $filter_nets{$n}{'invmask'}) >> 8;
			# 4th octet
			$key = sprintf '%x', $intip & 0xFF;
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
sub u32_div_hmask
{
	my ($netmask, $n) = @_;
	log_croak("$n is invalid number of octet") if $n < 1 || $n > 4;
	# get n-th byte from netmask
	my $inthmask = (2**(32 - $netmask) - 1) & (0xFF << 8*(4-$n));
	my $hmask = sprintf '0x%08x', $inthmask;
	my $div = ($inthmask >> 8*(4-$n)) + 1;
	return ($div, $hmask);
}

# shaping regime

sub shaper_init
{
	my $ret = E_OK;
	$ret = shaper_dev_init($i_if, 'dst', 16) if $i_if_enabled;
	$ret = shaper_dev_init($o_if, 'src', 12) if $o_if_enabled;
	return $ret;
}

sub shaper_dev_init
{
	my ($dev, $match, $offset) = @_;

	$TC->("qdisc add dev $dev root handle 1: $root_qdisc default $default_cid");
	$TC->("filter add dev $dev parent 1:0 protocol ip pref $pref_hash u32");
	for my $net (sort {$filter_nets{$a}{'ht'} <=> $filter_nets{$b}{'ht'}}
	  keys %filter_nets) {
		my $ht1 = sprintf '%x', $filter_nets{$net}{'ht'};
		my $netmask = $filter_nets{$net}{'mask'};

		if ($netmask >= 24 && $netmask < 31) {
			my ($div1, $hmask1) = u32_div_hmask($netmask, 4);
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
			my ($div1, $hmask1) = u32_div_hmask($netmask, 3);

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
			my ($div2, $hmask2) = u32_div_hmask($netmask, 4);
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

	# bypass specified networks
	bypass_init($dev, $match, 1);

	# pass shaper's own traffic
	if ($default_policy eq 'block') {
		my $self_ip = get_iface_ip($dev);
		if (nonempty($self_ip)) {
			$TC->(
				"filter add dev $dev parent 1: protocol ip ".
				"pref $pref_bypass u32 match ip src $self_ip action pass"
			);
			$TC->(
				"filter add dev $dev parent 1: protocol ip ".
				"pref $pref_bypass u32 match ip dst $self_ip action pass"
			);
		}
	}
	# block all other traffic
	if ($default_policy eq 'block' || $default_policy eq 'block-all') {
		$TC->(
			"filter add dev $dev parent 1:0 protocol ip pref $pref_default ".
			'u32 match u32 0 0 at 0 '.
			'action drop'
		);
	}
	if ($default_policy eq 'pass') {
		# add default class
		$shaper_dev_add_class->($dev, $default_cid, $default_rate, $default_ceil);
	}
	return $?;
}

sub shaper_add
{
	my ($ip, $cid, $rate) = @_;
	my $ret = E_OK;
	my $ceil = $rate;
	my ($ht, $key) = ip_leafht_key($ip);
	$ret = shaper_dev_add($i_if, $cid, $rate, $ceil, "ip dst $ip", $ht, $key)
		if $i_if_enabled;
	$ret = shaper_dev_add($o_if, $cid, $rate, $ceil, "ip src $ip", $ht, $key)
		if $o_if_enabled;
	return $ret;
}

sub shaper_dev_add
{
	my ($dev, $cid, $rate, $ceil, $match, $ht, $key) = @_;
	my $ret = E_OK;

	$ret = $shaper_dev_add_class->($dev, $cid, $rate, $ceil);
	$ret = shaper_dev_add_filter($dev, $cid, $match, $ht, $key);
	return $ret;
}

sub shaper_dev_add_filter
{
	my ($dev, $cid, $match, $ht, $key) = @_;

	$TC->(
		"filter replace dev $dev parent 1: pref $pref_leaf ".
		"handle $ht:$key:800 u32 ht $ht:$key: match $match flowid 1:$cid"
	);
	return $?;
}

sub htb_dev_add_class
{
	my ($dev, $cid, $rate, $ceil) = @_;
	$TC->(
		"class replace dev $dev parent 1: classid 1:$cid htb ".
		"rate $rate ceil $ceil quantum $quantum"
	);
	$TC->(
		"qdisc replace dev $dev parent 1:$cid handle $cid:0 $leaf_qdisc"
	);
	return $?;
}

sub hfsc_dev_add_class
{
	my ($dev, $cid, $rate, $ceil) = @_;
	$TC->(
		"class replace dev $dev parent 1: classid 1:$cid hfsc ".
		"sc rate $rate ul rate $ceil"
	);
	$TC->(
		"qdisc replace dev $dev parent 1:$cid handle $cid:0 $leaf_qdisc"
	);
	return $?;
}

sub shaper_change
{
	my ($ip, $cid, $rate) = @_;
	my $ceil = $rate;
	my $ret = E_OK;
	$ret = $shaper_dev_change_class->($i_if, $cid, $rate, $ceil) if $i_if_enabled;
	$ret = $shaper_dev_change_class->($o_if, $cid, $rate, $ceil) if $o_if_enabled;
	return $ret;
}

sub htb_dev_change_class
{
	my ($dev, $cid, $rate, $ceil) = @_;
	$TC->(
		"class change dev $dev parent 1: classid 1:$cid htb ".
		"rate $rate ceil $ceil quantum $quantum"
	);
	return $?;
}

sub hfsc_dev_change_class
{
	my ($dev, $cid, $rate, $ceil) = @_;
	$TC->(
		"class change dev $dev parent 1: classid 1:$cid hfsc ".
		"sc rate $rate ul rate $ceil"
	);
	return $?;
}

sub shaper_del
{
	my ($ip, $cid) = @_;
	my $ret = E_OK;
	my ($ht, $key) = ip_leafht_key($ip);
	$ret = shaper_dev_del($i_if, $cid, $ht, $key) if $i_if_enabled;
	$ret = shaper_dev_del($o_if, $cid, $ht, $key) if $o_if_enabled;
	return $ret;
}

sub shaper_dev_del
{
	my ($dev, $cid, $ht, $key) = @_;
	shaper_dev_del_filter($dev, $ht, $key);
	shaper_dev_del_class($dev, $cid);
	return $?;
}

sub shaper_dev_del_filter
{
	my ($dev, $ht, $key) = @_;
	$TC->(
		"filter del dev $dev parent 1: pref $pref_hash ".
		"handle $ht:$key:800 u32"
	);
	return $?;
}

sub shaper_dev_del_class
{
	my ($dev, $cid) = @_;
	$TC->("qdisc del dev $dev parent 1:$cid handle $cid:0");
	$TC->("class del dev $dev parent 1: classid 1:$cid");
	return $?;
}

sub shaper_load
{
	my ($ip, $cid, $rate);
	my $ret = E_OK;
	my $leaf_regexp;
	my $dev;

	$dev = $o_if if $o_if_enabled;
	$dev = $i_if if $i_if_enabled;

	open my $TCFH, '-|', "$tc -p -iec filter show dev $dev"
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

	open my $TCCH, '-|', "$tc class show dev $dev"
		or log_croak("unable to open pipe for $tc");
	@tcout = <$TCCH>;
	close $TCCH or log_carp("unable to close pipe for $tc");
	if ($root_qdisc eq 'htb') {
		$leaf_regexp = 'leaf\ ([0-9a-f]+):\ .*\ rate\ (\w+)';
	}
	elsif ($root_qdisc eq 'hfsc') {
		$leaf_regexp = 'leaf\ ([0-9a-f]+):\ .*\ m2\ (\w+)';
	}
	else {
		log_croak("\'$root_qdisc\' is unsupported root qdisc");
	}
	for (@tcout) {
		if (($cid, $rate) = /$leaf_regexp/xms) {
			next if !defined $rul_data{$cid};
			$rate = rate_cvt($rate, $rate_unit);
			$rul_data{$cid}{'rate'} = $rate;
		}
	}
	return $ret;
}

sub shaper_show
{
	my @ips = @_;
	my ($dev, $cid);
	my $ret = E_OK;

	$dev = $o_if if $o_if_enabled;
	$dev = $i_if if $i_if_enabled;

	if (nonempty($ips[0])) {
		for my $ip (@ips) {
			arg_check(\&is_ip, $ip, 'IP');

			open my $TCFH, '-|', "$tc -p -s filter show dev $dev"
				or log_croak("unable to open pipe for $tc");
			my @tcout = <$TCFH>;
			close $TCFH or log_carp("unable to close pipe for $tc");
			for my $i (0 .. $#tcout) {
				chomp $tcout[$i];
				if ($tcout[$i] =~ /match\ IP\ .*\ $ip/xms) {
					if (($cid) = $tcout[$i-1] =~ /flowid\ 1:([0-9a-f]+)/xms) {
						print BOLD, "TC rules for $ip\n\n", RESET;
						$ret = shaper_dev_ip_show($i_if, 'Input',  $ip, $cid)
							if $i_if_enabled;
						$ret = shaper_dev_ip_show($o_if, 'Output', $ip, $cid)
							if $o_if_enabled;
						print "\n";
						last;
					}
				}
			}
		}
	}
	else {
		$ret = shaper_dev_show($i_if) if $i_if_enabled;
		$ret = shaper_dev_show($o_if) if $o_if_enabled;
	}
	return $ret;
}

sub shaper_dev_ip_show
{
	my ($dev, $type, $ip, $cid) = @_;

	print_rules(
		"\n$type filter [$dev]:",
		"$tc -p -s filter show dev $dev | ".
		"grep -G -w -B 1 \"match IP .* $ip\""
	);
	print_rules(
		"\n$type class [$dev]:",
		"$tc -i -s -d class show dev $dev | ".
		"grep -G -w -A 4 \"leaf $cid\:\""
	);
	print_rules(
		"\n$type qdisc [$dev]:",
		"$tc -i -s -d qdisc show dev $dev | ".
		"grep -G -w -A 2 \"$cid\: parent 1:$cid\""
	);
	return $?;
}

sub shaper_dev_show
{
	my ($dev) = @_;
	print BOLD, "\nINPUT FILTERS [$dev]:\n", RESET;
	system "$tc -p -s filter show dev $dev";
	print BOLD, "\nINPUT CLASSES [$dev]:\n", RESET;
	system "$tc -i -s -d class show dev $dev";
	print BOLD, "\nINPUT QDISCS [$dev]:\n", RESET;
	system "$tc -i -s -d qdisc show dev $dev";
	return $?;
}

sub shaper_reset
{
	$sys->("$tc qdisc del dev $o_if root handle 1: $root_qdisc") if $o_if_enabled;
	$sys->("$tc qdisc del dev $i_if root handle 1: $root_qdisc") if $i_if_enabled;
	return $?;
}

# policing regime

sub policer_init
{
	my $ret = E_OK;
	$ret = policer_dev_init($o_if, 'dst', 16) if $o_if_enabled;
	$ret = policer_dev_init($i_if, 'src', 12) if $i_if_enabled;
	return $ret;
}

sub policer_dev_init
{
	my ($dev, $match, $offset) = @_;

	$TC->("qdisc add dev $dev handle $ingress_cid: ingress");
	$TC->(
		"filter add dev $dev parent $ingress_cid: protocol ip ".
		"pref $pref_hash u32"
	);
	for my $net (sort {$filter_nets{$a}{'ht'} <=> $filter_nets{$b}{'ht'}}
	  keys %filter_nets) {
		my $ht1 = sprintf '%x', $filter_nets{$net}{'ht'};
		my $netmask = $filter_nets{$net}{'mask'};

		if ($netmask >= 24 && $netmask < 31) {
			my ($div1, $hmask1) = u32_div_hmask($netmask, 4);
			$TC->(
				"filter add dev $dev parent $ingress_cid: protocol ip ".
				"pref $pref_hash handle $ht1: u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent $ingress_cid: protocol ip ".
				"pref $pref_hash u32 ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);
		}
		elsif ($netmask >= 16 && $netmask < 24) {
			my @oct = split /\./ixms, $filter_nets{$net}{'ip'};
			my ($div1, $hmask1) = u32_div_hmask($netmask, 3);

			# parent filter
			$TC->(
				"filter add dev $dev parent $ingress_cid: protocol ip ".
				"pref $pref_hash handle $ht1: u32 divisor $div1"
			);
			$TC->(
				"filter add dev $dev parent $ingress_cid: protocol ip ".
				"pref $pref_hash u32 ht 800:: match ip $match $net ".
				"hashkey mask $hmask1 at $offset link $ht1:"
			);

			# child filters
			my ($div2, $hmask2) = u32_div_hmask($netmask, 4);
			for my $i (0 .. $div1 - 1) {
				my $key = sprintf '%x', $i;
				my $ht2 = sprintf '%x', $filter_nets{$net}{'leafht_i'} + $i;
				my $j = $oct[2] + $i;
				my $net2 = "$oct[0].$oct[1].$j.0/24";

				$TC->(
					"filter add dev $dev parent $ingress_cid: protocol ip ".
					"pref $pref_hash handle $ht2: u32 divisor $div2"
				);
				$TC->(
					"filter add dev $dev parent $ingress_cid: protocol ip ".
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

	# bypass specified networks
	bypass_init($dev, $match, $ingress_cid);

	# block all other traffic
	if ($default_policy eq 'block') {
		$TC->(
			"filter add dev $dev parent $ingress_cid: protocol ip ".
			"pref $pref_default u32 match u32 0 0 at 0 ".
			'action drop'
		);
	}
	return $?;
}

sub policer_add
{
	my ($ip, $cid, $rate) = @_;
	my $ceil = $rate;
	my $ret = E_OK;
	my ($ht, $key) = ip_leafht_key($ip);

	$ret = policer_dev_add($o_if, $rate, $ceil, "ip dst $ip", $ht, $key)
		if $o_if_enabled;
	$ret = policer_dev_add($i_if, $rate, $ceil, "ip src $ip", $ht, $key)
		if $i_if_enabled;
	return $ret;
}

sub policer_dev_add
{
	my ($dev, $rate, $ceil, $match, $ht, $key) = @_;
	my $rate_byte = rate_cvt($rate, 'bps');
	$rate_byte =~ s/bps//gxms;
	my $policer_burst = round($policer_burst_ratio * $rate_byte) . 'b';

	$TC->(
		"filter replace dev $dev parent $ingress_cid: pref $pref_leaf ".
		"handle $ht:$key:800 u32 ht $ht:$key: match $match ".
		"police rate $rate burst $policer_burst drop flowid $ingress_cid:"
	);
	return $?;
}

sub policer_del
{
	my ($ip, $cid) = @_;
	my $ret = E_OK;
	my ($ht, $key) = ip_leafht_key($ip);
	$ret = policer_dev_del($i_if, $ht, $key) if $i_if_enabled;
	$ret = policer_dev_del($o_if, $ht, $key) if $o_if_enabled;
	return $ret;
}

sub policer_dev_del
{
	my ($dev, $ht, $key) = @_;

	$TC->(
		"filter del dev $dev parent $ingress_cid: pref $pref_hash ".
		"handle $ht:$key:800 u32"
	);
	return $?;
}

sub policer_load
{
	my ($ip, $cid, $rate);
	my $ret = E_OK;
	my $dev;

	$dev = $o_if if $o_if_enabled;
	$dev = $i_if if $i_if_enabled;

	open my $TCFH, '-|', "$tc -p -iec filter show dev $dev parent $ingress_cid:"
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
	return $ret;
}

sub policer_show
{
	my @ips = @_;
	my $ret = E_OK;

	if (nonempty($ips[0])) {
		for my $ip (@ips) {
			arg_check(\&is_ip, $ip, 'IP');
			policer_dev_ip_show($i_if, 'Input',  $ip) if $i_if_enabled;
			policer_dev_ip_show($o_if, 'Output', $ip) if $o_if_enabled;
		}
	}
	else {
		$ret = policer_dev_show($i_if) if $i_if_enabled;
		$ret = policer_dev_show($o_if) if $o_if_enabled;
	}
	return $ret;
}

sub policer_dev_ip_show
{
	my ($dev, $type, $ip) = @_;
	my @tcout;

	open my $TCFH, '-|',
		"$tc -p -s -iec filter show dev $dev parent $ingress_cid:"
		or log_croak("unable to open pipe for $tc");
	@tcout = <$TCFH>;
	close $TCFH or log_carp("unable to close pipe for $tc");
	for my $i (0 .. $#tcout) {
		chomp $tcout[$i];
		if ($tcout[$i] =~ /match\ IP\ .*\ $ip/xms) {
			print BOLD, "\n$type filter [$dev]:\n", RESET;
			for my $j ($i-1 .. $i+4) {
				print "$tcout[$j]";
			}
			last;
		}
	}
	return $?;
}

sub policer_dev_show
{
	my ($dev) = @_;
	print BOLD, "\nPOLICING FILTERS [$dev]:\n", RESET;
	system "$tc -p -s filter show dev $dev parent $ingress_cid:";
	return $?;
}

sub policer_reset
{
	$sys->("$tc qdisc del dev $o_if handle $ingress_cid: ingress")
		if $o_if_enabled;
	$sys->("$tc qdisc del dev $i_if handle $ingress_cid: ingress")
		if $i_if_enabled;
	return $?;
}

# hybrid regime: policing and shaping on ingress interface

sub hybrid_init
{
	my $ret = E_OK;
	$ret = policer_dev_init($i_if, 'src', 12);
	$ret = shaper_dev_init($i_if, 'dst', 16);
	return $ret;
}

sub hybrid_add
{
	my ($ip, $cid, $rate) = @_;
	my $ceil = $rate;
	my $ret = E_OK;
	my ($ht, $key) = ip_leafht_key($ip);
	$ret = policer_dev_add($i_if, $rate, $ceil, "ip src $ip", $ht, $key);
	$ret = shaper_dev_add($i_if, $cid, $rate, $ceil, "ip dst $ip", $ht, $key);
	return $ret;
}

sub hybrid_del
{
	my ($ip, $cid) = @_;
	my $ret = E_OK;
	my ($ht, $key) = ip_leafht_key($ip);
	$ret = policer_dev_del($i_if, $ht, $key);
	$ret = shaper_dev_del($i_if, $cid, $ht, $key);
	return $ret;
}

sub hybrid_change
{
	my ($ip, $cid, $rate) = @_;
	my $ret = E_OK;
	my $ceil = $rate;
	my ($ht, $key) = ip_leafht_key($ip);
	$ret = policer_dev_add($i_if, $rate, $ceil, "ip src $ip", $ht, $key);
	$ret = $shaper_dev_change_class->($i_if, $cid, $rate, $ceil);
	return $ret;
}

sub hybrid_show
{
	my @ips = @_;

	if (nonempty($ips[0])) {
		for my $ip (@ips) {
			arg_check(\&is_ip, $ip, 'IP');
			my $cid;
			my @tcout;

			open my $TCFH, '-|',
				"$tc -p -s -iec filter show dev $i_if parent $ingress_cid:"
					or log_croak("unable to open pipe for $tc");
			@tcout = <$TCFH>;
			close $TCFH or log_carp("unable to close pipe for $tc");
			for my $i (0 .. $#tcout) {
				chomp $tcout[$i];
				if ($tcout[$i] =~ /match\ IP\ .*\ $ip\/32/xms) {
					print BOLD, "TC rules for $ip\n\n",
					            "Policing filter [$i_if]:\n", RESET;
					for my $j ($i-1 .. $i+1) {
						print "$tcout[$j]";
					}
					last;
				}
			}

			open $TCFH, '-|', "$tc -p -s filter show dev $i_if"
				or log_croak("unable to open pipe for $tc");
			@tcout = <$TCFH>;
			close $TCFH or log_carp("unable to close pipe for $tc");
			for my $i (0 .. $#tcout) {
				chomp $tcout[$i];
				if ($tcout[$i] =~ /match\ IP\ .*\ $ip\/32/xms) {
					if (($cid) = $tcout[$i-1] =~ /flowid\ 1:([0-9a-f]+)/xms) {
						print BOLD, "Input filter [$i_if]:\n", RESET;
						print "$tcout[$i-1]\n$tcout[$i]\n";
						print_rules(
							"\nShaping filter [$i_if]:",
							"$tc -p -s filter show dev $i_if | ".
							"grep -w -B 1 \"match IP dst $ip/32\""
						);
						print_rules(
							"\nShaping class [$i_if]:",
							"$tc -i -s -d class show dev $i_if | ".
							"grep -w -A 3 \"leaf $cid\:\""
						);
						print_rules(
							"\nShaping qdisc [$i_if]:",
							"$tc -i -s -d qdisc show dev $i_if | ".
							"grep -w -A 2 \"$cid\: parent 1:$cid\""
						);
						print "\n";
						last;
					}
				}
			}
		}
	}
	else {
		print BOLD, "\nPOLICING FILTERS [$i_if]:\n", RESET;
		system "$tc -p -s filter show dev $i_if parent $ingress_cid:";
		print BOLD, "\nSHAPING FILTERS [$i_if]:\n", RESET;
		system "$tc -p -s filter show dev $i_if";
		print BOLD, "\nSHAPING CLASSES [$i_if]:\n", RESET;
		system "$tc -i -s -d class show dev $i_if";
		print BOLD, "\nSHAPING QDISCS [$i_if]:\n", RESET;
		system "$tc -i -s -d qdisc show dev $i_if";
		return $?;
	}
	return $?;
}

sub hybrid_reset
{
	$sys->("$tc qdisc del dev $i_if handle $ingress_cid: ingress");
	$sys->("$tc qdisc del dev $i_if root handle 1: $root_qdisc");
	return $?;
}

#
# Command handlers
#

sub cmd_init
{
	my $ret = E_OK;
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
	my $cid = (nonempty($classid)) ? $classid : ip_classid($ip);
	return $rul_add->($ip, $cid, $rate);
}

sub cmd_del
{
	my ($ip) = @_;

	arg_check(\&is_ip, $ip, 'IP');
	my $cid = (nonempty($classid)) ? $classid : ip_classid($ip);
	return $rul_del->($ip, $cid);
}

sub cmd_change
{
	my ($ip, $rate) = @_;

	arg_check(\&is_ip, $ip, 'IP');
	$rate = arg_check(\&is_rate, $rate, 'rate');
	my $cid = (nonempty($classid)) ? $classid : ip_classid($ip);
	return $rul_change->($ip, $cid, $rate);
}

sub cmd_list
{
	my @ips = @_;
	my $ret = $rul_load->();
	my $fmt = "%4s  %-15s %11s\n";

	if (nonempty($ips[0])) {
		for my $ip (@ips) {
			arg_check(\&is_ip, $ip, 'IP');
			my $cid = ip_classid($ip);
			if (defined $rul_data{$cid}) {
				printf $fmt, $cid, $rul_data{$cid}{'ip'},
					$rul_data{$cid}{'rate'};
			}
		}
	}
	else {
		for my $cid (sort { hex $a <=> hex $b } keys %rul_data) {
			printf $fmt, $cid, $rul_data{$cid}{'ip'}, $rul_data{$cid}{'rate'};
		}
	}
	return $ret;
}

sub cmd_load
{
	my $ret = E_OK;
	my $rate;

	$rul_batch_start->();
	$ret = $rul_init->();
	$ret = db_load();
	for my $cid (keys %db_data) {
		$rate = $db_data{$cid}{'rate'};
		if ($rate != 0) {
			$rate = round($rate_ratio * $rate);
			$rul_add->($db_data{$cid}{'ip'}, $cid, $rate.$rate_unit);
		}
	}
	$rul_batch_stop->();
	return $ret;
}

sub cmd_sync
{
	my ($add, $del, $chg) = (0, 0, 0);
	my ($db_rate, $rul_rate);

	$rul_load->();
	db_load();
	$rul_batch_start->();

	# delete rules for IPs that is not in database
	for my $rcid (keys %rul_data) {
		if (!defined $db_data{$rcid} && defined $rul_data{$rcid}) {
			my $ip = $rul_data{$rcid}{'ip'};
			print "- $ip\n" if $verbose & VERB_ON;
			$rul_del->($ip, $rcid);
			$del++;
		}
	}
	for my $dcid (keys %db_data) {
		# delete entries with zero rates
		$db_rate = $db_data{$dcid}{'rate'};
		my $db_rate_zero = ($db_rate == 0);
		my $rul_rate_defined = nonempty($rul_data{$dcid}{'rate'});
		if ($db_rate_zero && $rul_rate_defined ) {
			my $ip = $db_data{$dcid}{'ip'};
			print "- $ip\n" if $verbose & VERB_ON;
			$rul_del->($ip, $dcid);
			$del++;
			next;
		}
		$db_rate = round($rate_ratio * $db_rate);
		$db_rate .= $rate_unit;
		# add new entries
		if (!$db_rate_zero && !$rul_rate_defined) {
			my $ip = $db_data{$dcid}{'ip'};
			print "+ $ip\n" if $verbose & VERB_ON;
			$rul_add->($ip, $dcid, $db_rate);
			$add++;
			next;
		}
		# change if rate in database is different
		if ($rul_rate_defined) {
			$rul_rate = $rul_data{$dcid}{'rate'};
			if ($rul_rate ne $db_rate) {
				my $ip = $db_data{$dcid}{'ip'};
				print "* $ip $rul_rate -> $db_rate\n" if $verbose & VERB_ON;
				$rul_change->($ip, $dcid, $db_rate);
				$chg++;
			}
		}
	}

	$rul_batch_stop->();
	return ($add, $del, $chg);
}

sub cmd_show
{
	return $rul_show->(@_);
}

sub cmd_status
{
	my $dev;
	$dev = $o_if if $o_if_enabled;
	$dev = $i_if if $i_if_enabled;

	my @out;
	my $PIPE;
	open $PIPE, '-|', "$tc qdisc show dev $dev"
		or log_croak("unable to open pipe for $tc");
	@out = <$PIPE>;
	close $PIPE or log_croak("unable to close pipe for $tc");

	my $rqdisc;
	if ($out[0] =~ /^qdisc\ htb/xms) {
		$rqdisc = 'htb';
	}
	elsif ($out[0] =~ /^qdisc\ hfsc/xms) {
		$rqdisc = 'hfsc';
	}
	elsif (defined $out[1]) {
		if ($out[1] =~ /^qdisc\ ingress/xms) {
			$rqdisc = 'ingress';
		}
	}
	else {
		log_warn('no shaping rules found');
		return E_UNDEF;
	}

	if ($rqdisc eq 'htb' || $rqdisc eq 'hfsc') {
		my @lqd = split /\ /xms, $leaf_qdisc;
		my $lqdisc = $lqd[0];
		shift @out;
		for my $s (@out) {
			chomp $s;
			if ($s =~ /qdisc\ $lqdisc\ ([0-9a-f]+):/xms) {
				log_warn('shaping rules were successfully created');
				return E_OK;
			}
		}
		log_warn('root qdisc found, but there is no child queues');
	}
	return E_UNDEF;
}

sub cmd_ver
{
	print "$VERSTR\n\n";
	pod2usage({ -exitstatus => 'NOEXIT', -verbose => 99,
		-sections => 'LICENSE AND COPYRIGHT' });
	return E_OK;
}

sub cmd_help
{
	if ($verbose & VERB_ON) {
		pod2usage({ -exitstatus => 0, -verbose => 2 });
	}
	else {
		my $linewidth = 80;
		my $indent = '    ';

		print "$VERSTR\n\n";
		pod2usage({ -exitstatus => 'NOEXIT', -verbose => 99,
			-sections => 'SYNOPSIS|COMMANDS|OPTIONS', -output => \*STDOUT });
		print "Available database drivers:\n";
		my $drv = join q{ }, DBI->available_drivers;
		$drv =~ s/([^\n]{1,$linewidth})(?:\b\s*|\n)/$indent$1\n/goixms;
		print "$drv\n";
	}
	return E_OK;
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
	return E_OK;
}

sub cmd_dbdel
{
	my @ips = @_;
	my $dbh = db_connect();
	my $sth;

	for my $ip (@ips) {
		arg_check(\&is_ip, $ip, 'IP');
		my $intip = ip_texttoint($ip);
		$sth = $dbh->prepare($query_del);
		$sth->execute($intip);
		$sth->finish();
	}
	undef $sth;
	$dbh->disconnect();
	return E_OK;
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
	return E_OK;
}

sub cmd_dblist
{
	my ($ip) = @_;
	my $ret = E_OK;

	if (!defined $ip) {
		$ret = db_load();
		for my $cid (sort { hex $a <=> hex $b } keys %db_data) {
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
	return $ret;
}

sub cmd_ratecvt
{
	my ($rate, $unit) = @_;

	log_croak('rate is undefined') if !defined $rate;
	log_croak('destination unit is undefined') if !defined $unit;
	my $result;
	$result = rate_cvt($rate, $unit);
	print "$result\n";
	return E_OK;
}

sub cmd_calc
{
	my ($ip) = @_;

	if (!defined $ip) {
		require Data::Dumper;
		print Dumper(\%filter_nets);
		print Dumper(\%class_nets);
		return E_OK;
	}
	arg_check(\&is_ip, $ip, 'IP');
	my $cid = ip_classid($ip);
	my ($ht, $key) = ip_leafht_key($ip);
	print "classid = $cid, leaf ht = $ht, key = $key\n";
	return E_OK;
}


__END__

=head1 NAME

B<sc> - administration tool for ISP traffic shaper

=head1 SYNOPSIS

B<sc> [options] B<command> [ip] [rate]

=head1 DESCRIPTION

sc(8) is a command-line tool intended to simplify administration of traffic
shaper for Internet service providers.

=head2 Main features

=over

=item * Fast loading of large rulesets.

=item * Effective traffic classification with B<u32> hashing filters.

=item * Loading of data from any relational database supported by Perl DBI
module.

=item * Synchronization of rules with database.

=item * Batch command execution mode for scripting purposes.

=item * Support of different traffic limiting methods: shaping, policing, and
hybrid.

=back


=head1 DEPENDENCIES

DBI and a corresponding database-dependent module (e.g. DBD::Pg for PostgreSQL,
DBD::SQLite for SQLite, etc), AppConfig, Carp, Getopt::Long, Pod::Usage,
Sys::Syslog, Term::ANSIColor.


=head1 PREREQUISITES

=head2 Command-line tools

tc(8) from B<iproute2> suite.

=head2 Linux kernel configuration

=over

=item * B<u32> classifier (option B<CONFIG_NET_CLS_U32>=m or y)

=item * Traffic control actions (B<CONFIG_NET_CLS_ACT>=y and
B<CONFIG_NET_ACT_GACT>=m or y)

=back


=head1 COREQUISITES

If you prefer policing as a rate limiting method, you should enable the kernel
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
and show manpage if B<-v 1> option is specified.

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

=item B<-v>, B<--verbose> mode

Possible values:

=over

=item B<0>

no verbose messages (default)

=item B<1>

enable verbose messages (i.e. for results of `sync' command)

=item B<2>

disable usage of tc(8) batch rule loading

=item B<3>

do both B<1> and B<2>

=back

=item B<-q>, B<--quiet>

Suppress output of error messages from tc(8).

=item B<-c>, B<--colored>

Colorize the output.

=item B<-C>, B<--cid> classid

Use the specified classid value in B<add>, B<change> and B<del> commands
instead of automatically calculated.

=item B<-j>, B<--joint>

Joint mode. B<Add>, B<change> and B<del> commands will be applied to rules and
database entries simultaneously.

=item B<-b>, B<--batch>

Batch mode. Commands and options will be read from STDIN.

=item B<-N, --network> "net/mask ..."

Networks for IP to classid mapping (see sc.conf(5) for details).

=item B<--filter_network> "net/mask ..."

Networks for hashing filter generation (see sc.conf(5) for details).

=item B<--bypass_int> "net/mask ..."

Internal networks, whose traffic is transmitted without shaping.

=item B<--bypass_ext> "net/mask ..."

External networks, whose traffic is transmitted without shaping.

=item B<--policer_burst_ratio> real number

Ratio between the size of policer buffer size and bandwidth rate.

=item B<--quantum> size

Amount of bytes a stream is allowed to dequeue before the next queue gets a
turn.

=item B<-u>, B<--rate_unit> unit

Default rate unit

=item B<-r>, B<--rate_ratio> real number

Ratio between bandwidth rates in rules and in the database.
Used only for B<load> and B<sync> commands.

=item B<-R>, B<--root_qdisc> string

Root qdisc (C<htb> or C<hfsc>).

=item B<-L>, B<--leaf_qdisc> string

Leaf qdisc and parameters.

=item B<--db_driver> name

Database driver.

=item B<--db_host> host:port

Database server address or hostname.

=item B<--db_name> name

Database name to use.

=item B<--db_user> name

Database username.

=item B<--db_pass> password

Database password. Remember that it is insecure to specify a password here.

=item B<-S>, B<--syslog_enable>

Send errors and warnings to syslog.

=back


=head1 RATE UNITS

All rates should be specified as integer numbers, possibly followed by a unit.
Bare number implies the default unit (kibit).
You may use another unit by changing C<rate_unit> parameter in the
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

C<sc load> or C<sc start>

=item Add class for IP 10.0.0.1 with 256kibit/s.

C<sc add 10.0.0.1 256kibit>

=item Change rate to 512kibit/s

C<sc change 10.0.0.1 512kibit>

=item Delete rules for 10.0.0.1

C<sc del 10.0.0.1>

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
To print all generated command lines without execution, use B<-d 2> option.
To disable the usage of the batch mode of tc(8), use B<-v 2> option.
For more information please read the section B<OPTIONS>.

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


=head1 RESTRICTIONS

For performance reasons, script does not perform checks that require
additional executions of external programs.

Due to limited number of classids (from 2 to ffff) you can create only 65534
classes on a single interface.
For similar reasons sc(8) only supports networks with masks from /16 to /31.

For simplicity of u32 hash table numbers calculation, the maximum number of
entries in C<filter_network> parameter is 255, and the number of hashing
filters is limited by 0x7ff.


=head1 SEE ALSO

sc.conf(5), tc(8), tc-htb(8), tc-hfsc(8), Getopt::Long(3), AppConfig(3),
http://lartc.org/howto/lartc.adv-filter.hashing.html


=head1 AUTHOR

Stanislav Kruchinin <stanislav.kruchinin@gmail.com>


=head1 LICENSE AND COPYRIGHT

Copyright (c) Stanislav Kruchinin.

License: GNU GPL version 3 or later

This is free software: you are free to change and redistribute it.
There is NO WARRANTY; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR
PURPOSE.

=cut

