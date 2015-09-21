#!/usr/bin/env perl

use strict;
use warnings;
no warnings 'redefine';

BEGIN {
  push(@INC, './');
};

use Data::Dumper;
use File::Copy;
use File::Path qw(mkpath);
use Test::More tests => 30;
use Test::Trap;
use Test::Exception;
use Citadel;

require_ok('Socket');
require_ok('Time::localtime');
require_ok('File::Path');
require_ok('Net::CIDR::Lite');

Citadel::ensure_root();

is_deeply(\%Citadel::int_config, 
  { 
    version => '0.1.4',
    spool   => '/var/spool/citadel/bans',
    spool_dir => '/var/spool/citadel',
    conf_file => '/etc/citadel/citadel.conf',
    log_file => '/var/log/citadel.log',
    lock_file => '/var/lock/citadel.lock',
    sys_cmd_timeout_limit => '120',
    not_root => '0',
    time => time, 
  }, 'int_config is valid');

like (Citadel::get_time, qr/\S+/, 'get_time returns something');

Citadel::place_lock;
if ( -e '/var/lock/citadel.lock' ) {
  pass('Lock [/var/lock/citadel.lock] placed');
}
else {
  fail('Lock [/var/lock/citadel.lock] placed');
}

trap{ Citadel::halt_if_running() };
like( $trap->stderr, qr/FATAL:\s+citadel\s+has\s+encountered/, 'Should fail if non-stale lock file' );

open(LOCK, '>', '/var/lock/citadel.lock');
print LOCK '19861337';
close(LOCK);
lives_ok{ Citadel::halt_if_running() } 'Lives if lock file is not stale';


Citadel::rm_lock;
if ( -e '/var/lock/citadel.lock' ) {
  fail('Lock [/var/lock/citadel.lock] removed');
}
else {
  pass('Lock [/var/lock/citadel.lock] removed');
}

unlink('/etc/citadel/citadel.conf') if ( -e '/etc/citadel/citadel.conf' );;
trap{ Citadel::read_conf_file() };
like( $trap->stderr, qr/Conf\s+file\s+\S+\s+doesn't\s+exist/, 'read_conf_file() fails if citadel.conf is missing');
copy('./citadel.conf','/etc/citadel/citadel.conf') or die "Copy failed: $!";
my $conf_file = Citadel::read_conf_file();
is_deeply(
  $conf_file, 
  {
    allowed_ips => '127.0.0.1:0.0.0.0',
    auto_detect_fw_tool => 1,
    explicit_fw_tool => 'apf',
    apf_path => '/usr/local/sbin/apf',
    csf_path => '/usr/sbin/csf',
    iptables_path => '/sbin/iptables',
    allowed_cons => 150,
    ban_period => 600,
  }, 'Reading citadel.conf returns expected'
);

trap{ Citadel::logger({cat => 'c', msg => 'tests lol'}) };
like( $trap->stderr, qr/FATAL:\s+citadel\s+has\s+encountered/, 'Calling logger with critical halts execution' );
lives_ok{ Citadel::logger({cat => 'w', msg => 'tests lol'}) } 'Calling logger with warn does not halt execution';
lives_ok{ Citadel::logger({cat => 'i', msg => 'tests lol'}) } 'Calling logger with info does not halt execution';

trap{ Citadel::do_exit({ death_type => 'noclean' }) };
is ( $trap->exit, 1, 'do_exit with noclean death_type exits with code 1' );
trap{ Citadel::do_exit({ death_type => 'lulz' }) };
is ( $trap->exit, 0, 'do_exit with non-noclean death_type exits 0' );
trap{ Citadel::do_exit() };
is ( $trap->exit, 0, 'do_exit with no death_type exits 0' );
lives_ok{ Citadel::run_sys_cmd({ cmd => 'sleep 1' }) } 'run_sys_cmd runs properly';

like(Citadel::get_fw_tool({ conf => $conf_file }), qr/iptables|apf|csf/, 'get_fw_tool returned expected');
like(Citadel::get_fw_tool_block_cmd({ conf => $conf_file }), qr/-j\s+DROP|apf\s+-d\s+|csf\s+-d\s+/, 'Got a valid block command');
like(Citadel::get_fw_tool_unblock_cmd({ conf => $conf_file }), qr/-D\s+INPUT|apf\s+-u\s+|csf\s+-dr\s+/, 'Got a valid unblock command');
like( Citadel::nslookup({ip =>'173.194.46.38'}), qr/\S+\.\S+/, 'nslookup of IP produced string');

mkpath('/var/spool/citadel') unless (-e '/var/spool/citadel');
unlink('/var/spool/citadel/bans') if (-e '/var/spool/citadel/bans');
is_deeply(
  Citadel::get_spool_data(),
  [], 'Properly got no spool entries when no spool file'
);
open(SPOOL, '>>', '/var/spool/citadel/bans') || die "Can't write [/var/spool/citadel/bans]: $!\n";
print SPOOL " 192.168.2.2\n#test comment\n192.168.2.3 \n192.168.2.4\n";
close(SPOOL);
is_deeply(
  Citadel::get_spool_data(),
  [
    '192.168.2.2',
    '192.168.2.3',
    '192.168.2.4',
  ], 'Properly got spool entries from spool file'
);
unlink('/var/spool/citadel/bans') if (-e '/var/spool/citadel/bans');

## Setup mocking for unblock_ip_exceeded_timeout
{
  *Citadel::get_spool_data = sub {
    return [
             '192.168.2.100  1442841334',
             '192.168.2.150  1442841634',
           ]
  };
  *Citadel::unban_ip = sub {return 1;};
}
Citadel::unblock_ip_exceeded_timeout();
is_deeply(
  \@Citadel::ban_expired_ips,
  [
    '192.168.2.100',
    '192.168.2.150',
  ], 'ban_expired_ips populated expired IP from spool'
);
# Now mock get_spool_data again, this time with entries for IPs that are
# not expired!
my $curtime = time;
{
  *Citadel::get_spool_data = sub {
    return [
             "192.168.2.100 $curtime",
             "192.168.2.150 $curtime",
           ]
  };
  *Citadel::unban_ip = sub {return 1;};
}
Citadel::unblock_ip_exceeded_timeout();
is_deeply(
  \%Citadel::banned_ips,
  {
    '192.168.2.100' => $curtime,
    '192.168.2.150' => $curtime,
  }, 'banned_ips looks right for non-expired IP from spool'
);

## Setup mocking for block_bad_ips
{
  %Citadel::int_config = (
    bad_ips => {
      '192.168.2.100' => 1,
      '192.168.2.150' => 1,
    },
    time => time,
  );
  *Citadel::ban_ip = sub {return 1;};
  *Citadel::logger = sub {return 1;};
}
Citadel::block_bad_ips();
is_deeply(
  \%Citadel::banned_ips,
  {
    '192.168.2.100' => $Citadel::int_config{time},
    '192.168.2.150' => $Citadel::int_config{time},
  }, 'banned_ips was populated from block_bad_ips'
);


if (ref Citadel::get_active_conns_by_ip() eq ref {}) {
  pass('get_active_conns_by_ip returned hashref');
}
else {
  fail('get_active_conns_by_ip returned hashref');
}

## Setup mocking for populate_bad_ips
{
  *Citadel::get_active_conns_by_ip = sub {
    return {
      '192.168.2.100' => 150,
      '192.168.2.101' => 151,
      '192.168.2.102' => 50,
      '192.168.2.103' => 1,
      '192.168.2.104' => 200,
      '192.168.2.105' => 203,
    };
  };
  $Citadel::int_config{bad_ips} = ();
}
$conf_file->{allowed_ips} = '192.168.2.100:192.168.2.101/32:127.0.0.1';
Citadel::populate_bad_ips({ conf => $conf_file });
is_deeply(
  $Citadel::int_config{bad_ips},
  {
    '192.168.2.104' => '200',
    '192.168.2.105' => '203',
  }, 'populate_bad_ips populated int_config{bad_ips} properly'
);
