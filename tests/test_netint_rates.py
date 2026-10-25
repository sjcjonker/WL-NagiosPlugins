"""Execute the real plugin with deterministic SNMP responses and history files."""
import os
from pathlib import Path
import subprocess
import tempfile
import time
import unittest

PLUGIN = Path(os.environ.get('NETINT_PLUGIN', Path(__file__).resolve().parents[1] / 'check_snmp_netint.pl'))
FAKE_SNMP = r'''package Net::SNMP;
sub session { return (bless({}, shift), undef); }
sub close { 1 }
sub get_table {
    my %r = ('1.3.6.1.2.1.2.2.1.2.1' => 'eth0');
    $r{'1.3.6.1.2.1.2.2.1.2.2'} = 'eth1' if $ENV{MULTI};
    return \%r;
}
sub get_request {
    my ($self, %args) = @_;
    my %r;
    for my $oid (@{$args{Varbindlist}}) {
        if ($ENV{MULTI} && $oid =~ /\.2$/) {
            (my $first = $oid) =~ s/\.2$/.1/;
            $r{$oid} = $self->get_request(Varbindlist => [$first])->{$first};
            $r{$oid} = 'noSuchObject' if $oid =~ /\.31\.1\.1\.1\.(?:6|10)\.2$/;
            $r{$oid} = 'eth1' if $oid eq '1.3.6.1.2.1.2.2.1.2.2';
            next;
        }
        $r{$oid} = 0;
        $r{$oid} = $ENV{LINK_STATUS} || 1 if $oid =~ /\.2\.2\.1\.[78]\.1$/;
        $r{$oid} = $ENV{IN_COUNTER} if $oid =~ /(?:\.31\.1\.1\.1\.6|\.2\.2\.1\.10)\.1$/;
        $r{$oid} = $ENV{OUT_COUNTER} if $oid =~ /(?:\.31\.1\.1\.1\.10|\.2\.2\.1\.16)\.1$/;
        for my $pair (['IN32','1.3.6.1.2.1.2.2.1.10.1'], ['OUT32','1.3.6.1.2.1.2.2.1.16.1'],
                      ['IN64','1.3.6.1.2.1.31.1.1.1.6.1'], ['OUT64','1.3.6.1.2.1.31.1.1.1.10.1']) {
            $r{$oid} = $ENV{$pair->[0]} if $oid eq $pair->[1] && exists($ENV{$pair->[0]});
        }
        $r{$oid} = 'eth0' if $oid eq '1.3.6.1.2.1.2.2.1.2.1';
        $r{$oid} = $ENV{LINK_SPEED} if $oid eq '1.3.6.1.2.1.2.2.1.5.1';
        $r{$oid} = int($ENV{LINK_SPEED}/1000000) if $oid eq '1.3.6.1.2.1.31.1.1.1.15.1';
        $r{$oid} = $ENV{DISCARD_OUT} || 0 if $oid eq '1.3.6.1.2.1.2.2.1.19.1';
    }
    return \%r;
}
1;
'''


class NetintRateTests(unittest.TestCase):
    def run_check(self, rows, incoming, outgoing, *, high=True, speed=1000000000,
                  extended=False, discard=0, status=1, previous_perf=False, rate_output=True,
                  auto=False, counters=None, minimized=False, previous_bits=None, multi=False, automatic=False, snmp_port=161, unsafe_state=None, hostname="fixture.invalid"):
        with tempfile.TemporaryDirectory() as directory:
            root = Path(directory)
            (root / 'Net').mkdir()
            (root / 'Net/SNMP.pm').write_text(FAKE_SNMP)
            history = root / 'history'
            now = int(time.time())
            samples = [[now + row[0], *row[1:]] for row in rows]
            history.write_text(''.join(':'.join(map(str, row)) + '\n' for row in samples))
            env = {**os.environ, 'PERL5LIB': str(root), 'IN_COUNTER': str(incoming),
                   'OUT_COUNTER': str(outgoing), 'LINK_SPEED': str(speed),
                   'DISCARD_OUT': str(discard), 'LINK_STATUS': str(status)}
            env.update({key: str(value) for key, value in (counters or {}).items()})
            env['MULTI'] = '1' if multi else ''
            args = ['perl', '-w', str(PLUGIN), '-H', hostname, '-C', 'fixture',
                    '-2', '-n', 'eth0', '-r', '-k', '-f', '--label', '-z']
            if rate_output:
                args += ['-Y']
            if previous_perf:
                stamp, cin, cout = samples[-1]
                args += ['-P', f"'eth0_in_octet'={cin}c 'eth0_out_octet'={cout}c ptime={stamp}", '-T', str(stamp)]
                if previous_bits is not None:
                    args[-3] += f" 'eth0_counter_bits'={previous_bits}"
            elif automatic:
                args += ['--state-dir', str(root), '-p', str(snmp_port)]
            else:
                args += ['-F', str(history)]
            victim = root / 'victim'
            if unsafe_state:
                victim.write_text('do not overwrite\n')
                if unsafe_state == 'lock':
                    history.with_name('history.lock').symlink_to(victim)
                elif unsafe_state == 'history':
                    history.unlink()
                    history.symlink_to(victim)
                elif unsafe_state == 'directory':
                    root.chmod(0o777)
                    args += ['--state-dir', str(root)]
                    pos=args.index('-F'); del args[pos:pos+2]
            if high:
                args += ['-g']
            if extended:
                args += ['-q', '-e']
            if auto:
                args += ['--autocounters']
            if minimized:
                args += ['-m']
            if multi:
                args.remove('-r')
                args[args.index('-n') + 1] = 'eth'
                args.remove('-k')
                if '-Y' in args:
                    args.remove('-Y')
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.stderr, '', result.stderr)
            if unsafe_state:
                self.assertEqual(victim.read_text(), 'do not overwrite\n')
            if automatic:
                files=[p for p in root.glob('int.*') if not p.name.endswith('.lock')]
                self.assertEqual(len(files),1)
                self.assertRegex(files[0].name,r'^int\.[0-9a-f]{64}$')
                self.last_history_name = files[0].name
                self.assertEqual(files[0].stat().st_mode & 0o777,0o600)
                return result, files[0].read_text()
            return result, history.read_text()

    def test_idle_zero_counters_are_valid(self):
        for previous_perf in (False, True):
            result, _ = self.run_check([[-600, 0, 0]], 0, 0, previous_perf=previous_perf)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('in=0.0KBps/out=0.0KBps', result.stdout)
            self.assertIn("'eth0_in_Bps'=0", result.stdout)

    def test_64_bit_reset_drops_old_baseline_and_recovers(self):
        result, history = self.run_check([[-600, 100000, 100000]], 100, 200)
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn('counter discontinuity', result.stdout)
        self.assertEqual(len(history.splitlines()), 1)
        self.assertNotIn('300239', result.stdout)
        self.assertNotIn("'eth0_in_Bps'", result.stdout)
        result, _ = self.run_check([[-600, 100, 200]], 614500, 614600)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('in=1.0KBps/out=1.0KBps', result.stdout)

    def test_32_bit_wrap_is_preserved(self):
        result, _ = self.run_check([[-600, 4294967200, 4294967200]], 614304, 614304, high=False)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('in=1.0KBps/out=1.0KBps', result.stdout)

    def test_impossible_positive_jump_is_rejected(self):
        result, history = self.run_check([[-600, 100, 200]], 10**14, 201)
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertEqual(len(history.splitlines()), 1)

    def test_unknown_speed_accepts_monotonic_counters(self):
        result, _ = self.run_check([[-600, 100, 200]], 614500, 614600, speed=0)
        self.assertEqual(result.returncode, 0, result.stdout)

    def test_missing_counters_do_not_reuse_history(self):
        result, history = self.run_check([[-1200, 100, 100], [-600, 200, 200]], 'noSuchInstance', 300)
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn('missing or invalid counters', result.stdout)
        self.assertEqual(history, '')

    def test_duplicate_and_future_timestamps_rebuild_baseline(self):
        for rows in ([[-600, 100, 100], [-600, 200, 200]], [[600, 100, 100]]):
            result, history = self.run_check(rows, 300, 300)
            self.assertNotIn('300239', result.stdout)
            self.assertLessEqual(len(history.splitlines()), 2)

    def test_extended_idle_traffic_still_checks_discards(self):
        result, _ = self.run_check([[-600, 100, 100, 0, 0, 0, 0]], 100, 100, extended=True, discard=100)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('discard-out=10.0', result.stdout)

    def test_down_status_remains_critical(self):
        result, _ = self.run_check([], 0, 0, status=2)
        self.assertEqual(result.returncode, 2, result.stdout)

    def test_initial_sample_is_unknown(self):
        result, history = self.run_check([], 0, 0)
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn('waiting for rate samples', result.stdout)
        self.assertEqual(len(history.splitlines()), 1)

    def test_idle_intervals_contribute_to_average(self):
        result, _ = self.run_check([[-600, 0, 0], [-400, 204800, 204800],
                                    [-200, 204800, 204800]], 204800, 204800)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('in=0.5KBps/out=0.5KBps', result.stdout)

    def test_zero_to_positive_is_valid(self):
        result, _ = self.run_check([[-600, 0, 0]], 614400, 614400)
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('in=1.0KBps/out=1.0KBps', result.stdout)

    def test_impossible_32_bit_wrap_is_rejected_on_slow_link(self):
        result, _ = self.run_check([[-600, 1000, 1000]], 1, 1000, high=False, speed=1000000)
        self.assertEqual(result.returncode, 3, result.stdout)

    def test_reset_without_known_speed_is_still_rejected(self):
        result, _ = self.run_check([[-600, 1000, 1000]], 1, 1000, speed=0)
        self.assertEqual(result.returncode, 3, result.stdout)

    def test_error_counter_reset_rebuilds_baseline(self):
        result, _ = self.run_check([[-600, 1000, 1000, 100, 0, 0, 0]],
                                   2000, 2000, extended=True)
        self.assertEqual(result.returncode, 3, result.stdout)

    def test_rate_bound_also_applies_without_perfspeed_output(self):
        result, _ = self.run_check([[-600, 100, 200]], 10**14, 201, rate_output=False)
        self.assertEqual(result.returncode, 3, result.stdout)

    def test_auto_prefers_64_when_both_pairs_exist(self):
        result, history = self.run_check([[-600, 0, 0, 64]], 614400, 614400, auto=True,
                                         counters={'IN32': 0, 'OUT32': 0})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('counters=64-bit', result.stdout)
        self.assertIn('in=1.0KBps/out=1.0KBps', result.stdout)
        self.assertTrue(history.splitlines()[-1].endswith(':64'))

    def test_auto_only_32_with_unknown_link_speed(self):
        for minimized in (False, True):
            result, _ = self.run_check([[-600, 0, 0, 32]], 0, 0, auto=True, speed=0,
                                       counters={'IN64': 'noSuchObject', 'OUT64': 'noSuchObject'},
                                       minimized=minimized)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('counters=32-bit', result.stdout)
            self.assertIn('in=0.0KBps/out=0.0KBps', result.stdout)
            self.assertNotIn('noSuchObjectc', result.stdout)

    def test_auto_only_64(self):
        result, _ = self.run_check([[-600, 0, 0, 64]], 0, 0, auto=True, high=False,
                                   counters={'IN32': 'noSuchInstance', 'OUT32': 'noSuchInstance'})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('counters=64-bit', result.stdout)

    def test_auto_requires_complete_pair_and_does_not_mix_widths(self):
        result, _ = self.run_check([], 0, 0, auto=True,
                                   counters={'IN64': 100, 'OUT64': 'noSuchObject',
                                             'IN32': 'noSuchObject', 'OUT32': 100})
        self.assertEqual(result.returncode, 3, result.stdout)
        self.assertIn('counters=unavailable', result.stdout)
        self.assertNotIn('noSuchObjectc', result.stdout)

    def test_auto_partial_64_pair_falls_back_to_complete_32_pair(self):
        result, _ = self.run_check([[-600, 0, 0, 32]], 0, 0, auto=True,
                                   counters={'OUT64': 'noSuchObject'})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('counters=32-bit', result.stdout)

    def test_auto_width_switch_and_legacy_history_rebuild(self):
        for row in ([-600, 100, 100, 32], [-600, 100, 100]):
            result, history = self.run_check([row], 614500, 614500, auto=True, counters={'IN32': 0, 'OUT32': 0})
            self.assertEqual(result.returncode, 3, result.stdout)
            self.assertEqual(len(history.splitlines()), 1)
            self.assertTrue(history.strip().endswith(':64'))

    def test_auto_perfdata_history_requires_same_width(self):
        for previous_bits, expected in ((64, 0), (32, 3), (None, 3)):
            result, _ = self.run_check([[-600, 0, 0]], 0, 0, auto=True,
                                       previous_perf=True, previous_bits=previous_bits, counters={'IN32': 'noSuchObject', 'OUT32': 'noSuchObject'})
            self.assertEqual(result.returncode, expected, result.stdout)

    def test_auto_selects_different_widths_per_interface(self):
        result, _ = self.run_check([], 1, 2, auto=True, multi=True, counters={'IN32': 0, 'OUT32': 0})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('eth0:UP [counters=64-bit]', result.stdout)
        self.assertIn('eth1:UP [counters=32-bit]', result.stdout)



    def test_mirrored_hc_uses_32_bit_and_survives_wrap(self):
        # Both UNVRs expose HC octets identical to Counter32 octets.
        for high in (True, False):
            result, history = self.run_check([[-600, 4294967200, 4294967200, 32]],
                                             614304, 614304, auto=True, high=high)
            self.assertEqual(result.returncode, 0, result.stdout)
            self.assertIn('counters=32-bit', result.stdout)
            self.assertIn('in=1.0KBps/out=1.0KBps', result.stdout)
            self.assertEqual(len(history.splitlines()),2)

    def test_true_hc_above_32_bit_limit_remains_64(self):
        result, _ = self.run_check([[-600, 4294967200, 4294967200, 64]],
                                   4295581600, 4295581600, auto=True,
                                   counters={'IN32': 614304, 'OUT32': 614304})
        self.assertEqual(result.returncode, 0, result.stdout)
        self.assertIn('counters=64-bit',result.stdout)

    def test_automatic_private_history_without_F(self):
        result, history = self.run_check([], 1, 2, automatic=True)
        self.assertEqual(result.returncode,3,result.stdout)
        self.assertEqual(len(history.splitlines()),1)

    def test_state_symlinks_are_not_followed(self):
        for attack in ('lock','history','directory'):
            result,_=self.run_check([],1,2,unsafe_state=attack)
            self.assertEqual(result.returncode,3,result.stdout)


    def test_automatic_paths_separate_hosts_and_forwarded_ports(self):
        names=[]
        for hostname, port in (('192.168.7.140',1161),('192.168.7.140',1163),('192.168.7.141',1161),('../../untrusted host',1161)):
            self.run_check([],1,2,automatic=True,snmp_port=port,hostname=hostname)
            names.append(self.last_history_name)
        self.assertEqual(len(set(names)),4)

if __name__ == '__main__':
    unittest.main()

