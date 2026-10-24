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
sub get_table { return {'1.3.6.1.2.1.2.2.1.2.1' => 'eth0'}; }
sub get_request {
    my ($self, %args) = @_;
    my %r;
    for my $oid (@{$args{Varbindlist}}) {
        $r{$oid} = 0;
        $r{$oid} = $ENV{LINK_STATUS} || 1 if $oid =~ /\.2\.2\.1\.[78]\.1$/;
        $r{$oid} = $ENV{IN_COUNTER} if $oid =~ /(?:\.31\.1\.1\.1\.6|\.2\.2\.1\.10)\.1$/;
        $r{$oid} = $ENV{OUT_COUNTER} if $oid =~ /(?:\.31\.1\.1\.1\.10|\.2\.2\.1\.16)\.1$/;
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
                  extended=False, discard=0, status=1, previous_perf=False, rate_output=True):
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
            args = ['perl', '-w', str(PLUGIN), '-H', 'fixture.invalid', '-C', 'fixture',
                    '-2', '-n', 'eth0', '-r', '-k', '-f', '--label', '-z']
            if rate_output:
                args += ['-Y']
            if previous_perf:
                stamp, cin, cout = samples[-1]
                args += ['-P', f"'eth0_in_octet'={cin}c 'eth0_out_octet'={cout}c ptime={stamp}", '-T', str(stamp)]
            else:
                args += ['-F', str(history)]
            if high:
                args += ['-g']
            if extended:
                args += ['-q', '-e']
            result = subprocess.run(args, env=env, capture_output=True, text=True, timeout=5)
            self.assertEqual(result.stderr, '', result.stderr)
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


if __name__ == '__main__':
    unittest.main()
