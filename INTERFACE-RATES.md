# Interface rate corrections

This fork retains the upstream license and attribution. Its interface plugin
starts from `willixix/WL-NagiosPlugins` commit
`4011ea1507eefa35a07ee11a3035a276d6c1fae0`.

`check_snmp_netint.pl -k` now validates history before calculating rates:

- A decreasing 64-bit counter starts a new baseline rather than adding 2^64.
- 32-bit byte-counter wraps remain supported. Without a known link speed,
  a 32-bit reset cannot reliably be distinguished from a wrap.
- Known positive link speeds bound each direction independently, allowing
  10% sampling skew. Unknown/zero speeds skip this bound. Misreported speeds
  can therefore cause unavailable rates and should be corrected on the agent.
- Invalid/missing counters, non-increasing timestamps and implausible jumps
  discard history through that discontinuity; file history repairs itself.
- Idle intervals, including counters at zero, are valid measurements and
  contribute zero to the average. Both discard directions are averaged.
- With `-k`, unavailable rates now report UNKNOWN instead of OK (unless an
  existing warning/critical condition already takes precedence). Initial
  collection and rebuilding need enough samples for the configured `-d`
  measurement window. Interface-down checks continue to report CRITICAL.

No history deletion, SNMP agent changes or new runtime dependencies are needed.
Other plugins in this repository are unchanged.

Run the executable regression tests (Python 3 and Perl):

```sh
python3 -m unittest discover -s tests -p test_netint_rates.py -v
perl -c check_snmp_netint.pl
```

Tests execute the actual plugin with a fake Net::SNMP module and isolated
history files. They make no network calls. Production still uses Net::SNMP.
