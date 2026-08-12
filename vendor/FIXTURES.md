# vendor/FIXTURES.md

**Enumeration of upstream test-fixture credentials bundled in `vendor/`.**

Every file listed below is a test fixture from the upstream `hostap`
repository. They exist to let hostap's own automated test suite exercise
EAP-TLS / EAP-TTLS / EAP-PEAP / EAP-FAST / EAP-SIM handshakes and
similar wireless-auth flows.

**Nothing here is a production credential.** honeysnatch does not use
these files at runtime, does not include them in the wheel (see
`pyproject.toml` — `honeysnatch/data/` is packaged; `vendor/` is not),
and does not invoke the hostap test suite.

If your secret-scanner flags this directory, add the following globs
to its allowlist:

```
vendor/hostap_2_9/tests/hwsim/auth_serv/**
vendor/hostap_2_10/tests/hwsim/auth_serv/**
vendor/hostap_research/tests/hwsim/auth_serv/**
```

## Fixture directories (verified as of v0.1.2)

- `vendor/hostap_2_9/tests/hwsim/auth_serv/`
- `vendor/hostap_2_10/tests/hwsim/auth_serv/`
- `vendor/hostap_research/tests/hwsim/auth_serv/`

## Verification

To re-count the fixture credentials at any time:

```
find vendor -type f \( -name "*.key" -o -name "*.pem" \
                    -o -name "*.p12" -o -name "*.pfx" \
                    -o -name "*.crt" \) | wc -l
```

To confirm none of them are referenced from first-party Python:

```
grep -rF "vendor/hostap" honeysnatch/ --include="*.py"
```

Both should produce results consistent with "vendored test fixtures,
not referenced at runtime."

## Reference

Upstream hostap test-suite documentation:
https://w1.fi/cgit/hostap/tree/tests/hwsim/README
