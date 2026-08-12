# vendor/ — Third-party source trees

**Provenance and licensing for every subdirectory under `vendor/`.**

This directory contains upstream C source code that honeysnatch's live
isolation testing depends on. The Python package is fully independent
of `vendor/`; it is used only when the operator opts in to live
on-air isolation tests (`fhs isolation build && fhs isolation run-all …`).

Review finding HS-09 remediation: this file exists so downstream users
and security scanners can distinguish first-party code from vendored
upstream, and legitimate test fixtures from real credentials.

## Trees

| Directory | Upstream | Version | License | Used by |
|---|---|---|---|---|
| `hostap_2_10/` | https://w1.fi/hostap.git | 2.10 (2022-01-16) | BSD-3-Clause | Default build target (`fhs isolation build`) |
| `hostap_2_9/`  | https://w1.fi/hostap.git | 2.9 (2019-08-07)  | BSD-3-Clause | Legacy build target, kept for reproducing older results |
| `hostap_research/` | AirSnitch reference tree (Mathy Vanhoef, NDSS'26) | research snapshot | BSD-3-Clause | Reference-only, NOT built by default; see `port_restoration/*.py` docstrings |
| `setup/` | first-party | — | MIT (repo LICENSE) | Bridge/hwsim setup shell scripts |
| `wpaspy.py` | Shim reexporting `hostap_2_10/wpaspy/` | — | BSD-3-Clause | Runtime control-interface client |

## Local modifications

To recover any local diff from the upstream 2.10 release:

```
git clone -b 'hostap_2_10' --single-branch --depth 1 \
    git://w1.fi/srv/git/hostap.git hostap_2_10_original
diff -ur hostap_2_10_original/ hostap_2_10/ -x '*.d' -x '*.o' -x '*.service' \
    | grep -v "Only in" > diff.patch
```

If a downstream fork adds patches at build time, they belong under
`vendor/<tree>/patches/` alongside a PATCH-MANIFEST.md so scanners can
correlate. honeysnatch itself currently does not apply patches to the
vendored trees at build time — the shipped source IS the source that
gets compiled.

## Bundled test-fixture credentials

The hostap upstream ships extensive test fixtures under
`vendor/hostap_2_9/tests/hwsim/auth_serv/`,
`vendor/hostap_2_10/tests/hwsim/auth_serv/`,
`vendor/hostap_research/tests/hwsim/auth_serv/`, and similar. These
directories contain `.key`, `.pem`, `.p12`, `.pfx` files used by the
hostap unit-test suite to exercise EAP-TLS, EAP-TTLS, EAP-PEAP, and
related handshakes.

**These are UPSTREAM TEST FIXTURES, NOT PRODUCTION CREDENTIALS.**

They are:

- Public in the upstream hostap repository since at least 2010.
- Documented by hostap upstream as fixtures.
- Not used by honeysnatch at runtime — only by hostap's own test suite,
  which honeysnatch does not invoke.

See `vendor/FIXTURES.md` for the enumerated fixture directories, so
automated secret-scanning tools can be configured with an allowlist.

## SBOM

A minimal SBOM for the first-party Python surface should be generated
at release time via `pip freeze > sbom-python.txt` in a clean venv
built from `requirements.txt` (which pins minimums; a production
release should convert those to `==` pins via `pip-compile`). The C
surface (hostap) is not currently SBOM'd — that work belongs to a
follow-up release once vendored trees are formally pinned to a fork
with recorded upstream commits and any local patches.

## Legacy Libwifi note

[Libwifi](https://github.com/vanhoefm/libwifi) is an experimental
Wi-Fi library referenced by earlier honeysnatch prototypes. It is
still pullable via `git submodule init && git submodule update` but is
not required by the current runtime.
