# Constrained trust for the Russian Trusted Root CA

Trust a third-party CA for a **fixed list of domains only**, instead of for the
whole internet.

Installing `russian_trusted_root_ca.cer` normally lets that CA vouch for *any*
hostname. This setup narrows it: a cross-certificate carrying an X.509
`nameConstraints` extension is signed by a local root, and only that local root
is trusted. Chains from the Ministry's CA then validate for the permitted
domains and fail everywhere else with `permitted subtree violation`.

Currently permitted:

```
sberbank.ru  sbrf.ru  vtb.ru  alfabank.ru  gazprombank.ru  psb.ru  psbank.ru
```

---

## How it works

```
leaf (sberbank.ru)
  └─ Russian Trusted Sub CA          sent by the server
       └─ Russian Trusted Root CA    ← our cross-certificate, name-constrained
            └─ !Root to bypass…      ← our root, the only trusted anchor
```

The cross-certificate re-issues the Ministry's root under our own root, keeping
its Subject DN and public key byte-identical, and adds `nameConstraints`. Two
properties make it work:

- **Subject DN preserved** — the sub CA's `issuer` field must match it exactly,
  or chain building fails. The DN is copied from the original's parsed name rather
  than rebuilt from strings, which guarantees this.
- **SKI preserved** — the sub CA's `authorityKeyIdentifier` must match the
  cross-cert's `subjectKeyIdentifier`. Same public key ⇒ same hash, checked
  automatically on every re-sign.

No private key from the Ministry is needed: only its *public* key is re-signed,
copied verbatim out of its own self-signed certificate.

**Chrome and Edge don't need any of this.** They support
`CACertificatesWithConstraints` (Chrome 131+), which applies constraints to the
original certificate via policy. The cross-certificate exists for Firefox and
for system-wide trust. Both mechanisms are generated here; pick one.

---

## Layout

| Path | What |
|---|---|
| `roots/` | Foreign CA roots to constrain |
| `roots/retired/` | Roots no longer constrained |
| `constrained/` | One cross-certificate per root |
| `rucerts.toml` | Permitted domains and signing parameters |
| `myroot.pem` / `myroot.key` | Local root. **The key is the crown jewel.** |
| `src/`, `tests/`, `Cargo.toml` | The `rucerts` tool |
| `templates/` | Installer source (`.ps1`) and its `.cmd` wrapper, compiled into the binary |
| `backup-*/` | Automatic backups from `rucerts root set-cn` |
| `legacy/` | The superseded shell implementation, kept for reference |

Generated into the workspace, ready to install or share:

| File | Use |
|---|---|
| `install-certs.ps1` | **Self-contained** — certificates embedded, share this alone |
| `install-certs.cmd` | Double-clickable wrapper; send it alongside the `.ps1` |
| `myroot.crt` | Local root, for manual Firefox import |
| `*-constrained.crt` | Cross-certificates, for manual Firefox import |
| `*-original.crt` | Untouched originals, used for the safety check |
| `constrained-ca-policy.reg` | Chrome/Edge policy, uses the *original* root |

These are outputs: every one is rewritten from the certificates on each run, so edits to
them are lost. Edit the files in `templates/` and rebuild to change the installer.

---

## Commands

Everything is one binary. Build it once with `cargo build --release`; the examples
below assume `target/release/rucerts` is on your path.

Global flags: `--dir <workspace>` (defaults to the current directory) and
`--no-artifacts` to skip regenerating the installable files.

### Domains

```bash
rucerts domain add sberbank.ru            # add (accepts a pasted URL too)
rucerts domain remove gazprombank.ru      # remove
rucerts domain list
rucerts resign                            # re-sign all roots, no list change
rucerts artifacts                         # regenerate installable files only
```

Adding re-signs every cross-certificate and regenerates the artifacts. It fetches the
target's certificate and warns about **sibling SAN entries** — a leaf fails
unless *every* SAN name is permitted, which is why `sbrf.ru` is listed alongside
`sberbank.ru`.

Removal takes exact entries only; `www.psbank.ru` is covered by the `psbank.ru`
subtree, so remove the parent. It refuses to empty the list, and a batch that
would is rejected whole rather than applied partially.

### CA rotation

```bash
rucerts ca list                           # roots, key fingerprints, cross-cert status
rucerts ca add new_root.cer               # add a root, or detect a renewal
rucerts ca retire <name>                  # stop constraining one
```

Two cases, told apart by comparing public keys:

- **Same key, new dates** — nothing to do. The cross-certificate carries its own
  validity signed by your root, so chains keep working even past the original's
  expiry. Only the on-disk copy is refreshed.
- **New key** — added *alongside* the old one. Both stay constrained until sites
  finish migrating; retire the old one afterwards.

Input may be PEM or DER. Anything that is not a self-signed CA is rejected: an
intermediate cannot be cross-signed this way.

### Rename the local root

```bash
rucerts root set-cn "New Common Name"     # prompts before proceeding
rucerts root set-cn "New Common Name" -y
```

Mints a **new key pair**, re-signs everything, backs up the old material to
`backup-<timestamp>/`. The old root becomes orphaned — remove it from every
trust store and re-import. Cheap before install, disruptive after.

Non-ASCII names are stored as `UTF8String`; the 64-byte X.509 limit is checked in
bytes, not characters.

### Verify

```bash
rucerts verify
```

Four sections: extension inspection (critical flag, SKI, issuer, list
consistency across roots), live positive control against real sites, a
**negative control**, and the original roots' fingerprints for a trust-store
sweep. Exits non-zero if any check fails.

The negative control is the only step that proves anything. It builds a
throwaway cross-certificate in memory with the probe domain's names removed and
re-checks the same real leaf, requiring `permitted subtree violation`
specifically — not merely that validation failed. Without it, a certificate that
permits *everything* looks identical to a working one.

### Bootstrap a new workspace

```bash
rucerts init --cn "My Constraining Root"
rucerts ca add /path/to/some_root.cer
rucerts domain add example.com
```

### Install on Windows — `install-certs.ps1`

Windows client machines default to a `Restricted` execution policy, so a `.ps1` cannot be
started by double-clicking it. `install-certs.cmd` exists for that: `.cmd` files are not
policy-gated, and it invokes PowerShell with `-ExecutionPolicy Bypass` for that one
process, leaving the machine's policy alone. It also clears the zone marker that files
arriving by browser, mail or network share carry.

Double-clicked with no arguments it prints the certificates and thumbprints, then asks
before installing. Arguments pass straight through, so `install-certs.cmd -Machine` and
`install-certs.cmd -Uninstall` behave like the `.ps1` equivalents.

Running the `.ps1` directly still requires:

```powershell
powershell -ExecutionPolicy Bypass -File .\install-certs.ps1
```

```powershell
.\install-certs.ps1 -ShowOnly              # print certs + thumbprints, install nothing
.\install-certs.ps1                        # install into CurrentUser
.\install-certs.ps1 -Machine               # LocalMachine, needs elevation
.\install-certs.ps1 -WhatIf                # dry run
.\install-certs.ps1 -Export .\certs        # write .crt files out (for Firefox)
.\install-certs.ps1 -RemoveUnconstrained   # also delete an unconstrained original
.\install-certs.ps1 -Uninstall             # remove everything it installed
```

Puts `myroot` in **Root** and every cross-certificate in **Intermediate
Certification Authorities** — the split is the mechanism, not cosmetics. A
cross-certificate in `Root` becomes a trust anchor and defeats the design.

Certificates it installs are tagged via `FriendlyName` (`[constrained-ru]`), so
re-running finds and replaces its own earlier copies even after the root's CN
has changed. It aborts if a cross-certificate's issuer doesn't match the root,
and if an **unconstrained** original is trusted anywhere.

Windows raises its own warning dialog when a root certificate is added to
`CurrentUser\Root`. That prompt is the operating system asking whether you really mean to
grant a new trust anchor authority over your browsing, and it cannot be suppressed — nor
should it be. Installing with `-Machine` from an elevated shell writes to
`LocalMachine\Root` without it, but trades it for a UAC prompt: the same consent, asked
once instead of once per user.

---

## Workflows

### First install

```bash
rucerts verify                   # confirm the pair is sound before trusting it
rucerts artifacts                # ensure the installable files are current
```

Then on Windows:

```powershell
cd <workspace>
.\install-certs.ps1 -ShowOnly
.\install-certs.ps1
```

Restart Chrome and Edge. For Firefox:

```powershell
.\install-certs.ps1 -Export .\certs
```

`about:preferences#privacy` → View Certificates → **Authorities** → Import:

1. `myroot.crt` — check **"Trust this CA to identify websites"**
2. every `*-constrained.crt` — leave **all boxes unchecked**

The second is not a mistake. It is stored without trust bits and used only for
path building; its trust flows from `myroot.crt`. Restart Firefox.

### Chrome/Edge via policy instead

Run `constrained-ca-policy.reg` as admin, restart the browser, confirm at
`chrome://policy` that `CACertificatesWithConstraints` shows **OK**. This path
uses the *original* root and ignores the cross-certificate entirely — do not run
both mechanisms unless you want two places to update.

### Adding a domain

```bash
rucerts domain add newsite.ru    # watch for SAN warnings
```

Then re-run `install-certs.ps1` (Windows), or re-run the `.reg` and restart
(policy), or delete and re-import in Firefox. `myroot` never changes, so it is
imported exactly once, ever.

### Checking it still works

```bash
rucerts verify
```

In the browser, open a permitted site → padlock → certificate viewer → select
the top certificate. **Issued by** must read your root's CN. If the Russian root
appears self-issued, an unconstrained copy is trusted somewhere and the
constraint is being bypassed.

---

## Security notes

**`myroot.key` is the whole trust decision.** Anyone holding it can issue
certificates for the permitted domains that your browsers will accept. Keep it
`0600`, never distribute it, and never embed it. `rucerts root set-cn` backs it up in
plaintext under `backup-*/` — delete those once you're satisfied.

**Sharing `install-certs.ps1` asks people to trust *you*.** It embeds only
public certificates, but installing it makes your root an anchor on their
machine, and you hold the key. The constraints bound that to the permitted
domains — real, and worth stating — but they don't remove you as a trusted
party. Have recipients run `-ShowOnly` and check thumbprints out of band.

**One unconstrained copy voids everything.** If the original root is trusted
anywhere — Windows stores, `/usr/local/share/ca-certificates`, a Firefox
profile — path building routes around your cross-certificate and the constraints
enforce nothing. `install-certs.ps1` and `rucerts verify` both surface this. 
this. Never install `*-original.crt`; it exists only so the check has something
to compare against.

**Constraint types not listed are unconstrained.** `rucerts.toml` therefore
excludes IP, email, and URI explicitly, and the Chrome policy pins
`permitted_cidrs` to `127.0.0.1/32`. Removing those lines silently widens the
CA's authority to any bare-IP certificate.

---

## Troubleshooting

| Symptom | Cause |
|---|---|
| `permitted subtree violation` on a site you added | A sibling SAN isn't covered. Check the leaf's full SAN. |
| `unable to get local issuer certificate` | Server sent a sub CA you don't have, or the cross-cert isn't installed as an intermediate. |
| Site works but the constraint seems ignored | An unconstrained original is trusted. Check every store. |
| Chain breaks after a re-sign | SKI mismatch — `rucerts resign` aborts on this; don't bypass it. |
| Cyrillic root name shows as mojibake | A pre-Rust certificate. Re-run `rucerts root set-cn`. |
| `Access is denied` setting FriendlyName | Cosmetic only; the certificate installed fine. |
| Chrome policy shows "ignored" | Chrome older than 131, or the JSON is malformed. |

Manual chain check:

```bash
openssl s_client -connect sberbank.ru:443 -servername sberbank.ru -showcerts \
  </dev/null 2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > /tmp/chain.pem
csplit -s -z -f /tmp/c_ -b '%d.pem' /tmp/chain.pem '/BEGIN CERTIFICATE/' '{*}'
cat constrained/*.pem /tmp/c_1.pem > /tmp/unt.pem
openssl verify -CAfile myroot.pem -untrusted /tmp/unt.pem /tmp/c_0.pem
```

---

## Requirements

A Rust toolchain and OpenSSL development headers (`libssl-dev`) to build; the
resulting binary needs no `openssl` executable at runtime. Windows side:
PowerShell 5.1+, Chrome/Edge 131+ for the policy route. Staging assumes WSL with
the Windows drive mounted.

```bash
cargo build --release      # target/release/rucerts
cargo test                 # includes parity checks against the installed certificate
```

### Windows

Windows ships no system OpenSSL, so the `vendored` feature builds and statically links
it. That needs a C compiler, `perl` and `nasm` on PATH.

```powershell
cargo build --release --features vendored
```

Cross-compiling from WSL works too, and produces a standalone `.exe` with no DLL
dependencies:

```bash
rustup target add x86_64-pc-windows-gnu
sudo apt install mingw-w64 perl nasm
cargo build --release --target x86_64-pc-windows-gnu --features vendored
```

Running the tool on Windows is the more natural arrangement: everything it generates
lands in the workspace, and `install-certs.ps1` runs from right there.

One caveat: Windows has no mode bits, so `myroot.key` inherits its folder's ACL rather
than being forced to owner-only. Under `C:\Users\<you>\` that is already private; anywhere
else, the tool prints the `icacls` command to lock it down.

The `legacy/` directory holds the shell implementation this replaced, along with
the `cross.cnf` and OpenSSL CA database it used. Nothing reads them any more;
they are kept because this directory is not under version control. The shell
version copied its output to a separate Windows directory; the Rust tool writes
into the workspace instead, so any old copy of that directory is now orphaned.

It also holds `russian_trusted_sub_ca.cer`, a **superseded** Russian Trusted Sub
CA. Its Subject Key Identifier is `D1:E1:71:0D:…`, while the intermediate these
servers actually send today is `77:3D:D9:39:…` — the same Subject DN with a
different key. Do not install it. Servers supply their own intermediate during
the handshake, which is precisely why the *root* is cross-signed rather than the
sub CA: that choice survives sub-CA rotation without any action.
