#!/usr/bin/env bash
# Manage the permitted-domain list, re-sign every name-constrained cross-certificate,
# and refresh the Windows staging copies (certs + Chrome/Edge policy .reg).
#
# Usage: ./add-domain.sh newsite.ru [more.ru ...]   add domains
#        ./add-domain.sh --remove old.ru [...]      remove domains
#        ./add-domain.sh --resign                   re-sign without changing domains
#        ./add-domain.sh --restage                  stage only
#
# Every certificate in roots/ is cross-signed under myroot.pem with the same
# constraints, so a CA key rotation is handled by dropping the new root in
# alongside the old one (see update-ca.sh).
#
# STAGE_DIR overrides where the Windows copies land; set it empty to skip staging.
set -euo pipefail
cd "$(dirname "$0")"

STAGE_DIR=${STAGE_DIR-/mnt/c/Users/umatrix/certsru}
DAYS_CROSS=2000

usage() {
    echo "usage: $0 <domain> [domain...]      add domains, re-sign, stage" >&2
    echo "       $0 --remove <domain> [...]   remove domains, re-sign, stage" >&2
    echo "       $0 --resign                  re-sign all roots, stage" >&2
    echo "       $0 --restage                 stage only, no re-sign" >&2
    exit 1
}
[ $# -ge 1 ] || usage

# One-time migration from the original single-root layout.
if [ ! -d roots ]; then
    mkdir -p roots
    if [ -f russian_trusted_root_ca.cer ]; then
        mv russian_trusted_root_ca.cer roots/
        echo "migrated russian_trusted_root_ca.cer -> roots/"
    fi
fi
mkdir -p constrained

roots() {  # every foreign root we constrain
    local f found=0
    for f in roots/*.cer roots/*.pem roots/*.crt; do
        [ -e "$f" ] || continue
        printf '%s\n' "$f"; found=1
    done
    [ "$found" = 1 ] || { echo "no certificates in roots/" >&2; return 1; }
}

covered() {  # covered <name> -- is <name> inside an existing permitted subtree?
    local name=$1 p
    while read -r p; do
        [ -z "$p" ] && continue
        [ "$name" = "$p" ] && return 0
        case "$name" in *".$p") return 0 ;; esac
    done < <(sed -n 's/^permitted;DNS\.[0-9]*[[:space:]]*=[[:space:]]*//p' cross.cnf)
    return 1
}

resign() {
    local r base out
    while read -r r; do
        base=$(basename "$r"); base=${base%.*}
        out="constrained/${base}.pem"
        rm -f "$out"
        openssl ca -config cross.cnf -batch -notext -days "$DAYS_CROSS" \
            -cert myroot.pem -keyfile myroot.key \
            -ss_cert "$r" -out "$out" >/dev/null 2>&1

        # The cross-cert must keep the original's Subject Key Identifier, or the
        # sub CA's authorityKeyIdentifier stops matching and chains fail to build.
        local a b
        a=$(openssl x509 -in "$r"   -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')
        b=$(openssl x509 -in "$out" -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')
        if [ "$a" != "$b" ]; then
            echo "ERROR: SKI changed for $base ($a -> $b)" >&2; exit 1
        fi
        echo "signed $out  (SKI $b)"
    done < <(roots)

    echo
    openssl x509 -in "$(roots | head -1 | sed 's|roots/|constrained/|; s|\.[^.]*$|.pem|')" \
        -noout -ext nameConstraints
    echo
    stage
    echo
    echo "Now re-import in whichever store you use:"
    echo "  certmgr.msc : run install-certs.ps1 again (it replaces old copies)"
    echo "  policy      : re-run constrained-ca-policy.reg as admin, restart Chrome/Edge"
    echo "  Firefox     : delete the old certs under Authorities, import the new ones with NO trust bits"
    echo "myroot.crt is unchanged unless set-root-cn.sh was run."
}

stage() {
    if [ -z "$STAGE_DIR" ]; then
        echo "staging skipped (STAGE_DIR empty)"; return 0
    fi
    if [ ! -d "$STAGE_DIR" ]; then
        echo "staging skipped: $STAGE_DIR not present (not on this machine?)"; return 0
    fi

    # Drop stale per-root files so a removed root does not linger in the store,
    # plus the single-root layout's filenames from before the roots/ refactor.
    rm -f "$STAGE_DIR"/*-constrained.crt "$STAGE_DIR"/*-original.crt \
          "$STAGE_DIR/russian-root-constrained.crt" "$STAGE_DIR/russian_trusted_root_ca.crt"
    cp myroot.pem "$STAGE_DIR/myroot.crt"

    local r base
    while read -r r; do
        base=$(basename "$r"); base=${base%.*}
        cp "$r"                        "$STAGE_DIR/${base}-original.crt"
        cp "constrained/${base}.pem"   "$STAGE_DIR/${base}-constrained.crt"
    done < <(roots)

    # Self-contained installer: the staged install-certs.ps1 carries the
    # certificates inline, so it can be shared as a single file.
    if [ -f install-certs.ps1 ]; then
        python3 - "$STAGE_DIR" <<'PY'
import glob, os, re, sys

stage = sys.argv[1]
src = open('install-certs.ps1', encoding='utf-8').read()

def body(path):
    m = re.findall(r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
                   open(path).read(), re.S)
    if not m:
        sys.exit(f'not a PEM certificate: {path}')
    b = ''.join(m[0].split())
    return '\n'.join(b[i:i + 76] for i in range(0, len(b), 76))

entries = [("myroot", "root", body('myroot.pem'))]
for path in sorted(p for ext in ('cer', 'pem', 'crt')
                   for p in glob.glob(f'roots/{"*"}.{ext}') if os.path.isfile(p)):
    base = os.path.splitext(os.path.basename(path))[0]
    cross = f'constrained/{base}.pem'
    if not os.path.exists(cross):
        sys.exit(f'missing cross-certificate for {path}')
    entries.append((base, 'constrained', body(cross)))
    entries.append((base, 'original',    body(path)))

block = []
for name, kind, b64 in entries:
    block.append("@{Name='%s';Kind='%s';B64=@'" % (name, kind))
    block.append(b64)
    block.append("'@}")

if '#<<<EMBEDDED>>>' not in src:
    sys.exit('install-certs.ps1 has no #<<<EMBEDDED>>> marker')
out = src.replace('#<<<EMBEDDED>>>', '\n'.join(block))

# UTF-8 with BOM so Windows PowerShell 5.1 reads the Cyrillic names correctly.
with open(f'{stage}/install-certs.ps1', 'w', encoding='utf-8-sig', newline='\r\n') as fh:
    fh.write(out)
print(f'embedded {len(entries)} certificate(s) into install-certs.ps1')
PY
    fi

    # Chrome/Edge policy: one entry per root, constraints read back out of the
    # SIGNED certs so the policy cannot drift from the cross-certificates.
    python3 - "$STAGE_DIR" <<'PY'
import glob, json, os, re, subprocess, sys

stage = sys.argv[1]
entries = []
names = None

# Match the shell's roots(): certificate files only, never roots/retired/.
paths = sorted(p for ext in ('cer', 'pem', 'crt')
               for p in glob.glob(f'roots/*.{ext}') if os.path.isfile(p))

for path in paths:
    base = os.path.splitext(os.path.basename(path))[0]
    cross = f'constrained/{base}.pem'
    if not os.path.exists(cross):
        sys.exit(f'missing cross-certificate for {path}')

    b64 = ''.join(re.findall(
        r'-----BEGIN CERTIFICATE-----(.*?)-----END CERTIFICATE-----',
        open(path).read(), re.S)[0].split())

    txt = subprocess.run(['openssl', 'x509', '-in', cross, '-noout',
                          '-ext', 'nameConstraints'],
                         capture_output=True, text=True, check=True).stdout
    found = re.findall(r'DNS:(\S+)', txt)
    if not found:
        sys.exit(f'no permitted DNS names in {cross} -- refusing to write policy')
    names = found
    entries.append({"certificate": b64,
                    "constraints": {"permitted_dns_names": found,
                                    "permitted_cidrs": ["127.0.0.1/32"]}})

if not entries:
    sys.exit('no roots found -- refusing to write policy')

reg = ['Windows Registry Editor Version 5.00', '']
for vendor in (r'Google\Chrome', r'Microsoft\Edge'):
    reg.append(rf'[HKEY_LOCAL_MACHINE\SOFTWARE\Policies\{vendor}\CACertificatesWithConstraints]')
    for i, obj in enumerate(entries, start=1):
        esc = json.dumps(obj, separators=(',', ':')).replace('\\', '\\\\').replace('"', '\\"')
        reg.append(f'"{i}"="{esc}"')
    reg.append('')

with open(f'{stage}/constrained-ca-policy.reg', 'w', encoding='utf-16') as fh:
    fh.write('\r\n'.join(reg))
print(f"staged {len(entries)} root(s), domains:", ', '.join(names))
PY
    echo "staged -> $STAGE_DIR"
}

case $1 in
    --restage)
        [ $# -eq 1 ] || usage
        stage
        exit 0 ;;
    --resign)
        [ $# -eq 1 ] || usage
        resign
        exit 0 ;;
    --remove)
        shift
        [ $# -ge 1 ] || usage
        removed=0
        for d in "$@"; do
            case $d in -*) usage ;; esac
            d=${d#*://}; d=${d%%/*}
            line=$(grep -n "^permitted;DNS\.[0-9]*[[:space:]]*=[[:space:]]*${d}\$" cross.cnf | cut -d: -f1 || true)
            if [ -z "$line" ]; then
                echo "skip   $d (not an exact entry; subtree parents must be removed by name)"
                continue
            fi
            # Refuse to empty the list: a cross-cert permitting no DNS name at all
            # rejects every host, which looks like a broken chain rather than a policy.
            remaining=$(grep -c '^permitted;DNS\.' cross.cnf)
            if [ "$remaining" -le 1 ]; then
                echo "refusing to remove the last permitted domain -- the cert would trust nothing" >&2
                exit 1
            fi
            sed -i "${line}d" cross.cnf
            echo "remove $d"
            removed=1
        done
        [ "$removed" = 1 ] || { echo "nothing removed"; exit 0; }
        resign
        echo
        echo "Removal takes effect only after re-import; browsers keep the old certs until then."
        exit 0 ;;
    -*) usage ;;
esac

added=0
for d in "$@"; do
    case $d in -*) usage ;; esac
    d=${d#*://}; d=${d%%/*}          # tolerate a pasted URL
    if covered "$d"; then
        echo "skip   $d (already inside a permitted subtree)"
    else
        n=$(sed -n 's/^permitted;DNS\.\([0-9]*\).*/\1/p' cross.cnf | sort -n | tail -1)
        n=$((n + 1))
        last=$(grep -n '^permitted;DNS\.' cross.cnf | tail -1 | cut -d: -f1)
        sed -i "${last}a permitted;DNS.${n}  = ${d}" cross.cnf
        echo "add    $d  (permitted;DNS.${n})"
        added=1
    fi

    # Warn about sibling SANs -- one uncovered name fails the whole leaf.
    san=$(timeout 12 openssl s_client -connect "$d:443" -servername "$d" </dev/null 2>/dev/null \
          | openssl x509 -noout -ext subjectAltName 2>/dev/null \
          | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ' || true)
    for s in $san; do
        covered "${s#\*.}" || echo "  WARNING: leaf also carries SAN '$s' -- not covered, add it too"
    done
done

if [ "$added" = 0 ]; then
    echo "no domains added; re-staging anyway to keep copies in sync"
    stage
    exit 0
fi

resign
