#!/usr/bin/env bash
# Regenerate the constraining root under a new Common Name, re-sign the
# name-constrained cross-certificate against it, and refresh the staging copies.
#
# Usage: ./set-root-cn.sh "Constrained Russian CA (local, do not delete)" [-y]
#
# This mints a NEW key pair. The old root becomes useless: anything already
# importing it must be re-imported. Old files are backed up, never overwritten
# in place.
set -euo pipefail
cd "$(dirname "$0")"

DAYS_ROOT=3650
DAYS_CROSS=2000

assume_yes=0
cn=""
for a in "$@"; do
    case $a in
        -y|--yes) assume_yes=1 ;;
        -*) echo "unknown option: $a" >&2; exit 1 ;;
        *) [ -z "$cn" ] || { echo "give exactly one CN (quote it)" >&2; exit 1; }; cn=$a ;;
    esac
done

[ -n "$cn" ] || { echo 'usage: '"$0"' "New Common Name" [-y]' >&2; exit 1; }
case $cn in
    */*) echo "CN must not contain '/' -- it terminates the DN field" >&2; exit 1 ;;
    *=*) echo "CN must not contain '=' -- pass the name only, not a full DN" >&2; exit 1 ;;
esac
cn_bytes=$(printf '%s' "$cn" | wc -c)
[ "$cn_bytes" -le 64 ] || { echo "CN is $cn_bytes bytes -- X.509 upper bound is 64" >&2; exit 1; }

[ -f cross.cnf ] || { echo "missing required file: cross.cnf" >&2; exit 1; }
ls roots/* >/dev/null 2>&1 || { echo "no certificates in roots/ -- add one with ./update-ca.sh" >&2; exit 1; }

if [ -f myroot.pem ]; then
    echo "current root : $(openssl x509 -in myroot.pem -noout -subject | sed 's/^subject=//')"
fi
echo "new root     : CN = $cn"
echo
echo "This mints a new key pair and re-signs the cross-certificate."
echo "Any trust store already holding the old root must be updated:"
echo "  - remove the old root, import the new myroot.crt"
echo "  - replace russian-root-constrained.crt (its issuer changes)"

if [ "$assume_yes" = 0 ]; then
    printf 'Proceed? [y/N] '
    read -r reply
    case $reply in [yY]|[yY][eE][sS]) ;; *) echo "aborted"; exit 1 ;; esac
fi

# ---- back up anything we are about to replace --------------------------------
backup="backup-$(date +%Y%m%d-%H%M%S)"
mkdir -p "$backup"
for f in myroot.key myroot.pem index.txt index.txt.attr serial; do
    [ -f "$f" ] && cp -p "$f" "$backup/"
done
for d in newcerts constrained; do
    [ -d "$d" ] && cp -rp "$d" "$backup/" 2>/dev/null || true
done
echo "backed up -> $backup/"

# ---- new root ----------------------------------------------------------------
# -utf8 is required: without it openssl reads -subj as 8-bit and re-encodes each
# byte as a codepoint, producing double-encoded mojibake for non-ASCII names.
openssl req -x509 -utf8 -newkey rsa:4096 -nodes -days "$DAYS_ROOT" \
    -keyout myroot.key -out myroot.pem -subj "/CN=$cn" 2>/dev/null
chmod 600 myroot.key

# New issuer means a fresh CA database; serials restart at 01.
rm -rf newcerts index.txt index.txt.attr index.txt.old index.txt.attr.old serial serial.old
mkdir -p newcerts && : > index.txt && echo 01 > serial

# ---- re-sign every cross-certificate (also verifies SKI, and stages) ---------
echo
echo "root subject : $(openssl x509 -in myroot.pem -noout -subject | sed 's/^subject=//')"
./add-domain.sh --resign

# ---- best-effort live check against a domain that really uses this CA --------
probe=${PROBE_HOST:-sberbank.ru}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT
if timeout 15 openssl s_client -connect "$probe:443" -servername "$probe" -showcerts \
        </dev/null 2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > "$tmp/chain.pem" \
        && [ -s "$tmp/chain.pem" ]; then
    csplit -s -z -f "$tmp/c_" -b '%d.pem' "$tmp/chain.pem" '/BEGIN CERTIFICATE/' '{*}'
    if [ -f "$tmp/c_1.pem" ]; then
        cat constrained/*.pem "$tmp/c_1.pem" > "$tmp/untrusted.pem"
        echo -n "live check ($probe): "
        openssl verify -CAfile myroot.pem -untrusted "$tmp/untrusted.pem" "$tmp/c_0.pem" || true
    fi
else
    echo "live check skipped (could not reach $probe)"
fi

echo
echo "Re-import required. The OLD root is now orphaned; delete it wherever it was trusted."
