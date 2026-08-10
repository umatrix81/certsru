#!/usr/bin/env bash
# Add or update a foreign CA root that should be name-constrained.
#
# Usage: ./update-ca.sh /path/to/new_root.cer [...]   add or update a root
#        ./update-ca.sh --list                        show what is constrained now
#        ./update-ca.sh --retire <name>               stop constraining a root
#
# A CA "update" is one of two very different things:
#
#   same public key, new validity  -> nothing needs doing. The cross-certificate
#       carries its own validity signed by your root, so it keeps working even
#       after the original expires. This script detects that and says so.
#
#   new public key (real rotation) -> the new root must be cross-signed too, and
#       BOTH must stay installed until every site has migrated. This script adds
#       the new one alongside the old rather than replacing it.
set -euo pipefail
cd "$(dirname "$0")"

mkdir -p roots constrained

pubkey_fp() {  # sha256 over the SubjectPublicKeyInfo
    openssl x509 -in "$1" -noout -pubkey 2>/dev/null \
        | openssl pkey -pubin -outform DER 2>/dev/null \
        | openssl dgst -sha256 | sed 's/.*= *//'
}

list_roots() {
    local f base cross
    shopt -s nullglob
    local any=0
    for f in roots/*; do
        base=$(basename "$f"); base=${base%.*}
        cross="constrained/${base}.pem"
        echo "  $base"
        echo "      subject : $(openssl x509 -in "$f" -noout -subject | sed 's/^subject=//')"
        echo "      expires : $(openssl x509 -in "$f" -noout -enddate | sed 's/notAfter=//')"
        echo "      key     : $(pubkey_fp "$f" | cut -c1-32)..."
        if [ -f "$cross" ]; then
            echo "      cross   : $cross (expires $(openssl x509 -in "$cross" -noout -enddate | sed 's/notAfter=//'))"
        else
            echo "      cross   : MISSING -- run ./add-domain.sh --resign"
        fi
        any=1
    done
    [ "$any" = 1 ] || echo "  (none)"
}

if [ "${1:-}" = "--list" ]; then
    echo "Constrained roots:"; list_roots; exit 0
fi

if [ "${1:-}" = "--retire" ]; then
    [ $# -eq 2 ] || { echo "usage: $0 --retire <name>" >&2; exit 1; }
    name=$2
    shopt -s nullglob
    hit=$(ls roots/"$name".* 2>/dev/null | head -1 || true)
    [ -n "$hit" ] || { echo "no root named '$name' (see --list)" >&2; exit 1; }
    remaining=$(ls roots/* 2>/dev/null | wc -l)
    [ "$remaining" -gt 1 ] || { echo "refusing to retire the only root" >&2; exit 1; }
    mkdir -p roots/retired
    mv "$hit" roots/retired/
    rm -f "constrained/${name}.pem"
    echo "retired $name -> roots/retired/"
    ./add-domain.sh --resign
    echo
    echo "The retired cross-certificate is still installed and valid until it expires."
    echo "Run install-certs.ps1 (it removes copies it manages) or delete it by hand."
    exit 0
fi

[ $# -ge 1 ] || { echo "usage: $0 <new_root.cer> [...] | --list | --retire <name>" >&2; exit 1; }

changed=0
for src in "$@"; do
    [ -f "$src" ] || { echo "not a file: $src" >&2; exit 1; }

    # Normalise to PEM; accept DER input too.
    tmp=$(mktemp)
    if ! openssl x509 -in "$src" -out "$tmp" 2>/dev/null; then
        if ! openssl x509 -inform DER -in "$src" -out "$tmp" 2>/dev/null; then
            echo "not a certificate: $src" >&2; rm -f "$tmp"; exit 1
        fi
    fi

    subj=$(openssl x509 -in "$tmp" -noout -subject | sed 's/^subject=//')
    iss=$(openssl x509 -in "$tmp" -noout -issuer  | sed 's/^issuer=//')
    echo "== $src"
    echo "   subject: $subj"

    if [ "$subj" != "$iss" ]; then
        echo "   ERROR: not self-signed (issuer differs). openssl ca -ss_cert requires a" >&2
        echo "          self-signed root; an intermediate cannot be cross-signed this way." >&2
        rm -f "$tmp"; exit 1
    fi
    if ! openssl verify -CAfile "$tmp" "$tmp" >/dev/null 2>&1; then
        echo "   ERROR: self-signature does not verify" >&2; rm -f "$tmp"; exit 1
    fi
    if ! openssl x509 -in "$tmp" -noout -ext basicConstraints 2>/dev/null | grep -q 'CA:TRUE'; then
        echo "   ERROR: not a CA certificate (basicConstraints CA:TRUE missing)" >&2
        rm -f "$tmp"; exit 1
    fi

    newfp=$(pubkey_fp "$tmp")

    # Same key as something we already constrain?
    match=""
    shopt -s nullglob
    for f in roots/*; do
        [ "$(pubkey_fp "$f")" = "$newfp" ] && { match=$f; break; }
    done

    if [ -n "$match" ]; then
        oldend=$(openssl x509 -in "$match" -noout -enddate | sed 's/notAfter=//')
        newend=$(openssl x509 -in "$tmp"   -noout -enddate | sed 's/notAfter=//')
        echo "   same public key as $(basename "$match")"
        echo "   old validity: $oldend"
        echo "   new validity: $newend"
        echo "   -> Existing cross-certificate already covers this key. Nothing must be"
        echo "      re-imported; chains keep validating even past the original's expiry."
        cp "$tmp" "$match"
        echo "   refreshed $match on disk (cosmetic -- keeps --list accurate)"
        rm -f "$tmp"
        continue
    fi

    base=$(basename "$src"); base=${base%.*}
    base=$(printf '%s' "$base" | tr -c 'A-Za-z0-9._-' '_')
    dest="roots/${base}.cer"
    if [ -e "$dest" ]; then
        echo "   ERROR: roots/${base}.cer exists with a DIFFERENT key." >&2
        echo "          Rename the input, or --retire the old one first." >&2
        rm -f "$tmp"; exit 1
    fi

    mv "$tmp" "$dest"
    echo "   NEW KEY -- added as $dest"
    echo "   Both roots stay constrained; retire the old one once sites have migrated."
    changed=1
done

if [ "$changed" = 1 ]; then
    echo
    ./add-domain.sh --resign
else
    echo
    echo "No new keys. Re-staging to keep copies current."
    ./add-domain.sh --restage
fi
