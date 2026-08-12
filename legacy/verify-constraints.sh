#!/usr/bin/env bash
# Audit every name-constrained cross-certificate:
#   1. what they permit (inspection)
#   2. permitted domains that really use these CAs still validate (positive control)
#   3. the same leaf is REJECTED once its name is removed (negative control)
#
# Step 3 is the one that matters. Without it, a cert that permits everything
# looks identical to a working one.
#
# Usage: ./verify-constraints.sh
set -euo pipefail
cd "$(dirname "$0")"

ROOT=myroot.pem

for f in "$ROOT" cross.cnf myroot.key; do
    [ -f "$f" ] || { echo "missing: $f" >&2; exit 1; }
done
ls constrained/*.pem >/dev/null 2>&1 || { echo "no cross-certificates -- run ./add-domain.sh --resign" >&2; exit 1; }

tmp=$(mktemp -d); trap 'rm -rf "$tmp"' EXIT

bold() { printf '\n\033[1m%s\033[0m\n' "$1"; }
pass() { printf '  \033[32mPASS\033[0m %s\n' "$1"; }
fail() { printf '  \033[31mFAIL\033[0m %s\n' "$1"; FAILED=1; }
skip() { printf '  \033[90mskip\033[0m %s\n' "$1"; }
FAILED=0

cat constrained/*.pem > "$tmp/bundle.pem"

# ---------------------------------------------------------------- 1. inspect
bold "1. Cross-certificates and what they permit"
mapfile -t permitted < <(openssl x509 -in "$(ls constrained/*.pem | head -1)" -noout \
                         -ext nameConstraints | sed -n 's/.*DNS:\(\S*\).*/\1/p')
[ ${#permitted[@]} -gt 0 ] || { fail "no permitted DNS names -- constrains nothing"; exit 1; }
printf '  permitted: %s\n' "${permitted[*]}"

for cross in constrained/*.pem; do
    base=$(basename "$cross" .pem)
    orig=$(ls roots/"$base".* 2>/dev/null | head -1 || true)
    echo "  -- $base"
    if [ -z "$orig" ]; then
        fail "$base has no matching file in roots/"; continue
    fi

    if openssl x509 -in "$cross" -noout -text | grep -A1 'X509v3 Name Constraints' | grep -q critical; then
        pass "$base constraints present and critical"
    else
        fail "$base constraints missing or not critical"
    fi

    a=$(openssl x509 -in "$orig"  -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')
    b=$(openssl x509 -in "$cross" -noout -ext subjectKeyIdentifier | tail -1 | tr -d ' ')
    [ "$a" = "$b" ] && pass "$base SKI matches the original root" \
                    || fail "$base SKI differs -- sub-CA AKI will not match"

    iss=$(openssl x509 -in "$cross" -noout -issuer  | sed 's/^issuer=//')
    sub=$(openssl x509 -in "$ROOT"  -noout -subject | sed 's/^subject=//')
    [ "$iss" = "$sub" ] && pass "$base issued by $ROOT" \
                        || fail "$base issuer mismatch: '$iss' vs '$sub'"

    # Each cross-cert must permit the same set, or the effective policy is the union.
    mapfile -t this < <(openssl x509 -in "$cross" -noout -ext nameConstraints \
                        | sed -n 's/.*DNS:\(\S*\).*/\1/p')
    [ "${this[*]}" = "${permitted[*]}" ] && pass "$base permits the same list as the others" \
                                         || fail "$base permits a DIFFERENT list: ${this[*]}"
done

# --------------------------------------------------- 2/3. live controls
bold "2. Positive control -- permitted domains that use these CAs"
verified=""
for d in "${permitted[@]}"; do
    if ! timeout 12 openssl s_client -connect "$d:443" -servername "$d" -showcerts \
         </dev/null 2>/dev/null | awk '/BEGIN CERT/,/END CERT/' > "$tmp/$d.chain" \
         || [ ! -s "$tmp/$d.chain" ]; then
        skip "$d (unreachable)"; continue
    fi
    rm -f "$tmp/c_"*; csplit -s -z -f "$tmp/c_" -b '%d.pem' "$tmp/$d.chain" '/BEGIN CERTIFICATE/' '{*}'
    [ -f "$tmp/c_1.pem" ] || { skip "$d (server sent no intermediate)"; continue; }
    cat "$tmp/bundle.pem" "$tmp/c_1.pem" > "$tmp/unt.pem"
    if openssl verify -CAfile "$ROOT" -untrusted "$tmp/unt.pem" "$tmp/c_0.pem" >/dev/null 2>&1; then
        pass "$d validates through the constrained chain"
        if [ -z "$verified" ]; then
            verified=$d
            cp "$tmp/c_0.pem" "$tmp/probe_leaf.pem"
            cp "$tmp/c_1.pem" "$tmp/probe_sub.pem"
        fi
    else
        issuer=$(openssl x509 -in "$tmp/c_0.pem" -noout -issuer | sed 's/.*CN *= *//')
        skip "$d (chains to a CA we do not constrain: $issuer)"
    fi
done

bold "3. Negative control -- same leaf, name removed from the constraint"
if [ -z "$verified" ]; then
    skip "no reachable domain used these CAs, cannot run the negative control"
    echo "  Without this step the audit is incomplete: an over-permissive cert still shows PASS above."
else
    mapfile -t leafsan < <(openssl x509 -in "$tmp/probe_leaf.pem" -noout -ext subjectAltName \
                           | tr ',' '\n' | sed -n 's/.*DNS://p' | tr -d ' ')
    cp cross.cnf "$tmp/neg.cnf"
    for s in "${leafsan[@]}"; do
        base=${s#\*.}
        for p in "${permitted[@]}"; do
            if [ "$base" = "$p" ] || [ "${base%.$p}" != "$base" ]; then
                sed -i "/^permitted;DNS\.[0-9]*[[:space:]]*=[[:space:]]*${p}\$/d" "$tmp/neg.cnf"
            fi
        done
    done
    # Isolated CA database so the real index.txt/serial are untouched.
    mkdir -p "$tmp/newcerts"; : > "$tmp/index.txt"; echo 01 > "$tmp/serial"
    sed -i "s|^database .*|database = $tmp/index.txt|; s|^serial .*|serial = $tmp/serial|; \
            s|^new_certs_dir .*|new_certs_dir = $tmp/newcerts|" "$tmp/neg.cnf"

    : > "$tmp/neg-bundle.pem"
    for r in roots/*; do
        [ -e "$r" ] || continue
        openssl ca -config "$tmp/neg.cnf" -batch -notext -days 30 \
            -cert "$ROOT" -keyfile myroot.key -ss_cert "$r" \
            -out "$tmp/neg-one.pem" >/dev/null 2>&1 || continue
        cat "$tmp/neg-one.pem" >> "$tmp/neg-bundle.pem"
    done
    cat "$tmp/probe_sub.pem" >> "$tmp/neg-bundle.pem"

    out=$(openssl verify -CAfile "$ROOT" -untrusted "$tmp/neg-bundle.pem" "$tmp/probe_leaf.pem" 2>&1 || true)
    if echo "$out" | grep -q 'subtree violation'; then
        pass "$verified rejected: $(echo "$out" | sed -n 's/.*depth lookup: //p' | head -1)"
        echo "        => constraints are enforced, not merely present"
    else
        fail "leaf still accepted with its name removed -- constraints are NOT being enforced"
        echo "$out" | sed 's/^/        /'
    fi
fi

# ------------------------------------------------- 4. competing trust paths
bold "4. Competing trust paths for the original roots"
for r in roots/*; do
    [ -e "$r" ] || continue
    name=$(openssl x509 -in "$r" -noout -subject | sed 's/.*CN *= *//')
    hit=0
    for store in /etc/ssl/certs/ca-certificates.crt /etc/pki/tls/certs/ca-bundle.crt; do
        [ -f "$store" ] || continue
        if openssl crl2pkcs7 -nocrl -certfile "$store" 2>/dev/null \
            | openssl pkcs7 -print_certs -noout 2>/dev/null | grep -qF "$name"; then
            fail "'$name' present in $store -- chains can bypass the constraint"; hit=1
        fi
    done
    [ $hit = 0 ] && pass "'$name' not in this system's CA bundle (Linux side)"
    echo "        SHA256 $(openssl x509 -in "$r" -noout -fingerprint -sha256 | cut -d= -f2)"
done
echo "  Windows stores: run .\\install-certs.ps1 -- it scans CurrentUser and LocalMachine"
echo "  Firefox: about:preferences#connectionSecurity > View Certificates > Authorities"

bold "Result"
[ $FAILED = 0 ] && echo "  all checks passed" || { echo "  FAILURES ABOVE"; exit 1; }
