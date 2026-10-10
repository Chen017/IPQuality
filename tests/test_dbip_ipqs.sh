#!/usr/bin/env bash
# Offline regression tests for DB-IP /self and IPQS JSON serialization.
set -u

root=$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)
core=${1:-"$root/../ip.sh"}
tmp=$(mktemp -d)
trap 'rm -rf "$tmp"' EXIT

# Extract the production DB-IP function without running network tests.
eval "$(sed -n '/^db_dbip(){/,/^}/p' "$core")"
declare -A dbip sinfo sscore
sinfo[database]=Database
sinfo[ldatabase]=0
sscore[low]=Low
sscore[medium]=Medium
sscore[high]=High
Font_Cyan='' Font_B='' Font_I='' Font_Suffix=''
CurlARG=''
IP='192.0.2.10'
ibar_step=0
show_progress_bar() { :; }
kill_progress_bar() { :; }

curl() {
    local family='' url='' arg
    for arg in "$@"; do
        case "$arg" in
            -4|-6) family=$arg ;;
            https://db-ip.com/api/core/|https://api.db-ip.com/*) url=$arg ;;
        esac
    done
    printf '%s %s\n' "$family" "$url" >> "$tmp/calls"
    case "$url" in
        https://db-ip.com/api/core/)
            if [[ $scenario == no_key ]]; then
                printf '<html>No public key</html>\n'
            else
                printf '<div data-api-key="fixture-key"></div>\n'
            fi
            ;;
        https://api.db-ip.com/v2/fixture-key/self\?convertCurrencies)
            case "$scenario" in
                normal) printf '{"threatLevel":"low","countryCode":"NL","isProxy":false}\n' ;;
                medium) printf '{"threatLevel":"medium","countryCode":"DE","isProxy":false}\n' ;;
                error) printf '{"errorCode":"ACCESS_DENIED","message":"mock error"}\n' ;;
                malformed) printf '{"threatLevel":\n' ;;
            esac
            ;;
        *) return 1 ;;
    esac
}

fail() { echo "FAIL: $*" >&2; exit 1; }
assert_calls() {
    local family=$1 expected=$2
    [[ $(wc -l < "$tmp/calls") -eq $expected ]] || fail "expected $expected requests"
    if grep -v "^-$family " "$tmp/calls"; then
        fail "request used wrong address family"
    fi
}

for family in 4 6; do
    scenario=normal
    : > "$tmp/calls"
    if [[ "$family" == 6 ]]; then IP='2001:db8::10'; else IP='192.0.2.10'; fi
    db_dbip "$family" >/dev/null || fail "normal family $family failed"
    [[ ${dbip[score]:-none} == 0 ]] || fail "IPv$family missing ipAddress should retain score 0"
    [[ ${dbip[countrycode]:-} == NL ]] || fail "IPv$family country missing"
    assert_calls "$family" 2
    echo "PASS: IPv$family two same-family requests and missing ipAddress"
done

scenario=medium
: > "$tmp/calls"
db_dbip 4 >/dev/null || fail 'medium response rejected'
[[ ${dbip[score]:-none} == 50 ]] || fail 'medium score missing'
assert_calls 4 2
echo 'PASS: medium threat maps to 50'

scenario=error
: > "$tmp/calls"
if db_dbip 4 >/dev/null; then fail 'explicit API error accepted'; fi
[[ -z ${dbip[score]:-} ]] || fail 'error retained stale score'
assert_calls 4 2
echo 'PASS: explicit API error rejected'

scenario=no_key
: > "$tmp/calls"
if db_dbip 4 >/dev/null; then fail 'missing API key accepted'; fi
[[ -z ${dbip[score]:-} ]] || fail 'missing key has a score'
assert_calls 4 1
echo 'PASS: no API key prevents second request'

scenario=malformed
: > "$tmp/calls"
db_dbip 4 >/dev/null || :
[[ -z ${dbip[score]:-} ]] || fail 'malformed JSON has a score'
assert_calls 4 2
echo 'PASS: malformed JSON never creates a score'

grep -Fq 'IPQS: \"${ipqs[score]:-null}\"' "$core" || fail 'IPQS serializer regression'
echo 'PASS: IPQS JSON serializes ipqs[score]'
echo 'All DB-IP/IPQS regression tests passed.'
