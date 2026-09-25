#!/usr/bin/env bash
# Run a built actor image locally (Apify SDK local storage, no platform) on a
# fixed live lookup and print how many host records it produced.
#
#   scripts/smoke-test.sh <image>      -> prints an integer on stdout
#
# Exits non-zero if the container fails. The count alone proves little, since
# the free sources are flaky; the update workflow runs the current and the
# candidate image back to back and compares the two counts.
set -euo pipefail
image=$1
dir=$(mktemp -d)
mkdir -p "$dir/key_value_stores/default"
cat > "$dir/key_value_stores/default/INPUT.json" <<'EOF'
{"domain": "tesla.com", "sources": ["crtsh", "certspotter", "rapiddns", "hackertarget"], "limit": 200, "timeout": 600}
EOF
docker run --rm -v "$dir:/actor/storage" "$image" >&2
sudo chown -R "$(id -u)" "$dir" 2>/dev/null || true
python3 - "$dir" <<'EOF'
import json, pathlib, sys
rows = [json.loads(p.read_text()) for p in pathlib.Path(sys.argv[1], 'datasets', 'default').glob('*.json')
        if p.name != '__metadata__.json']
print(sum(r.get('recordType') == 'host' for r in rows))
EOF
