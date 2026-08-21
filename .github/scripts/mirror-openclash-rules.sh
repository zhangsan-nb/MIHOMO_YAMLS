#!/usr/bin/env bash

set -euo pipefail

output_dir="${1:?usage: mirror-openclash-rules.sh OUTPUT_DIR}"

if [[ -d "${output_dir}" ]] && find "${output_dir}" -mindepth 1 -print -quit | grep -q .; then
  echo "output directory must be empty: ${output_dir}" >&2
  exit 1
fi

mkdir -p \
  "${output_dir}/domain" \
  "${output_dir}/ip" \
  "${output_dir}/classical" \
  "${output_dir}/yaml" \
  "${output_dir}/fakeip"

sources_file="${output_dir}/SOURCES.tsv"
printf 'path\tsource\tbytes\tsha256\n' > "${sources_file}"

mirror_count=0

fetch_rule() {
  local relative_path="$1"
  local source_url="$2"
  local minimum_bytes="$3"
  local destination="${output_dir}/${relative_path}"
  local byte_count
  local checksum

  mkdir -p "$(dirname "${destination}")"
  curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --retry 3 \
    --retry-all-errors \
    --connect-timeout 15 \
    --max-time 120 \
    --output "${destination}" \
    "${source_url}"

  byte_count="$(wc -c < "${destination}")"
  if (( byte_count < minimum_bytes )); then
    echo "downloaded rule is unexpectedly small: ${relative_path} (${byte_count} bytes)" >&2
    exit 1
  fi

  if LC_ALL=C grep -aEqi '<!doctype[[:space:]]+html|<html|404:[[:space:]]*not[[:space:]]*found|403[[:space:]]*forbidden' "${destination}"; then
    echo "downloaded rule looks like an HTTP error page: ${relative_path}" >&2
    exit 1
  fi

  checksum="$(sha256sum "${destination}" | awk '{print $1}')"
  printf '%s\t%s\t%s\t%s\n' \
    "${relative_path}" \
    "${source_url}" \
    "${byte_count}" \
    "${checksum}" >> "${sources_file}"

  mirror_count=$((mirror_count + 1))
  echo "mirrored ${relative_path} (${byte_count} bytes)"
}

domain_rules=(
  Tracking Advertising Direct LocationDKS Private Download Speedtest AI
  Telegram Twitter SocialMedia NewsMedia Games Crypto Netflix YouTube XPTV
  Emby Streaming AppleCN Apple Google Microsoft Facebook Proxy China
)

ip_rules=(
  Advertising Private AI Telegram SocialMedia XPTV Emby Netflix Streaming
  Google Facebook Proxy China
)

for name in "${domain_rules[@]}"; do
  fetch_rule \
    "domain/${name}.mrs" \
    "https://raw.githubusercontent.com/666OS/rules/release/mihomo/domain/${name}.mrs" \
    32
done

for name in "${ip_rules[@]}"; do
  fetch_rule \
    "ip/${name}.mrs" \
    "https://raw.githubusercontent.com/666OS/rules/release/mihomo/ip/${name}.mrs" \
    32
done

fetch_rule \
  "classical/UK-wifi-call.list" \
  "https://raw.githubusercontent.com/HenryChiao/wificalling/refs/heads/main/rules/UK-wifi-call.list" \
  16

fetch_rule \
  "yaml/AWAvenue-Ads-Rule-Clash.yaml" \
  "https://raw.githubusercontent.com/TG-Twilight/AWAvenue-Ads-Rule/main/Filters/AWAvenue-Ads-Rule-Clash.yaml" \
  16

fetch_rule \
  "yaml/GitHub.yaml" \
  "https://raw.githubusercontent.com/MetaCubeX/meta-rules-dat/meta/geo/geosite/github.yaml" \
  16

fetch_rule \
  "fakeip/fakeip-filter.mrs" \
  "https://github.com/DustinWin/ruleset_geodata/releases/download/mihomo-ruleset/fakeip-filter.mrs" \
  32

if (( mirror_count != 43 )); then
  echo "expected 43 mirrored providers, got ${mirror_count}" >&2
  exit 1
fi

cat > "${output_dir}/README.md" <<'EOF'
# OpenClash rule mirror

This branch is generated atomically by GitHub Actions for the OpenClash
configurations maintained by this repository. A failed or incomplete refresh
does not replace the previous known-good branch.

- `domain/`: Mihomo domain MRS providers
- `ip/`: Mihomo IP-CIDR MRS providers
- `classical/`: classical text providers
- `yaml/`: YAML providers
- `fakeip/`: Fake-IP filter provider
- `SOURCES.tsv`: upstream URL, byte size, and SHA-256 for every mirrored rule
- `SHA256SUMS`: checksums for all published files
EOF

(
  cd "${output_dir}"
  find . -type f ! -name SHA256SUMS -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

echo "validated and prepared ${mirror_count} OpenClash rule providers"
