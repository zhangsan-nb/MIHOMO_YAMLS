#!/usr/bin/env bash

set -euo pipefail

output_dir="${1:?usage: mirror-openclash-rules.sh OUTPUT_DIR [PREVIOUS_SOURCES_TSV]}"
previous_sources_file="${2:-}"

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
report_tsv="${output_dir}/REPORT.tsv"
report_markdown="${output_dir}/REPORT.md"
printf 'path\tsource\tbytes\tsha256\n' > "${sources_file}"
printf 'status\tpath\tdetail\n' > "${report_tsv}"

declare -A previous_checksums=()
if [[ -n "${previous_sources_file}" && -s "${previous_sources_file}" ]]; then
  while IFS=$'\t' read -r path _source _bytes checksum; do
    [[ "${path}" == "path" || -z "${path}" || -z "${checksum}" ]] && continue
    previous_checksums["${path}"]="${checksum}"
  done < "${previous_sources_file}"
fi

success_count=0
new_count=0
updated_count=0
unchanged_count=0
failed_count=0
expected_count=43

record_failure() {
  local relative_path="$1"
  local detail="$2"
  printf 'FAILED\t%s\t%s\n' "${relative_path}" "${detail}" >> "${report_tsv}"
  failed_count=$((failed_count + 1))
  echo "failed ${relative_path}: ${detail}" >&2
}

fetch_rule() {
  local relative_path="$1"
  local source_url="$2"
  local minimum_bytes="$3"
  local destination="${output_dir}/${relative_path}"
  local temporary="${destination}.download"
  local byte_count
  local checksum
  local previous_checksum
  local status

  mkdir -p "$(dirname "${destination}")"
  rm -f "${temporary}"

  if ! curl \
    --fail \
    --location \
    --silent \
    --show-error \
    --retry 3 \
    --retry-all-errors \
    --connect-timeout 15 \
    --max-time 120 \
    --output "${temporary}" \
    "${source_url}"; then
    record_failure "${relative_path}" "下载失败"
    rm -f "${temporary}"
    return
  fi

  byte_count="$(wc -c < "${temporary}")"
  if (( byte_count < minimum_bytes )); then
    record_failure "${relative_path}" "文件过小（${byte_count} 字节）"
    rm -f "${temporary}"
    return
  fi

  if LC_ALL=C grep -aEqi '<!doctype[[:space:]]+html|<html|404:[[:space:]]*not[[:space:]]*found|403[[:space:]]*forbidden' "${temporary}"; then
    record_failure "${relative_path}" "疑似 HTTP 错误页"
    rm -f "${temporary}"
    return
  fi

  checksum="$(sha256sum "${temporary}" | awk '{print $1}')"
  if ! mv "${temporary}" "${destination}"; then
    record_failure "${relative_path}" "保存文件失败"
    rm -f "${temporary}"
    return
  fi

  previous_checksum="${previous_checksums[${relative_path}]:-}"
  if [[ -z "${previous_checksum}" ]]; then
    status="NEW"
    new_count=$((new_count + 1))
  elif [[ "${previous_checksum}" == "${checksum}" ]]; then
    status="UNCHANGED"
    unchanged_count=$((unchanged_count + 1))
  else
    status="UPDATED"
    updated_count=$((updated_count + 1))
  fi

  printf '%s\t%s\t%s\t%s\n' \
    "${relative_path}" \
    "${source_url}" \
    "${byte_count}" \
    "${checksum}" >> "${sources_file}"
  printf '%s\t%s\t%s\n' "${status}" "${relative_path}" "${byte_count} 字节" >> "${report_tsv}"

  success_count=$((success_count + 1))
  echo "${status,,} ${relative_path} (${byte_count} bytes)"
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

if (( success_count + failed_count != expected_count )); then
  record_failure "(system)" "规则定义数量异常：预期 ${expected_count}，实际 $((success_count + failed_count))"
fi

overall_result="成功"
if (( failed_count > 0 || success_count != expected_count )); then
  overall_result="失败"
fi

{
  echo "# OpenClash 规则镜像报告"
  echo
  echo "- 结果：${overall_result}"
  echo "- 新增：${new_count}"
  echo "- 更新：${updated_count}"
  echo "- 未变化：${unchanged_count}"
  echo "- 失败：${failed_count}"

  if (( new_count + updated_count > 0 )); then
    echo
    echo "## 本次有变化"
    awk -F '\t' 'NR > 1 && ($1 == "NEW" || $1 == "UPDATED") { printf "- %s (%s)\n", $2, $1 }' "${report_tsv}"
  fi

  if (( failed_count > 0 )); then
    echo
    echo "## 失败"
    awk -F '\t' 'NR > 1 && $1 == "FAILED" { printf "- %s：%s\n", $2, $3 }' "${report_tsv}"
  fi
} > "${report_markdown}"

if (( failed_count > 0 || success_count != expected_count )); then
  echo "rule mirror failed: ${success_count} succeeded, ${failed_count} failed" >&2
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
  find . -type f \
    ! -name SHA256SUMS \
    ! -name REPORT.tsv \
    ! -name REPORT.md \
    -print0 \
    | sort -z \
    | xargs -0 sha256sum > SHA256SUMS
)

echo "validated ${success_count} providers: ${new_count} new, ${updated_count} updated, ${unchanged_count} unchanged"
