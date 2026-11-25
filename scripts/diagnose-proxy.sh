#!/bin/bash
# Read-only curl diagnostics. Credentials are passed through stdin, not argv.
set +x
set -u
set -o pipefail
umask 077

if [[ "${1:-}" == "--help" ]]; then
  cat <<'HELP'
Usage: PROXY_HOST=server-ip PROXY_PORT=443 ROUNDS=1 bash scripts/diagnose-proxy.sh
Prompts for the proxy account (password hidden; blank username = no account).
A: SOCKS5 + pinned Cloudflare DoH; no system or proxy hostname lookup for target.
B: SOCKS5h + HTTPS public-IP check; target DNS is resolved by the upstream proxy.
C: ExitGuard http://127.0.0.1:17890 + HTTPS public-IP check; ExitGuard must be active.
Times are cumulative from each request's start, not separate stage durations.
No automatic retries, credentials in command arguments, verbose or raw packet trace.
HELP
  exit 0
fi

proxy_host=${PROXY_HOST:-}
proxy_port=${PROXY_PORT:-443}
rounds=${ROUNDS:-1}
if [[ -z "$proxy_host" ]]; then
  read -r -p 'SOCKS5 代理服务器 IP / 主机名: ' proxy_host
fi
if [[ ! "$proxy_host" =~ ^[a-zA-Z0-9.-]+$ ]] || [[ ! "$proxy_port" =~ ^[0-9]{1,5}$ ]] || ((10#$proxy_port < 1 || 10#$proxy_port > 65535)); then
  printf '%s\n' '代理地址或端口无效；账户请在下一步单独输入。' >&2
  exit 2
fi
if [[ ! "$rounds" =~ ^[1-9]$|^10$ ]]; then
  printf '%s\n' 'ROUNDS 必须为 1 至 10。' >&2
  exit 2
fi

read -r -p '代理用户名（无需认证则直接回车）: ' test_user
test_pass=''
if [[ -n "$test_user" ]]; then
  if [[ "$test_user" == *:* ]]; then
    printf '%s\n' '代理用户名不能包含冒号。' >&2
    exit 2
  fi
  read -r -s -p '代理密码（隐藏输入）: ' test_pass
  printf '\n'
fi

# Escape curl's quoted config syntax. This value is never printed or saved.
auth_escaped="$test_user:$test_pass"
auth_escaped=${auth_escaped//\\/\\\\}
auth_escaped=${auth_escaped//\"/\\\"}
auth_escaped=${auth_escaped//$'\r'/\\r}
auth_escaped=${auth_escaped//$'\t'/\\t}
auth_config() {
  if [[ "$1" == upstream && -n "$test_user" ]]; then
    printf 'proxy-user = "%s"\n' "$auth_escaped"
  fi
}

scratch_dir=$(mktemp -d "${TMPDIR:-/tmp}/exitguard-curl.XXXXXX") || exit 1
trap 'rm -rf "$scratch_dir"' EXIT
trap 'exit 130' INT
trap 'exit 143' TERM
failed=0

run_check() {
  local label=$1 auth=$2 proxy=$3 url=$4
  shift 4
  printf '\n[%s] %s\n' "$(date '+%Y-%m-%d %H:%M:%S %z')" "$label"
  # -q is first: ignore ~/.curlrc. Explicit proxy + empty noproxy avoids bypass.
  auth_config "$auth" | /usr/bin/curl -q --config - \
    --proxy "$proxy" --noproxy '' --ipv4 --http1.1 \
    --connect-timeout 10 --max-time 15 --silent --show-error --fail-with-body \
    --output "$scratch_dir/body" --dump-header "$scratch_dir/headers" \
    --write-out 'HTTP=%{http_code} connect=%{time_connect}s TLS=%{time_appconnect}s first_byte=%{time_starttransfer}s total=%{time_total}s\n' \
    "$@" "$url"
  local rc=$?
  printf 'curl_exit=%s\n' "$rc"
  if ((rc != 0)); then
    failed=$((failed + 1))
  elif [[ "$label" == A:* ]]; then
    local octet
    octet=$(od -An -tu1 -j 3 -N 1 "$scratch_dir/body" | tr -d '[:space:]')
    if grep -iq '^content-type:[[:space:]]*application/dns-message' "$scratch_dir/headers" && \
       [[ $(wc -c < "$scratch_dir/body") -ge 12 && "$octet" =~ ^[0-9]+$ ]]; then
      printf 'DNS_RCODE=%s（0=成功，2=解析服务失败，3=域名不存在，5=拒绝）\n' "$((octet & 15))"
    else
      printf '%s\n' 'HTTP 已返回，但响应未识别为完整 DNS 报文。'
    fi
  else
    # Print only the public-IP field, not an arbitrary response/error page.
    LC_ALL=C grep -Eo '"ip"[[:space:]]*:[[:space:]]*"[0-9a-fA-F:.]+"' "$scratch_dir/body" | head -n 1 || true
  fi
}

printf '%s\n' '各项顺序执行，无自动重试；时间字段为累计耗时。'
printf '%s\n' 'C 项需要 ExitGuard 已启动；A/B 项直接测试上游，不依赖 ExitGuard。'
for ((round=1; round<=rounds; round++)); do
  printf '\n===== 第 %s/%s 轮 =====\n' "$round" "$rounds"
  run_check 'A: 上游 SOCKS5 → 固定地址的安全 DNS' upstream "socks5://$proxy_host:$proxy_port" \
    'https://cloudflare-dns.com/dns-query?dns=AAABAAABAAAAAAAAA2FwaQVpcGlmeQNvcmcAAAEAAQ' \
    --resolve 'cloudflare-dns.com:443:1.1.1.1' --header 'Accept: application/dns-message'
  run_check 'B: 上游 SOCKS5 → 公网出口（由上游解析域名）' upstream "socks5h://$proxy_host:$proxy_port" \
    'https://api.ipify.org?format=json'
  run_check 'C: ExitGuard 本机入口 → 公网出口' none 'http://127.0.0.1:17890' \
    'https://api.ipify.org?format=json'
  if ((round < rounds)); then sleep 2; fi
done
unset test_user test_pass auth_escaped
printf '\n完成：%s 次 curl 请求失败。\n' "$failed"
printf '%s\n' '常见错误码：7=连接失败；28=超时；35=TLS握手失败；56=接收中断或CONNECT失败；60=证书验证失败；97=SOCKS代理握手失败。以对应 curl 错误文字为准。'
((failed == 0))
