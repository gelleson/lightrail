set -eu

os_id=unknown
os_version=unknown
if [ -r /etc/os-release ]; then
    . /etc/os-release
    os_id=${ID:-unknown}
    os_version=${VERSION_ID:-unknown}
fi

uid=$(id -u)
sudo_mode=${LIGHTRAIL_SUDO_MODE:-auto}
sudo_available=0
if [ "$uid" -eq 0 ] ||
   { [ "$sudo_mode" != never ] &&
     command -v sudo >/dev/null 2>&1 &&
     sudo -n true >/dev/null 2>&1; }; then
    sudo_available=1
fi

privileged() {
    if [ "$uid" -eq 0 ]; then
        "$@"
    elif [ "$sudo_available" -eq 1 ]; then
        sudo -n "$@"
    else
        return 126
    fi
}

docker_cli=0
docker_ready=0
docker_via_sudo=0
compose=0
buildx=0
if command -v docker >/dev/null 2>&1; then
    docker_cli=1
    if docker info >/dev/null 2>&1; then
        docker_ready=1
        docker compose version >/dev/null 2>&1 && compose=1
        docker buildx version >/dev/null 2>&1 && buildx=1
    elif privileged docker info >/dev/null 2>&1; then
        docker_ready=1
        docker_via_sudo=1
        privileged docker compose version >/dev/null 2>&1 && compose=1
        privileged docker buildx version >/dev/null 2>&1 && buildx=1
    fi
fi

remote_root_ready=0
if [ -n "${LIGHTRAIL_REMOTE_ROOT:-}" ] &&
   [ -d "$LIGHTRAIL_REMOTE_ROOT" ] &&
   [ -w "$LIGHTRAIL_REMOTE_ROOT" ]; then
    remote_root_ready=1
fi

port_80_in_use=0
port_443_in_use=0
if command -v ss >/dev/null 2>&1; then
    if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:|\])80$'; then
        port_80_in_use=1
    fi
    if ss -H -ltn 2>/dev/null | awk '{print $4}' | grep -Eq '(^|:|\])443$'; then
        port_443_in_use=1
    fi
fi

firewall=unknown
firewall_80=unknown
firewall_443=unknown
if command -v ufw >/dev/null 2>&1 &&
   privileged ufw status 2>/dev/null | grep -q '^Status: active'; then
    firewall=ufw
    if privileged ufw status 2>/dev/null | grep -Eiq '(^|[[:space:]])80(/tcp)?[[:space:]].*ALLOW'; then
        firewall_80=allow
    else
        firewall_80=deny
    fi
    if privileged ufw status 2>/dev/null | grep -Eiq '(^|[[:space:]])443(/tcp)?[[:space:]].*ALLOW'; then
        firewall_443=allow
    else
        firewall_443=deny
    fi
elif command -v firewall-cmd >/dev/null 2>&1 &&
     firewall-cmd --state >/dev/null 2>&1; then
    firewall=firewalld
    if firewall-cmd --quiet --query-port=80/tcp >/dev/null 2>&1 ||
       firewall-cmd --quiet --query-service=http >/dev/null 2>&1; then
        firewall_80=allow
    else
        firewall_80=deny
    fi
    if firewall-cmd --quiet --query-port=443/tcp >/dev/null 2>&1 ||
       firewall-cmd --quiet --query-service=https >/dev/null 2>&1; then
        firewall_443=allow
    else
        firewall_443=deny
    fi
elif command -v nft >/dev/null 2>&1; then
    firewall=nftables
elif command -v iptables >/dev/null 2>&1; then
    firewall=iptables
else
    firewall=none
fi

printf 'os_id=%s\n' "$os_id"
printf 'os_version=%s\n' "$os_version"
printf 'arch=%s\n' "$(uname -m)"
printf 'uid=%s\n' "$uid"
printf 'sudo_available=%s\n' "$sudo_available"
printf 'docker_cli=%s\n' "$docker_cli"
printf 'docker_ready=%s\n' "$docker_ready"
printf 'docker_via_sudo=%s\n' "$docker_via_sudo"
printf 'compose=%s\n' "$compose"
printf 'buildx=%s\n' "$buildx"
printf 'remote_root_ready=%s\n' "$remote_root_ready"
printf 'port_80_in_use=%s\n' "$port_80_in_use"
printf 'port_443_in_use=%s\n' "$port_443_in_use"
printf 'firewall=%s\n' "$firewall"
printf 'firewall_80=%s\n' "$firewall_80"
printf 'firewall_443=%s\n' "$firewall_443"
