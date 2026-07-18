set -eu

if [ -z "${LIGHTRAIL_REMOTE_ROOT:-}" ]; then
    echo "LIGHTRAIL_REMOTE_ROOT is required" >&2
    exit 64
fi

os_id=unknown
if [ -r /etc/os-release ]; then
    . /etc/os-release
    os_id=${ID:-unknown}
fi
case "$os_id" in
    ubuntu|debian) ;;
    *)
        echo "unsupported distribution: $os_id (expected ubuntu or debian)" >&2
        exit 65
        ;;
esac

uid=$(id -u)
sudo_mode=${LIGHTRAIL_SUDO_MODE:-auto}
as_root() {
    if [ "$uid" -eq 0 ]; then
        "$@"
    elif [ "$sudo_mode" != never ] &&
         command -v sudo >/dev/null 2>&1 &&
         sudo -n true >/dev/null 2>&1; then
        sudo -n "$@"
    else
        echo "root or passwordless sudo is required for: $*" >&2
        return 77
    fi
}

docker_healthy=0
if command -v docker >/dev/null 2>&1; then
    if docker info >/dev/null 2>&1 || as_root docker info >/dev/null 2>&1; then
        docker_healthy=1
    else
        echo "an existing Docker installation is present but unhealthy; refusing to replace it" >&2
        exit 78
    fi
fi

need_packages=0
if [ "$docker_healthy" -eq 0 ]; then
    need_packages=1
elif ! docker compose version >/dev/null 2>&1 &&
     ! as_root docker compose version >/dev/null 2>&1; then
    need_packages=1
elif ! docker buildx version >/dev/null 2>&1 &&
     ! as_root docker buildx version >/dev/null 2>&1; then
    need_packages=1
fi

if [ "$need_packages" -eq 1 ]; then
    as_root env DEBIAN_FRONTEND=noninteractive apt-get update
fi
if [ "$need_packages" -eq 1 ]; then
    as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y ca-certificates curl util-linux
fi

if [ "$need_packages" -eq 1 ]; then
    as_root install -m 0755 -d /etc/apt/keyrings
    key_file=$(mktemp)
    trap 'rm -f "$key_file"' EXIT HUP INT TERM
    curl -fsSL "https://download.docker.com/linux/$os_id/gpg" >"$key_file"
    as_root install -m 0644 "$key_file" /etc/apt/keyrings/docker.asc
    as_root chmod a+r /etc/apt/keyrings/docker.asc
    arch=$(dpkg --print-architecture)
    codename=$(. /etc/os-release && printf '%s' "$VERSION_CODENAME")
    printf 'deb [arch=%s signed-by=/etc/apt/keyrings/docker.asc] https://download.docker.com/linux/%s %s stable\n' \
        "$arch" "$os_id" "$codename" |
        as_root tee /etc/apt/sources.list.d/docker.list >/dev/null
    as_root env DEBIAN_FRONTEND=noninteractive apt-get update
    if [ "$docker_healthy" -eq 1 ]; then
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
            docker-buildx-plugin docker-compose-plugin
    else
        as_root env DEBIAN_FRONTEND=noninteractive apt-get install -y \
            docker-ce docker-ce-cli containerd.io docker-buildx-plugin docker-compose-plugin
    fi
fi

if command -v systemctl >/dev/null 2>&1; then
    as_root systemctl enable --now docker
fi

remote_user=$(id -un)
remote_group=$(id -gn)
if [ -e "$LIGHTRAIL_REMOTE_ROOT" ]; then
    if [ ! -d "$LIGHTRAIL_REMOTE_ROOT" ]; then
        echo "remote_root exists but is not a directory: $LIGHTRAIL_REMOTE_ROOT" >&2
        exit 79
    fi
    if [ ! -w "$LIGHTRAIL_REMOTE_ROOT" ]; then
        echo "remote_root exists but is not writable; refusing to change its ownership or mode" >&2
        exit 79
    fi
elif install -d -m 0750 "$LIGHTRAIL_REMOTE_ROOT" >/dev/null 2>&1; then
    :
else
    as_root install -d -m 0750 -o "$remote_user" -g "$remote_group" "$LIGHTRAIL_REMOTE_ROOT"
fi

if docker info >/dev/null 2>&1; then
    docker compose version >/dev/null
    docker buildx version >/dev/null
else
    as_root docker info >/dev/null
    as_root docker compose version >/dev/null
    as_root docker buildx version >/dev/null
fi
