set -eu
umask 077
[ "$(id -u)" -eq 0 ] && [ "$(uname -s)" = Linux ] || exit 1
case "$(uname -m)" in x86_64|aarch64|arm64) ;; *) exit 1 ;; esac
# Bootstrap only runs after the user explicitly starts execution.
if command -v systemctl >/dev/null && [ -d /run/systemd/system ]; then MIAO_INIT=systemd
elif command -v rc-service >/dev/null && [ -d /run/openrc ]; then MIAO_INIT=openrc
else echo unsupported_init >&2; exit 1; fi
# Skip package managers entirely when all required tools already exist.
if command -v python3 >/dev/null && python3 -c 'import sys, yaml; sys.exit(sys.version_info < (3, 8))' 2>/dev/null &&
   command -v openssl >/dev/null && command -v ss >/dev/null && command -v setcap >/dev/null &&
   { [ "$MIAO_INIT" = systemd ] || command -v logrotate >/dev/null; } &&
   { [ -s /etc/ssl/certs/ca-certificates.crt ] || [ -s /etc/pki/tls/certs/ca-bundle.crt ]; }; then
  exit 0
fi
# Serialize package setup too; a crashed bootstrap leaves a PID for safe retry.
LOCK=/var/lib/miao-vps/bootstrap.lock
tries=0
until mkdir "$LOCK" 2>/dev/null; do
  if [ -f "$LOCK/pid" ]; then
    old_pid="$(cat "$LOCK/pid")"
    case "$old_pid" in *[!0-9]*|'') exit 1 ;; esac
    if ! kill -0 "$old_pid" 2>/dev/null; then rm -f "$LOCK/pid"; rmdir "$LOCK" 2>/dev/null || true; fi
  fi
  tries=$((tries+1)); [ "$tries" -lt 120 ] || exit 1
  sleep 1
done
printf '%s' "$$" > "$LOCK/pid"
trap 'rm -f "$LOCK/pid"; rmdir "$LOCK" 2>/dev/null || true' 0
# Package names are fixed, never derived from request data. Pass only missing
# packages, so an unrelated missing tool does not upgrade existing OpenSSL.
if command -v apt-get >/dev/null; then
  manager=apt; python_pkg=python3; yaml_pkg=python3-yaml; ip_pkg=iproute2; cap_pkg=libcap2-bin
elif command -v apk >/dev/null; then
  manager=apk; python_pkg=python3; yaml_pkg=py3-yaml; ip_pkg=iproute2; cap_pkg=libcap
elif command -v dnf >/dev/null; then
  manager=dnf; python_pkg=python3; yaml_pkg=python3-pyyaml; ip_pkg=iproute; cap_pkg=libcap
elif command -v yum >/dev/null; then
  manager=yum; python_pkg=python3; yaml_pkg=python3-pyyaml; ip_pkg=iproute; cap_pkg=libcap
elif command -v pacman >/dev/null; then
  manager=pacman; python_pkg=python; yaml_pkg=python-yaml; ip_pkg=iproute2; cap_pkg=libcap
elif command -v zypper >/dev/null; then
  manager=zypper; python_pkg=python3; yaml_pkg=python3-PyYAML; ip_pkg=iproute2; cap_pkg=libcap-progs
else
  echo unsupported_package_manager >&2; exit 1
fi
packages=""
if ! command -v python3 >/dev/null || ! python3 -c 'import sys; sys.exit(sys.version_info < (3, 8))' 2>/dev/null; then packages="$packages $python_pkg"; fi
if ! python3 -c 'import yaml' 2>/dev/null; then packages="$packages $yaml_pkg"; fi
if ! command -v openssl >/dev/null; then packages="$packages openssl"; fi
if ! command -v ss >/dev/null; then packages="$packages $ip_pkg"; fi
if ! command -v setcap >/dev/null; then packages="$packages $cap_pkg"; fi
if [ "$MIAO_INIT" = openrc ] && ! command -v logrotate >/dev/null; then packages="$packages logrotate"; fi
if [ ! -s /etc/ssl/certs/ca-certificates.crt ] && [ ! -s /etc/pki/tls/certs/ca-bundle.crt ]; then packages="$packages ca-certificates"; fi
if [ -n "$packages" ]; then
  # Word splitting is intentional; packages contains only the constants above.
  case "$manager" in
    apt) apt-get -o DPkg::Lock::Timeout=60 update >&2
         DEBIAN_FRONTEND=noninteractive apt-get -o DPkg::Lock::Timeout=60 install -y $packages >&2 ;;
    apk) apk add --no-cache $packages >&2 ;;
    dnf) dnf install -y $packages >&2 ;;
    yum) yum install -y $packages >&2 ;;
    pacman) pacman -S --needed --noconfirm $packages >&2 ;;
    zypper) zypper --non-interactive install $packages >&2 ;;
  esac
fi
python3 -c 'import sys, yaml; sys.exit(sys.version_info < (3, 8))'
for tool in openssl ss setcap; do command -v "$tool" >/dev/null || exit 1; done
if [ "$MIAO_INIT" = openrc ]; then command -v logrotate >/dev/null || exit 1; fi
