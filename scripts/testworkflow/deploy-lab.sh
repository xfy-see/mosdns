#!/usr/bin/env bash
# SPDX-License-Identifier: GPL-3.0-or-later
# Everything created here belongs to one network namespace. No host nft/routing
# changes are made. The enclosing Python controller supplies a fresh random ID.
set -euo pipefail

check() {
  [[ $(uname -s) == Linux ]] || { echo 'Linux is required' >&2; return 1; }
  [[ $EUID == 0 ]] || { echo 'Run through sudo; a private network namespace requires root' >&2; return 1; }
  for tool in ip nft python3; do command -v "$tool" >/dev/null || { echo "Missing $tool" >&2; return 1; }; done
}

case ${1:-} in
  --check) check; exit ;;
  --run) shift ;;
  *) echo 'Usage: deploy-lab.sh --check | --run mosdns-lab-<32 hex digits> COMMAND [ARGS...]' >&2; exit 2 ;;
esac
check
namespace=${1:-}
[[ $namespace =~ ^mosdns-lab-[0-9a-f]{32}$ ]] || { echo 'Invalid owned namespace name' >&2; exit 2; }
shift
[[ $# -gt 0 ]] || { echo 'A command is required' >&2; exit 2; }
if ip netns list | awk '{print $1}' | grep -Fxq "$namespace"; then
  echo 'Refusing to reuse an existing namespace' >&2
  exit 1
fi
owned=0
cleanup() {
  code=$?
  trap - EXIT INT TERM HUP
  if [[ $owned == 1 ]]; then
    # A namespace handle, not command-name matching, identifies owned processes.
    mapfile -t owned_pids < <(ip netns pids "$namespace")
    if [[ ${#owned_pids[@]} -gt 0 ]]; then
      kill -TERM "${owned_pids[@]}" 2>/dev/null || true
      for _ in {1..30}; do
        [[ -z $(ip netns pids "$namespace") ]] && break
        sleep .1
      done
      mapfile -t owned_pids < <(ip netns pids "$namespace")
      [[ ${#owned_pids[@]} == 0 ]] || kill -KILL "${owned_pids[@]}" 2>/dev/null || true
    fi
    if ! ip netns delete "$namespace"; then
      echo "Failed to remove owned namespace $namespace" >&2
      code=1
    fi
    # Cgroups belong to this same fresh UUID; rmdir refuses nonempty groups.
    # This also covers interruption before the Python finalizer can run.
    for group in /sys/fs/cgroup/"$namespace"-[0-9][0-9][0-9]; do
      [[ ! -d $group ]] || rmdir "$group" || code=1
    done
  fi
  exit "$code"
}
trap cleanup EXIT
trap 'exit 130' INT
trap 'exit 143' TERM HUP
ip netns add "$namespace"
owned=1
ip -n "$namespace" link set lo up
ip netns exec "$namespace" "$@"
