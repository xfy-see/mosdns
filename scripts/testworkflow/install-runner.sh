#!/usr/bin/env bash
# Install one ephemeral Linux X64 GitHub runner from an operator-verified archive.
set -euo pipefail

usage() {
  cat <<'USAGE'
Usage: bash scripts/testworkflow/install-runner.sh \
  --archive /absolute/actions-runner-linux-x64-VERSION.tar.gz \
  --sha256 VERIFIED_OFFICIAL_ARCHIVE_SHA256 \
  --directory /absolute/new-runner-directory \
  [--repo xfy-see/mosdns] [--name mosdns-lab-unique-name] [--extract-only]

Download the archive and checksum from GitHub Settings > Actions > Runners.
The installer never downloads software or reads existing credentials. It checks
the archive SHA256, installs outside this checkout, and starts one ephemeral job.
GitHub's config.sh prompts for a fresh registration token; do not pass it here.
Run as a normal user on Linux X64. --extract-only verifies/extracts without
registering or starting the runner.
USAGE
}

archive=''
checksum=''
directory=''
repository='xfy-see/mosdns'
runner_name="mosdns-lab-$(date -u +%Y%m%dT%H%M%SZ)"
extract_only=false
while (($#)); do
  case "$1" in
    --archive|--sha256|--directory|--repo|--name)
      (($# >= 2)) || { usage >&2; exit 2; }
      case "$1" in
        --archive) archive=$2 ;;
        --sha256) checksum=$2 ;;
        --directory) directory=$2 ;;
        --repo) repository=$2 ;;
        --name) runner_name=$2 ;;
      esac
      shift 2 ;;
    --extract-only) extract_only=true; shift ;;
    -h|--help) usage; exit 0 ;;
    *) usage >&2; exit 2 ;;
  esac
done
[[ -n "$archive" && -n "$directory" && "$checksum" =~ ^[0-9a-f]{64}$ ]] || { usage >&2; exit 2; }
[[ "$archive" = /* && "$directory" = /* ]] || { echo 'Archive and runner directory must be absolute paths.' >&2; exit 2; }
[[ "$repository" =~ ^[A-Za-z0-9_.-]+/[A-Za-z0-9_.-]+$ ]] || { echo 'Invalid repository.' >&2; exit 2; }
[[ "$runner_name" =~ ^[A-Za-z0-9_.-]+$ ]] || { echo 'Invalid runner name.' >&2; exit 2; }
[[ "$(uname -s)" = Linux && "$(uname -m)" = x86_64 ]] || { echo 'A Linux X64 machine is required.' >&2; exit 2; }
((EUID != 0)) || { echo 'Run this installer as a normal user.' >&2; exit 2; }
command -v python3 >/dev/null || { echo 'Python 3 is required.' >&2; exit 2; }
script_directory=$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)
checkout=$(cd -- "$script_directory/../.." && pwd -P)

python3 - "$archive" "$checksum" "$directory" "$checkout" <<'PY'
import hashlib
from pathlib import Path, PurePosixPath
import shutil
import sys
import tarfile

archive = Path(sys.argv[1]).resolve(strict=True)
destination = Path(sys.argv[3]).expanduser().resolve()
checkout = Path(sys.argv[4]).resolve()
if destination == checkout or checkout in destination.parents:
    raise SystemExit("Runner directory must be outside the repository checkout")
if destination.exists():
    raise SystemExit("Runner directory must not already exist")
digest = hashlib.sha256()
with archive.open("rb") as stream:
    for block in iter(lambda: stream.read(1024 * 1024), b""):
        digest.update(block)
if digest.hexdigest() != sys.argv[2]:
    raise SystemExit("Runner archive SHA256 differs from the supplied official checksum")
with tarfile.open(archive, "r:gz") as bundle:
    members = bundle.getmembers()
    for member in members:
        path = PurePosixPath(member.name)
        if path.is_absolute() or ".." in path.parts or "\\" in member.name:
            raise SystemExit("Unsafe archive path")
        if not member.isdir() and not member.isfile():
            raise SystemExit("Only regular files and directories are accepted in the runner archive")
    names = {PurePosixPath(m.name).as_posix() for m in members if m.isfile()}
    if not {"config.sh", "run.sh"}.issubset(names):
        raise SystemExit("Archive does not contain GitHub runner entry points")
    destination.mkdir(mode=0o700, parents=True, exist_ok=False)
    for member in members:
        path = destination.joinpath(*PurePosixPath(member.name).parts)
        if member.isdir():
            path.mkdir(mode=0o700, parents=True, exist_ok=True)
            continue
        path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        stream = bundle.extractfile(member)
        if stream is None:
            raise SystemExit("Cannot read runner archive entry")
        with stream, path.open("xb") as output:
            shutil.copyfileobj(stream, output)
        path.chmod(member.mode & 0o777)
print("Verified runner archive and installed into " + str(destination))
PY

[[ "$extract_only" = false ]] || exit 0
cd -- "$directory"
./config.sh --url "https://github.com/$repository" --name "$runner_name" \
  --labels mosdns-lab --ephemeral --work _work
exec ./run.sh
