#!/usr/bin/env python3
"""Publish the first Go optimization release from a verified existing CI run.

Runs in GitHub Actions only. Does not compile, run binaries, overwrite assets,
move existing tags, or alter an existing published release.
"""
import hashlib
import json
import os
from pathlib import Path
import shutil
import subprocess

ROOT = Path(__file__).resolve().parent.parent
REPO = 'xfy-see/mosdns'
COMMIT = 'c203ecd11bd8e8b897789bef8f9798dee80c987b'
RUN = 37875686901
TAG = 'v5.3.4-opt.1'
TITLE = 'v5.3.4-opt.1 — Go 优化首版'
NOTES = ROOT / 'docs/releases/v5.3.4-opt.1.md'
EXPECTED = {
    'mosdns-full-linux-arm64': '3ebe3987fc2f553c1eb70d899cab3cb9468fb57a0e25a99f41ae945497aef4e5',
    'mosdns-minimal-linux-arm64': 'e94e47f3fd00d67c1ab7d26961c8770d6b14531603f0f2198fc43bec4cb4234d',
    'mosdns-full-linux-amd64': '81774b183023ccfda965cd33a43a89eedf5a9bdc8c4aed3d5c661b463230a0ab',
    'mosdns-minimal-linux-amd64': '04ab1ae48c20ffd25f532c85a6c4d7fbc40c17fdbcf65e58533e372ca7de9c19',
}


def gh(*args, input_data=None):
    result = subprocess.run(['gh', *args], cwd=ROOT, check=True,
                            input=input_data, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    return result.stdout


def api(path):
    return json.loads(gh('api', 'repos/' + REPO + '/' + path))


def check_tag():
    refs = api('git/matching-refs/tags/' + TAG)
    refs = [r for r in refs if r['ref'] == 'refs/tags/' + TAG]
    if len(refs) > 1:
        raise RuntimeError('duplicate tag refs')
    if refs:
        ref = refs[0]['object']
        if ref['type'] == 'tag':
            ref = api('git/tags/' + ref['sha'])['object']
        if ref['type'] != 'commit' or ref['sha'] != COMMIT:
            raise RuntimeError('existing release tag selects another commit')
    return bool(refs)


def digest(path):
    if path.is_symlink() or not path.is_file():
        raise RuntimeError('expected regular asset: ' + str(path))
    return hashlib.sha256(path.read_bytes()).hexdigest()


def release_assets(release, expected):
    assets = api('releases/%s/assets?per_page=100' % release['id'])
    if len(assets) > len(expected) or len({a['name'] for a in assets}) != len(assets):
        raise RuntimeError('unexpected or duplicate release assets')
    for asset in assets:
        record = expected.get(asset['name'])
        if (not record or asset['state'] != 'uploaded' or asset['size'] != record['bytes']
                or asset.get('digest') != 'sha256:' + record['sha256']):
            raise RuntimeError('release asset mismatch: ' + asset['name'])
    return {a['name'] for a in assets}


def main():
    if os.environ.get('GITHUB_ACTIONS') != 'true' or os.environ.get('GITHUB_REPOSITORY') != REPO:
        raise RuntimeError('publisher requires the selected repository Actions environment')
    source = ROOT / '.build/github-actions' / str(RUN)
    receipt = json.loads((source / 'verification.json').read_text())
    if (receipt.get('status'), receipt.get('repository'), receipt.get('commit'),
            receipt.get('run_id'), receipt.get('run_attempt')) != ('verified', REPO, COMMIT, RUN, 1):
        raise RuntimeError('unexpected build verification receipt')
    live = api('actions/runs/' + str(RUN))
    if (live['head_sha'], live['run_attempt'], live['status'], live['conclusion']) != (
            COMMIT, 1, 'completed', 'success'):
        raise RuntimeError('source run changed after download')
    stage = ROOT / '.build/first-go-release'
    stage.mkdir()
    for arch in ('arm64', 'amd64'):
        directory = source / ('linux-' + arch)
        verified = next(a for a in receipt['artifacts'] if a['arch'] == arch)
        for name, sha in verified['files'].items():
            path = directory / name
            if digest(path) != sha:
                raise RuntimeError('download changed: ' + name)
            target = 'manifest-linux-' + arch + '.json' if name == 'manifest.json' else name
            shutil.copyfile(path, stage / target)
    for name, sha in EXPECTED.items():
        if digest(stage / name) != sha:
            raise RuntimeError('production ELF differs from reviewed first release: ' + name)
    (stage / 'BUILD-INFO.json').write_text(json.dumps({
        'repository': REPO, 'tag': TAG, 'commit': COMMIT,
        'source_run_id': RUN, 'source_run_attempt': 1,
        'source_run_url': live['html_url'], 'go_version': '1.26.0',
        'cgo_enabled': False, 'upx': False, 'binary_version': 'git-' + COMMIT,
        'verification': {k: receipt[k] for k in ('status', 'repository', 'commit', 'run_id', 'run_attempt')},
        'verified_artifacts': [
            {k: v for k, v in record.items() if k != 'verified_at'}
            for record in receipt['artifacts']
        ],
    }, indent=2, sort_keys=True) + '\n')
    assets = sorted(stage.iterdir())
    (stage / 'SHA256SUMS').write_text(''.join(digest(p) + '  ' + p.name + '\n' for p in assets))
    assets = sorted(stage.iterdir())
    expected = {p.name: {'bytes': p.stat().st_size, 'sha256': digest(p)} for p in assets}
    if not check_tag():
        gh('api', '--method', 'POST', 'repos/' + REPO + '/git/refs', '--input', '-',
           input_data=json.dumps({'ref': 'refs/tags/' + TAG, 'sha': COMMIT}))
        if not check_tag():
            raise RuntimeError('new tag was not confirmed')
    # List with write credentials so a previous interrupted draft is also visible.
    releases = api('releases?per_page=100')
    matches = [r for r in releases if r['tag_name'] == TAG]
    if len(matches) > 1:
        raise RuntimeError('multiple releases share the selected tag')
    if matches:
        release = matches[0]
        if release['body'].rstrip('\n') != NOTES.read_text().rstrip('\n') or release['name'] != TITLE:
            raise RuntimeError('existing release description differs')
    else:
        gh('release', 'create', TAG, '--repo', REPO, '--verify-tag', '--target', COMMIT,
           '--draft', '--title', TITLE, '--notes-file', str(NOTES))
        release = api('releases/tags/' + TAG)
    if not check_tag():
        raise RuntimeError('draft release did not create the selected tag')
    present = release_assets(release, expected)
    if not release['draft']:
        if present != set(expected):
            raise RuntimeError('published release has an incomplete asset set')
    else:
        for path in assets:
            if path.name not in present:
                gh('release', 'upload', TAG, str(path), '--repo', REPO)
        release = api('releases/tags/' + TAG)
        if release_assets(release, expected) != set(expected):
            raise RuntimeError('draft upload incomplete')
        if not check_tag():
            raise RuntimeError('release tag disappeared before publication')
        gh('release', 'edit', TAG, '--repo', REPO, '--draft=false', '--latest')
    release = api('releases/tags/' + TAG)
    if not check_tag():
        raise RuntimeError('published release tag is missing')
    if release['draft'] or release_assets(release, expected) != set(expected):
        raise RuntimeError('release not confirmed published with all assets')
    print(release['html_url'])


if __name__ == '__main__':
    main()
