#!/usr/bin/env python3
"""Stage the single qualified unmodified browser artifact for every OCI build."""
import argparse
import hashlib
import os
from pathlib import Path
import shutil
import tempfile
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
URL = 'https://pub-e57a7c60f6934eb09a6600bf2fc59cdc.r2.dev/ShardX-Linux.zip'
SHA256 = '3ead1629a1c893f248cd01ee7c9125552b2cac5c91846cb71d6cb1b24883c213'
USER_AGENT = 'Apophis-TeamSeatWatch/1.0'


def digest(path):
    with path.open('rb') as source:
        return hashlib.file_digest(source, 'sha256').hexdigest()


def prepare(source=None):
    folder = ROOT / '.browser-artifacts'
    folder.mkdir(mode=0o700, exist_ok=True)
    archive = folder / 'ShardX-Linux.zip'
    if archive.exists():
        if digest(archive) != SHA256:
            raise RuntimeError('Qualified browser archive checksum mismatch')
        return archive
    if source and digest(source) != SHA256:
        raise RuntimeError('Qualified browser source checksum mismatch')
    with tempfile.TemporaryDirectory(prefix='.download-', dir=folder) as temporary:
        staged = Path(temporary) / archive.name
        if source:
            try:
                os.link(source, staged)
            except OSError:
                shutil.copyfile(source, staged)
        else:
            request = urllib.request.Request(URL, headers={'User-Agent': USER_AGENT})
            with urllib.request.urlopen(request, timeout=60) as response, staged.open('wb') as target:
                shutil.copyfileobj(response, target)
        if digest(staged) != SHA256:
            raise RuntimeError('Qualified browser archive checksum mismatch')
        os.replace(staged, archive)
    return archive


if __name__ == '__main__':
    parser = argparse.ArgumentParser()
    parser.add_argument('--source', type=Path, help='Reuse an already downloaded qualified ZIP')
    args = parser.parse_args()
    print(f'Qualified browser staged: {prepare(args.source)}')
