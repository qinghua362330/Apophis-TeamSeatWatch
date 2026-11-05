#!/usr/bin/env python3
import hashlib
import importlib.util
import io
from pathlib import Path
import tempfile
from unittest import mock


SCRIPT = Path(__file__).with_name('prepare-browser.py')
SPEC = importlib.util.spec_from_file_location('prepare_browser', SCRIPT)
MODULE = importlib.util.module_from_spec(SPEC)
SPEC.loader.exec_module(MODULE)


def main():
    root = SCRIPT.parent.parent
    dockerfile = (root / 'Dockerfile').read_text()
    assert MODULE.SHA256 == '1de8a89ea228e4a0a602fd0c13c7a324fe5f310e9b08b0c4bf37e9ed0c474fcd'
    assert '5b1533db3b08c9cc8f7c24e0c2e31b6202d0bb1dad880f04978d03ce9e4b3ffa' in dockerfile
    assert 'ghcr.io/qinghua362330/apophis-teamseatwatch@sha256:076b0549f664367c5869a875a259812c42612d4041da07504f8ccfdb735ebe16' in dockerfile
    assert 'AS browser-runtime' in dockerfile
    payload = b'qualified-browser-fixture'
    expected = hashlib.sha256(payload).hexdigest()
    with tempfile.TemporaryDirectory() as temporary:
        root = Path(temporary)
        response = io.BytesIO(payload)
        with mock.patch.object(MODULE, 'ROOT', root), \
                mock.patch.object(MODULE, 'SHA256', expected), \
                mock.patch.object(MODULE.urllib.request, 'urlopen', return_value=response) as urlopen:
            archive = MODULE.prepare()

        request = urlopen.call_args.args[0]
        assert request.get_header('User-agent') == MODULE.USER_AGENT
        assert urlopen.call_args.kwargs == {'timeout': 60}
        assert archive.read_bytes() == payload


if __name__ == '__main__':
    main()
