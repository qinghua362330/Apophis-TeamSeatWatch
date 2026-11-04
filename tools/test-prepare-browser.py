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
