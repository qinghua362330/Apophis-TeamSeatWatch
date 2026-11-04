#!/usr/bin/env python3
"""Single-host installation and maintenance using the existing application CLI."""

import argparse
import base64
import datetime
import fcntl
import getpass
import json
import os
from pathlib import Path
import platform
import secrets
import shutil
import ssl
import subprocess
import sys
import tarfile
import tempfile
import time
import urllib.error
import urllib.request

ROOT = Path(__file__).resolve().parent.parent
DEFAULT_DATA = Path.home() / '.local/share/apophis-teamseatwatch'


def run(command, *, env=None, capture=False, output=None):
    return subprocess.run(command, env=env, check=True, text=output is None,
                          stdout=output or (subprocess.PIPE if capture else None),
                          stderr=subprocess.PIPE if capture else None)


def write(path, text):
    path.write_text(text)
    path.chmod(0o600)


def write_env(directory, name, values):
    write(directory / name, ''.join(f'{key}={value}\n' for key, value in values.items()))


def certificates(directory):
    authority = directory / 'tls/authority'
    authority.mkdir(parents=True, mode=0o700)
    ca, ca_key = authority / 'ca.crt', authority / 'ca.key'
    run(['openssl', 'req', '-x509', '-newkey', 'rsa:3072', '-nodes', '-sha256',
         '-days', '3650', '-keyout', str(ca_key), '-out', str(ca),
         '-subj', '/CN=TeamSeatWatch Local CA', '-addext', 'basicConstraints=critical,CA:TRUE',
         '-addext', 'keyUsage=critical,keyCertSign,cRLSign'], capture=True)
    for role, name, cn, usage in [('control', 'server', 'localhost', 'serverAuth'),
                                  ('gateway', 'client', 'gateway', 'clientAuth'),
                                  ('web', 'localhost', 'localhost', 'serverAuth')]:
        folder = directory / 'tls' / role
        folder.mkdir(mode=0o700)
        extensions = ('basicConstraints=critical,CA:FALSE\n'
                      'keyUsage=critical,digitalSignature,keyEncipherment\n'
                      f'extendedKeyUsage={usage}\n')
        if role != 'gateway':
            extensions += 'subjectAltName=DNS:localhost,IP:127.0.0.1\n'
        write(folder / 'extensions.cnf', extensions)
        run(['openssl', 'req', '-new', '-newkey', 'rsa:3072', '-nodes', '-keyout',
             str(folder / f'{name}.key'), '-out', str(folder / f'{name}.csr'),
             '-subj', f'/CN={cn}'], capture=True)
        run(['openssl', 'x509', '-req', '-sha256', '-days', '365', '-in',
             str(folder / f'{name}.csr'), '-CA', str(ca), '-CAkey', str(ca_key),
             '-CAcreateserial', '-extfile', str(folder / 'extensions.cnf'),
             '-out', str(folder / f'{name}.crt')], capture=True)
        shutil.copyfile(ca, folder / 'ca.crt')
    for path in (directory / 'tls').rglob('*'):
        if path.is_file():
            path.chmod(0o600)


def initialize(data, base):
    install = data / 'installation'
    if install.exists():
        return json.loads((install / 'settings.json').read_text())
    # Publish a complete set atomically; interrupted generation cannot replace keys.
    staging = Path(tempfile.mkdtemp(prefix='.setup-', dir=data))
    settings = {'project': 'tsw-' + secrets.token_hex(5), 'port_base': base}
    try:
        db_password = secrets.token_hex(24)
        cpa_webhook_secret = secrets.token_urlsafe(32)
        database = {'TSW_DATABASE_URL':
                    f'postgres://teamseatwatch:{db_password}@127.0.0.1:{base+5}/teamseatwatch?sslmode=disable',
                    'TSW_TOTP_KEYRING_FILE': '/secrets/keyring.json'}
        write_env(staging, 'postgres.env', {'POSTGRES_USER': 'teamseatwatch',
                  'POSTGRES_DB': 'teamseatwatch', 'POSTGRES_PASSWORD': db_password,
                  'POSTGRES_INITDB_ARGS': '--auth-host=scram-sha-256'})
        write_env(staging, 'database.env', database)
        write_env(staging, 'control.env', {**database,
                  'TSW_TOTP_KEYRING_FILE': '/secrets/keyring.json',
                  'TSW_PLATFORM_BASE_URL': 'https://chatgpt.com',
                  'TSW_CONTROL_LISTEN': f'127.0.0.1:{base}',
                  'TSW_PRIVATE_LISTEN': f'127.0.0.1:{base+1}',
                  'TSW_OWNER_STATIC_DIR': '/app/owner',
                  'TSW_OWNER_ORIGINS': f'https://localhost:{base+3}',
                  'TSW_CPA_WEBHOOK_SECRET': cpa_webhook_secret,
                  'TSW_TLS_CA_FILE': '/tls/ca.crt', 'TSW_TLS_CERT_FILE': '/tls/server.crt',
                  'TSW_TLS_KEY_FILE': '/tls/server.key'})
        write_env(staging, 'gateway.env', {
                  'TSW_GATEWAY_LISTEN': f'127.0.0.1:{base+2}',
                  'TSW_CONTROL_PRIVATE_URL': f'https://127.0.0.1:{base+1}/internal/v1/health',
                  'TSW_PUBLIC_STATIC_DIR': '/app/public', 'TSW_TLS_CA_FILE': '/tls/ca.crt',
                  'TSW_TLS_CERT_FILE': '/tls/client.crt', 'TSW_TLS_KEY_FILE': '/tls/client.key',
                  'TSW_CONTROL_SERVER_NAME': 'localhost'})
        key = base64.urlsafe_b64encode(secrets.token_bytes(32)).decode().rstrip('=')
        write(staging / 'keyring.json', json.dumps({'current_version': 1, 'keys': {'1': key}})+'\n')
        certificates(staging)
        write(staging / 'nginx.conf', f'''events {{}}
http {{
  access_log /dev/stdout;
  error_log /dev/stderr warn;
  ssl_protocols TLSv1.3;
  ssl_certificate /tls/localhost.crt;
  ssl_certificate_key /tls/localhost.key;
  client_max_body_size 20m;
  proxy_read_timeout 300s;
  server {{
    listen 127.0.0.1:{base+3} ssl;
    server_name localhost;
    location / {{
      proxy_pass http://127.0.0.1:{base};
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-Proto https;
    }}
  }}
  server {{
    listen 127.0.0.1:{base+4} ssl;
    server_name localhost;
    location / {{
      proxy_pass http://127.0.0.1:{base+2};
      proxy_set_header Host $http_host;
      proxy_set_header X-Forwarded-Proto https;
    }}
  }}
}}
''')
        write(staging / 'settings.json', json.dumps(settings, indent=2)+'\n')
        os.replace(staging, install)
    finally:
        if staging.exists():
            shutil.rmtree(staging)
    return settings


class Installation:
    def __init__(self, data, settings, image):
        self.data, self.settings = data, settings
        self.env = {**os.environ, 'TSW_INSTALL_DIR': str(data / 'installation'),
                    'TSW_DATABASE_PORT': str(settings['port_base'] + 5), 'TSW_IMAGE': image}
        self.command = ['docker', 'compose', '--project-name', settings['project'],
                        '--file', str(ROOT / 'deploy/compose.yaml')]

    def compose(self, *args, **kwargs):
        return run(self.command + list(args), env=kwargs.pop('env', self.env), **kwargs)

    def owner(self):
        return self.compose('exec', '-T', 'postgres', 'psql', '-p',
                            self.env['TSW_DATABASE_PORT'], '-U', 'teamseatwatch', '-d',
                            'teamseatwatch', '-Atc', 'SELECT username FROM tsw_owners;',
                            capture=True).stdout.strip()

    def set_password(self, role, username):
        password = getpass.getpass('管理员密码 / Admin password (至少14字符 / min. 14 characters): ')
        if len(password) < 14 or password != getpass.getpass('再次输入 / Repeat password: '):
            raise RuntimeError('密码至少14字符，两次输入须一致 / Password must match and have at least 14 characters.')
        env = {**self.env, 'TSW_OWNER_LOGIN': username, 'TSW_OWNER_PASSWORD': password}
        self.compose('run', '--rm', '--no-deps', '-e', 'TSW_OWNER_LOGIN', '-e',
                     'TSW_OWNER_PASSWORD', 'cli', role, env=env)

    def ready(self):
        context = ssl.create_default_context(cafile=str(self.data / 'installation/tls/authority/ca.crt'))
        base = self.settings['port_base']
        for _ in range(90):
            try:
                with urllib.request.urlopen(f'https://localhost:{base+4}/health/ready',
                                            context=context, timeout=3) as response:
                    if json.load(response) == {'status': 'ok'}:
                        return
            except (OSError, urllib.error.URLError, ValueError):
                pass
            time.sleep(1)
        raise RuntimeError('启动检查未通过；运行 logs 查看原因 / Startup check failed; run logs for details.')

    def backup(self):
        stamp = datetime.datetime.now(datetime.timezone.utc).strftime('%Y%m%dT%H%M%SZ')
        folder = self.data / 'backups' / (stamp + '-' + secrets.token_hex(3))
        folder.mkdir(parents=True, mode=0o700)
        with (folder / 'database.dump').open('xb') as handle:
            self.compose('exec', '-T', 'postgres', 'pg_dump', '-p', self.env['TSW_DATABASE_PORT'],
                         '-U', 'teamseatwatch', '-d', 'teamseatwatch', '--format=custom', output=handle)
        with tarfile.open(folder / 'installation.tar.gz', 'w:gz') as archive:
            archive.add(self.data / 'installation', arcname='installation')
        print(f'备份 / Backup: {folder}')
        return folder


def main():
    os.umask(0o077)
    parser = argparse.ArgumentParser(description='TeamSeatWatch 启动与维护 / Start and maintain TeamSeatWatch')
    parser.add_argument('action', choices=['start', 'stop', 'status', 'logs', 'backup', 'reset-password'])
    parser.add_argument('--data-dir', type=Path, default=DEFAULT_DATA,
                        help='安装资料目录；同一安装始终使用同一路径 / Persistent installation directory')
    parser.add_argument('--port-base', type=int, default=None, help='首次安装的连续6个端口起点 / First of six ports')
    parser.add_argument('--image', default='apophis-teamseatwatch:local', help='Application image tag')
    parser.add_argument('--build', action='store_true', help='从当前源码重建镜像 / Rebuild from current source')
    args = parser.parse_args()
    if platform.system() != 'Linux' or platform.machine() not in ['x86_64', 'amd64']:
        raise RuntimeError('此入口支持 Linux x86_64 / This installer supports Linux x86_64.')
    for command in ['docker', 'openssl']:
        if not shutil.which(command):
            raise RuntimeError(f'请先安装 / Install first: {command}')
    run(['docker', 'compose', 'version'], capture=True)
    data = args.data_dir.expanduser().resolve()
    if args.action != 'start' and not (data / 'installation/settings.json').exists():
        raise RuntimeError('此目录尚未安装，请先运行 start / Run start for this directory first.')
    data.mkdir(parents=True, exist_ok=True, mode=0o700)
    with (data / '.lock').open('a') as lock:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
        if args.port_base is not None and not 1024 <= args.port_base <= 65530:
            raise RuntimeError('port-base 范围 / Range: 1024–65530')
        settings = initialize(data, args.port_base or 18440)
        if args.port_base is not None and args.port_base != settings['port_base']:
            raise RuntimeError('已有安装请沿用原端口 / Keep the existing installation ports.')
        installation = Installation(data, settings, args.image)
        if args.action == 'start':
            exists = subprocess.run(['docker', 'image', 'inspect', args.image],
                                    stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL).returncode == 0
            if args.build or not exists:
                print('正在构建，首次运行需下载依赖 / Building; the first run downloads dependencies.', flush=True)
                run([sys.executable, str(ROOT / 'tools/prepare-browser.py')])
                run(['docker', 'build', '--network=host', '--tag', args.image, str(ROOT)])
            installation.compose('up', '-d', '--wait', 'postgres')
            installation.compose('stop', 'https', 'gateway', 'control')
            installation.backup()
            installation.compose('run', '--rm', '--no-deps', 'cli', 'migrate')
            username = installation.owner()
            if not username:
                installation.set_password('owner-create', 'owner')
            installation.compose('run', '--rm', '--no-deps', 'https', 'nginx', '-t')
            installation.compose('up', '-d', 'control', 'gateway', 'https')
            installation.ready()
            base = settings['port_base']
            print(f'\n已就绪 / Ready\n管理端 / Admin: https://localhost:{base+3}/owner/\n'
                  f'兑换端 / Redeem: https://localhost:{base+4}/redeem/\n账号 / Login: {username or "owner"}\n'
                  f'请信任此CA证书 / Trust this CA: {data}/installation/tls/authority/ca.crt\n'
                  f'安装资料 / Installation data: {data}')
        elif args.action == 'stop':
            installation.compose('stop')
        elif args.action == 'status':
            installation.compose('ps')
        elif args.action == 'logs':
            installation.compose('logs', '--tail', '80', 'control', 'gateway', 'https', 'postgres')
        elif args.action == 'backup':
            installation.compose('up', '-d', '--wait', 'postgres')
            installation.compose('stop', 'https', 'gateway', 'control')
            installation.backup()
            print('备份完成，运行 start 恢复服务 / Backup complete; run start to resume services.')
        elif args.action == 'reset-password':
            installation.compose('up', '-d', '--wait', 'postgres')
            username = installation.owner()
            if not username:
                raise RuntimeError('没有管理员，请先运行 start / No admin; run start first.')
            installation.set_password('owner-reset', username)


if __name__ == '__main__':
    try:
        main()
    except (RuntimeError, OSError, subprocess.CalledProcessError, ValueError) as error:
        print(f'操作未完成 / Incomplete: {error}', file=sys.stderr)
        sys.exit(1)
    except KeyboardInterrupt:
        print('\n已中止；安装资料保留，可再次运行 start / Interrupted; installation data is retained. Run start again.', file=sys.stderr)
        sys.exit(130)
