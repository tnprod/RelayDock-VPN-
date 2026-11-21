import asyncio
import logging
from pathlib import Path
import asyncssh


class UserError(Exception):
    def __init__(self, message, code='ssh_error'):
        super().__init__(message)
        self.code = code


# Fixed read-only commands. No user input is interpolated into a shell command.
AUDIT_SCRIPT = r'''
export LC_ALL=C
printf '\nRD2:os\n'; cat /etc/os-release 2>/dev/null
printf '\nRD2:arch\n'; uname -m
printf '\nRD2:uid\n'; id -u
printf '\nRD2:sudo\n'; if [ "$(id -u)" = 0 ]; then echo root; elif sudo -n true 2>/dev/null; then echo available; else echo unavailable; fi
printf '\nRD2:memory\n'; awk '/MemTotal:/ {print $2}' /proc/meminfo 2>/dev/null
printf '\nRD2:disk\n'; df -Pk / 2>/dev/null | tail -n 1 | awk '{print $4}'
printf '\nRD2:ports\n'; ss -H -ltn 2>/dev/null | head -n 80
printf '\nRD2:services\n'; for service in xray x-ui mtg docker; do printf '%s=' "$service"; systemctl is-active "$service" 2>/dev/null || true; done
printf '\nRD2:docker\n'; docker --version 2>/dev/null || true
printf '\nRD2:firewall\n'; if command -v ufw >/dev/null 2>&1; then if [ "$(id -u)" = 0 ]; then ufw status 2>/dev/null | head -n 16; else sudo -n ufw status 2>/dev/null | head -n 16; fi; else echo not_detected; fi
'''


def parse_report(output):
    fields = {}
    section = None
    for line in output.splitlines():
        if line.startswith('RD2:'):
            section = line[4:]
            fields[section] = []
        elif section:
            fields[section].append(line[:500])
    os_info = {}
    for line in fields.get('os', []):
        if '=' in line:
            key, value = line.split('=', 1)
            os_info[key] = value.strip('"\'')
    def first(name, default='unknown'):
        return next((x for x in fields.get(name, []) if x.strip()), default)
    def number(name):
        value = first(name, '')
        return int(value) if value.isdigit() else None
    services = {}
    for line in fields.get('services', []):
        if '=' in line:
            key, value = line.split('=', 1)
            if key in {'xray', 'x-ui', 'mtg', 'docker'}:
                services[key] = value
    ports = []
    for line in fields.get('ports', []):
        parts = line.split()
        if len(parts) >= 4:
            endpoint = parts[3]
            try:
                port = int(endpoint.rsplit(':', 1)[1])
            except (ValueError, IndexError):
                continue
            if 1 <= port <= 65535 and port not in ports:
                ports.append(port)
    warnings = []
    supported = os_info.get('ID') == 'ubuntu' and os_info.get('VERSION_ID') == '24.04'
    if not supported:
        warnings.append('Автоматическая установка для этой ОС ещё не проверена. Обследование доступно.')
    if first('sudo') == 'unavailable':
        warnings.append('Для будущей установки потребуются root или дополнительные права sudo.')
    if services.get('x-ui') == 'active':
        warnings.append('Обнаружена работающая 3x-ui. Перед изменениями потребуется план совместимости.')
    if first('docker', ''):
        warnings.append('Docker обнаружен. Список контейнеров и их конфигурации в этом обследовании не читаются.')
    if not os_info:
        warnings.append('ОС не определена: сервер может ограничивать доступ к командам обследования.')
    return {
        'os': os_info.get('PRETTY_NAME', 'Не определена'),
        'os_id': os_info.get('ID'), 'os_version': os_info.get('VERSION_ID'),
        'architecture': first('arch'), 'uid': number('uid'),
        'privileges': first('sudo'), 'memory_kib': number('memory'),
        'disk_free_kib': number('disk'), 'tcp_ports': sorted(ports),
        'services': services, 'docker_detected': bool(first('docker', '')),
        'firewall': '\n'.join(fields.get('firewall', [])).strip() or 'Нет доступа к статусу',
        'warnings': warnings, 'install_os_supported': supported,
        'scope': 'read_only',
    }


class SSHService:
    def __init__(self,key_resolver=None):
        self.key_resolver=key_resolver
    async def fingerprint(self, server):
        try:
            key = await asyncio.wait_for(asyncssh.get_server_host_key(
                server['host'], server['port'], config=None), timeout=12)
            if key is None:
                raise UserError('Сервер не передал SSH-ключ.')
            return {'host_key': key.export_public_key().decode('ascii').strip(),
                    'fingerprint': key.get_fingerprint('sha256'), 'algorithm': key.get_algorithm()}
        except UserError:
            raise
        except Exception as exc:
            raise safe_error(exc) from None

    def connection_options(self, server, credentials):
        if not server.get('host_key'):
            raise UserError('Сначала подтвердите отпечаток SSH-сервера.', 'trust_required')
        options = dict(host=server['host'], port=server['port'], username=server['username'],
                       config=None, known_hosts=([asyncssh.import_public_key(server['host_key'])], [], []),
                       connect_timeout=12, login_timeout=15, keepalive_interval=10,
                       gss_host=None, gss_kex=False, gss_auth=False,
                       agent_path=None, client_keys=None, password=None,
                       preferred_auth=['publickey', 'password', 'keyboard-interactive'])
        method = server['auth_method']
        if method == 'password':
            value = credentials.password.get_secret_value()
            if not value:
                raise UserError('Введите пароль для этого обследования.', 'credentials_required')
            options.update(password=value, preferred_auth=['password', 'keyboard-interactive'])
        elif method == 'key':
            path = Path(server['key_path']).expanduser()
            if not server['key_path'].startswith('vault:') and not path.is_file():
                raise UserError('Файл ключа не найден. Выберите существующий приватный ключ.', 'key_missing')
            try:
                phrase=credentials.passphrase.get_secret_value() or None
                if server['key_path'].startswith('vault:'):
                    if not self.key_resolver:raise ValueError('key_resolver_unavailable')
                    key=asyncssh.import_private_key(self.key_resolver(server['key_path']),passphrase=phrase)
                else:key = asyncssh.read_private_key(path, passphrase=phrase)
            except Exception:
                raise UserError('Не удалось прочитать ключ. Проверьте формат и парольную фразу.', 'key_invalid') from None
            options.update(client_keys=[key], preferred_auth=['publickey'])
        else:
            # Explicit agent mode only. AsyncSSH discovers the platform's agent socket.
            options.pop('agent_path')
            options.update(agent_identities=None, preferred_auth=['publickey'])
        return options

    async def audit(self, server, credentials):
        options = self.connection_options(server, credentials)
        try:
            async with asyncio.timeout(45):
                async with asyncssh.connect(**options) as connection:
                    result = await connection.run('sh -s', input=AUDIT_SCRIPT, timeout=25,
                                                  check=False, encoding='utf-8', errors='replace')
                    if len(result.stdout) > 100_000:
                        raise UserError('Ответ обследования превысил допустимый размер.', 'response_limit')
                    if result.exit_status != 0 or 'RD2:' not in result.stdout:
                        raise UserError('Сервер не выполнил обследование. Нужна Linux-оболочка sh.', 'audit_failed')
                    return parse_report(result.stdout)
        except UserError:
            raise
        except Exception as exc:
            raise safe_error(exc) from None


def safe_error(exc):
    # Never pass raw exception text to UI/logs: it may contain paths or credentials.
    frames = []
    current = exc.__traceback__
    while current:
        frames.append(current.tb_frame.f_code.co_name)
        current = current.tb_next
    logging.getLogger('relaydock.ssh').warning('SSH failure type=%s functions=%s', type(exc).__name__, ' > '.join(frames[-5:]))
    if isinstance(exc, asyncssh.HostKeyNotVerifiable):
        return UserError('Ключ сервера не совпал с сохранённым. Доступ остановлен; проверьте сервер через консоль хостера.', 'host_key_changed')
    if isinstance(exc, asyncssh.PermissionDenied):
        return UserError('Сервер отклонил вход. Проверьте пользователя и выбранный способ доступа.', 'authentication_failed')
    if isinstance(exc, (TimeoutError, asyncio.TimeoutError)):
        return UserError('Сервер не ответил вовремя. Проверьте адрес, SSH-порт и доступность сети.', 'timeout')
    if isinstance(exc, OSError):
        return UserError('Не удалось установить SSH-соединение. Проверьте адрес, сеть и SSH-agent, если он выбран.', 'connection_failed')
    return UserError('Не удалось завершить SSH-проверку. Настройки сервера не изменялись.')
