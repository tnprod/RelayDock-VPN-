import asyncio
import secrets
import time
from contextlib import asynccontextmanager
from pathlib import Path
from urllib.parse import urlsplit
from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import FileResponse, JSONResponse
from fastapi.staticfiles import StaticFiles
from pydantic import BaseModel, SecretStr
from . import __version__
from .file_picker import PickerError, select_private_key
from .models import Credentials, PlanInput, ServerInput, TrustInput,ProfileInput,AccessInput,ImportInput
from .manager import Manager
from .profiles import links
from .vault import Vault
import re
import io
from fastapi.responses import Response
from .ssh import SSHService, UserError
from .storage import Store, default_data_dir


def create_app(data_dir=None, bootstrap_token=None, ssh_service=None):
    token = bootstrap_token or secrets.token_urlsafe(32)
    session = secrets.token_urlsafe(32)
    store = Store(data_dir or default_data_dir())
    def key_resolver(reference):
        key_id=reference.removeprefix('vault:')
        if not re.fullmatch('[a-f0-9]{32}',key_id):raise ValueError('invalid_key_reference')
        return Vault(store.directory).decrypt((store.directory/'keys'/(key_id+'.enc')).read_text())['content']
    ssh = ssh_service or SSHService(key_resolver=key_resolver)
    challenges = {}
    busy = set()
    picker_lock = asyncio.Lock()
    manager=Manager(store,ssh)

    @asynccontextmanager
    async def lifespan(app):
        yield
        tasks=[j['task'] for j in manager.jobs.values() if j['status']=='running']
        for task in tasks:task.cancel()
        if tasks:await asyncio.wait(tasks,timeout=8)
        store.close()

    app = FastAPI(title='RelayDock', docs_url=None, redoc_url=None, openapi_url=None, lifespan=lifespan)
    app.state.store = store
    app.state.bootstrap_token = token
    app.state.manager=manager

    @app.middleware('http')
    async def protect(request, call_next):
        # Reject DNS rebinding, cross-origin requests and requests from non-loopback clients.
        hostname = request.url.hostname
        if hostname not in {'127.0.0.1', 'localhost', 'testserver'}:
            return JSONResponse({'detail': 'Недопустимый адрес приложения.'}, status_code=403)
        client = request.client.host if request.client else ''
        if client not in {'127.0.0.1', '::1', 'testclient'}:
            return JSONResponse({'detail': 'Доступ разрешён только с этого компьютера.'}, status_code=403)
        origin = request.headers.get('origin')
        if origin and origin != f'{request.url.scheme}://{request.url.netloc}':
            return JSONResponse({'detail': 'Запрос из другого источника отклонён.'}, status_code=403)
        if request.headers.get('sec-fetch-site') == 'cross-site':
            return JSONResponse({'detail': 'Межсайтовый запрос отклонён.'}, status_code=403)
        if request.url.path.startswith('/api/'):
            try:
                length = int(request.headers.get('content-length', '0'))
            except ValueError:
                return JSONResponse({'detail': 'Некорректный запрос.'}, status_code=400)
            if length > 131072:
                return JSONResponse({'detail': 'Запрос слишком большой.'}, status_code=413)
            if request.method not in {'GET', 'HEAD'} and request.headers.get('x-relaydock-client') != 'local':
                return JSONResponse({'detail': 'Нужен запрос из приложения.'}, status_code=403)
            if request.url.path != '/api/session' and not secrets.compare_digest(request.cookies.get('rd_session', ''), session):
                return JSONResponse({'detail': 'Откройте RelayDock через программу запуска.'}, status_code=401)
        response = await call_next(request)
        response.headers.update({'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff',
                                 'Referrer-Policy': 'no-referrer', 'X-Frame-Options': 'DENY',
                                 'Content-Security-Policy': "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; connect-src 'self'; frame-ancestors 'none'; base-uri 'none'; form-action 'self'"})
        return response

    @app.exception_handler(RequestValidationError)
    async def validation_error(request, exc):
        # Pydantic's default errors include the rejected input, potentially a password.
        return JSONResponse({'detail': 'Проверьте поля формы: адрес, порт, имя пользователя и способ доступа.'}, status_code=422)

    @app.exception_handler(UserError)
    async def user_error(request, exc):
        return JSONResponse({'detail': str(exc), 'code': exc.code}, status_code=400)

    def require_server(server_id, private=False):
        value = store.get(server_id, private)
        if value is None:
            raise UserError('Сервер не найден.', 'not_found')
        return value

    class SessionInput(BaseModel):
        token: SecretStr

    @app.post('/api/session')
    async def login(value: SessionInput):
        if not secrets.compare_digest(value.token.get_secret_value(), token):
            return JSONResponse({'detail': 'Недействительный сеанс. Перезапустите приложение.'}, status_code=401)
        response = JSONResponse({'ok': True})
        response.set_cookie('rd_session', session, httponly=True, samesite='strict', path='/')
        return response

    @app.get('/api/state')
    async def state():
        return {'version': __version__, 'stage': 'Управление VPN и постоянными ссылками',
                'servers': store.list(), 'plan': store.get_plan(), 'busy_ids': list(busy),
                'profiles':store.profiles(),'jobs':[manager.job(key) for key in list(manager.jobs)[-10:]]}

    @app.post('/api/servers')
    async def add_server(value: ServerInput):
        if value.auth_method == 'key' and not value.key_path:
            raise UserError('Выберите файл приватного ключа.')
        if len(store.list()) >= 100:
            raise UserError('Достигнут лимит: 100 серверов.')
        return store.create(value.model_dump())

    class KeyInput(BaseModel):
        name:str
        content:SecretStr

    @app.post('/api/keys')
    async def upload_key(value:KeyInput):
        content=value.content.get_secret_value().lstrip('\ufeff\r\n ')
        if len(content)>65536 or 'PRIVATE KEY-----' not in content[:100]:
            raise UserError('Выберите приватный SSH-ключ в формате OpenSSH или PEM. Файл .pub не подходит.')
        key_id=secrets.token_hex(16);directory=store.directory/'keys';directory.mkdir(exist_ok=True,mode=0o700)
        path=directory/(key_id+'.enc')
        path.write_text(Vault(store.directory).encrypt({'content':content}),encoding='utf-8');path.chmod(0o600)
        return {'reference':'vault:'+key_id,'name':re.split(r'[/\\]',value.name)[-1][:120]}

    @app.delete('/api/servers/{server_id}')
    async def delete_server(server_id: str):
        require_server(server_id)
        if server_id in busy:
            raise UserError('Дождитесь завершения обследования.')
        try:store.delete(server_id)
        except ValueError as error:raise UserError(str(error)) from None
        return {'ok': True}

    @app.post('/api/profiles')
    async def create_profile(value:ProfileInput):
        if manager.lock.locked():raise UserError('Дождитесь текущей настройки.')
        if value.mode=='relay' and not value.entry_id:raise UserError('Выберите входной сервер.')
        if value.mode=='direct' and (value.entry_vpn_port!=value.exit_vpn_port or value.mtproxy and value.entry_mt_port!=value.exit_mt_port):
            raise UserError('В прямой схеме клиентские и выходные порты должны совпадать.')
        if value.vpn and value.mtproxy and (value.entry_vpn_port==value.entry_mt_port or value.exit_vpn_port==value.exit_mt_port):
            raise UserError('Для VPN и Telegram нужны разные порты.')
        return manager.create(value.model_dump())

    @app.post('/api/profiles/import')
    async def import_profile(value:ImportInput):
        return manager.launch('Подключение существующего VPN',lambda event:manager.import_existing(value.model_dump(exclude={'access'}),value.access,event))

    @app.get('/api/profiles/{profile_id}/links')
    async def profile_links(profile_id:str):
        value=manager.profile(profile_id)
        return {'links':links(value,value['secret']),'status':value['status']}

    @app.get('/api/profiles/{profile_id}/backups')
    async def backups(profile_id:str):
        manager.profile(profile_id)
        return {'backups':store.backups(profile_id)}

    @app.get('/api/profiles/{profile_id}/qr/{index}')
    async def qr(profile_id:str,index:int):
        value=manager.profile(profile_id);items=links(value,value['secret'])
        if not 0<=index<len(items):raise UserError('Ссылка не найдена.')
        import qrcode
        image=qrcode.make(items[index]['uri']);stream=io.BytesIO();image.save(stream,format='PNG')
        return Response(stream.getvalue(),media_type='image/png')

    @app.post('/api/profiles/{profile_id}/backup')
    async def backup(profile_id:str):
        manager.profile(profile_id)
        return {'id':store.backup_profile(profile_id)}

    @app.post('/api/profiles/{profile_id}/deploy')
    async def deploy(profile_id:str,value:AccessInput):
        manager.profile(profile_id)
        return manager.launch('Настройка VPN',lambda event:manager.deploy(profile_id,value.access,event))

    @app.post('/api/profiles/{profile_id}/replace')
    async def replace(profile_id:str,value:AccessInput):
        manager.profile(profile_id)
        if not value.target_id:raise UserError('Выберите новый выходной сервер.')
        manager.server(value.target_id)
        return manager.launch('Замена выходного VPS',lambda event:manager.deploy(profile_id,value.access,event,value.target_id,value.vpn_port,value.mt_port))

    @app.post('/api/profiles/{profile_id}/check')
    async def check(profile_id:str,value:AccessInput):
        manager.profile(profile_id)
        return manager.launch('Проверка передачи данных',lambda event:manager.check(profile_id,value.access,event))

    @app.get('/api/jobs/{job_id}')
    async def job(job_id:str):return manager.job(job_id)

    @app.post('/api/servers/{server_id}/fingerprint')
    async def fingerprint(server_id: str):
        server = require_server(server_id, True)
        if server.get('host_key'):
            raise UserError('Ключ сервера уже сохранён. При его смене заново добавьте сервер после проверки у хостера.')
        if server_id in busy:
            raise UserError('Проверка этого сервера уже выполняется.')
        busy.add(server_id)
        try:
            value = await ssh.fingerprint(server)
            nonce = secrets.token_urlsafe(24)
            challenges[server_id] = dict(value, challenge=nonce, expires=time.monotonic() + 180)
            return {k: value[k] for k in ['fingerprint', 'algorithm']} | {'challenge': nonce}
        finally:
            busy.discard(server_id)

    @app.post('/api/servers/{server_id}/trust')
    async def trust(server_id: str, value: TrustInput):
        server = require_server(server_id, True)
        challenge = challenges.get(server_id)
        if not challenge or challenge['expires'] < time.monotonic() or not secrets.compare_digest(value.challenge, challenge['challenge']) or value.fingerprint != challenge['fingerprint']:
            raise UserError('Подтверждение устарело. Получите отпечаток ещё раз.')
        if server.get('host_key'):
            raise UserError('Ключ уже сохранён.')
        store.trust(server_id, challenge['host_key'], challenge['fingerprint'])
        challenges.pop(server_id, None)
        return store.get(server_id)

    @app.post('/api/servers/{server_id}/audit')
    async def audit(server_id: str, credentials: Credentials):
        server = require_server(server_id, True)
        if server_id in busy:
            raise UserError('Обследование этого сервера уже выполняется.')
        busy.add(server_id)
        try:
            report = await ssh.audit(server, credentials)
            store.report(server_id, report)
            return store.get(server_id)
        finally:
            busy.discard(server_id)

    @app.post('/api/plan')
    async def plan(value: PlanInput):
        if not value.vpn and not value.mtproxy:
            raise UserError('Выберите VPN, Telegram или оба сервиса.')
        exit_server = require_server(value.exit_id) if value.exit_id else None
        entry_server = require_server(value.entry_id) if value.entry_id and value.mode == 'relay' else None
        if value.mode == 'relay' and value.entry_id and value.entry_id == value.exit_id:
            raise UserError('Для ретранслятора нужны два разных сервера.')
        if entry_server and exit_server and entry_server['host'] == exit_server['host']:
            raise UserError('Входной и выходной VPS должны иметь разные адреса.')
        blockers = []
        if not exit_server:
            blockers.append('Выберите выходной VPS.')
        if value.mode == 'relay' and not entry_server:
            blockers.append('Выберите входной VPS.')
        for server in [s for s in [entry_server, exit_server] if s]:
            if not server['report']:
                blockers.append(f'Обследуйте сервер «{server["name"]}».')
            elif not server['report']['install_os_supported']:
                blockers.append(f'Для ОС сервера «{server["name"]}» установка ещё не проверена.')
            if server['report'] and server['report']['privileges'] == 'unavailable':
                blockers.append(f'На сервере «{server["name"]}» потребуются права root или sudo.')
        result = value.model_dump() | {
            'blockers': blockers,
            'steps': ['Сохранить резервную копию существующей конфигурации.',
                      ('Подготовить Xray и управление через 3x-ui.' if value.manager == '3x-ui' else 'Подготовить Xray под управлением RelayDock.')] if value.vpn else ['Сохранить резервную копию существующей конфигурации.'],
            'executable': False,
            'notice': 'Это предварительная схема. Установщик, миграция и изменение безопасности появятся на следующих этапах.',
        }
        if value.mtproxy:
            result['steps'].append('Подготовить MTProxy для Telegram.')
        if value.mode == 'relay':
            result['steps'].append('Подготовить пересылку на входном VPS после проверки выхода.')
        result['steps'].append('Проверить передачу данных и подготовить клиентские ссылки.')
        store.save_plan(result)
        return result

    @app.post('/api/select-key')
    async def select_key():
        if picker_lock.locked():
            raise UserError('Окно выбора файла уже открыто. Завершите выбор или нажмите «Отмена».', 'picker_busy')
        async with picker_lock:
            try:
                path = await asyncio.to_thread(select_private_key)
                return {'path': path}
            except PickerError as exc:
                raise UserError(str(exc), 'picker_failed') from None
            except Exception:
                raise UserError('Не удалось открыть выбор файла. Вставьте путь к ключу вручную.', 'picker_failed') from None

    static = Path(__file__).parent / 'static'
    @app.get('/')
    async def index():
        return FileResponse(static / 'index.html')
    app.mount('/assets', StaticFiles(directory=static, check_dir=False), name='assets')
    return app
