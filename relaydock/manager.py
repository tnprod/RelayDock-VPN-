import asyncio
import copy
import hashlib
import json
import os
from pathlib import Path
import secrets
import shlex
import time
import uuid
import asyncssh
from . import legacy
from .models import Credentials
from .profiles import exit_config, identity, links, public_key
from .runtime import fetch
from .probe import probe
from .ssh import UserError, safe_error

class Manager:
    def __init__(self,store,ssh):
        self.store=store;self.ssh=ssh
        self.jobs={};self.lock=asyncio.Lock()
        self.cache=store.directory/'runtime';self.cache.mkdir(exist_ok=True)

    def profile(self,profile_id):
        item=self.store.profile(profile_id,True)
        if not item:raise UserError('Подключение не найдено.')
        return item

    def server(self,server_id):
        item=self.store.get(server_id,True)
        if not item:raise UserError('Добавьте сервер в список.')
        if not item.get('host_key'):raise UserError('Сначала подтвердите первое подключение к этому серверу.')
        return item

    def launch(self,title,operation):
        if self.lock.locked() or any(j['status']=='running' for j in self.jobs.values()):
            raise UserError('Дождитесь завершения текущей настройки.')
        job_id=uuid.uuid4().hex
        self.jobs[job_id]={'id':job_id,'title':title,'status':'running','events':[],'started_at':time.time()}
        def event(text):self.jobs[job_id]['events'].append({'time':time.time(),'text':text})
        async def work():
            async with self.lock:
                try:
                    result=await operation(event)
                    self.jobs[job_id].update(status='done',result=result,finished_at=time.time())
                except Exception as error:
                    message=str(error) if isinstance(error,UserError) else 'Действие не завершено. Работающий маршрут не подтверждён; проверьте состояние и журнал этапов.'
                    self.jobs[job_id].update(status='failed',error=message,error_type=type(error).__name__,finished_at=time.time())
        task=asyncio.create_task(work())
        self.jobs[job_id]['task']=task
        return self.job(job_id)

    def job(self,job_id):
        value=self.jobs.get(job_id)
        if value is None:raise UserError('Задача не найдена. Проверьте состояние подключения.')
        return {key:value for key,value in value.items() if key!='task'}

    def credentials(self,access,server_id):
        value=access.get(server_id)
        if value is None:return Credentials()
        return value if isinstance(value,Credentials) else Credentials(**value)

    async def execute(self,server_id,access,source,payload,timeout=120,resources=None):
        server=self.server(server_id)
        options=self.ssh.connection_options(server,self.credentials(access,server_id))
        staged=[]
        try:
            async with asyncssh.connect(**options) as connection:
                if resources:
                    async with connection.start_sftp_client() as sftp:
                        for name,path in resources.items():
                            remote='/tmp/relaydock2-'+secrets.token_hex(16)
                            await sftp.put(str(path),remote);await sftp.chmod(remote,0o600)
                            staged.append(remote)
                            payload.setdefault('binaries',{})[name]={'temporary':remote,'sha256':hashlib.sha256(path.read_bytes()).hexdigest()}
                command='/usr/bin/python3 -c '+shlex.quote('exec(bytes.fromhex("'+source.encode().hex()+'"))')
                if server['username']!='root':command='sudo -n '+command
                try:
                    result=await connection.run(command,input=json.dumps(payload),timeout=timeout,encoding='utf-8',errors='replace')
                finally:
                    if staged:
                        async with connection.start_sftp_client() as sftp:
                            for path in staged:
                                try:await sftp.remove(path)
                                except (OSError,asyncssh.SFTPError):pass
            try:value=json.loads(result.stdout)
            except (ValueError,TypeError):raise UserError('Сервер не вернул результат. Проверьте доступ root/sudo и Python 3.') from None
            if result.exit_status or value.get('ok') is False:
                code=value.get('error','remote_failed')
                if code.startswith('port_in_use:'):raise UserError('Порт '+code.split(':',1)[1]+' уже занят. Работающая служба сохранена. Выберите другой порт.')
                raise UserError('Сервер отклонил изменение: '+code[:100])
            return value
        except UserError:raise
        except Exception as error:raise safe_error(error) from None

    async def remote(self,server_id,access,payload,resources=None):
        source=(Path(__file__).parent/'remote_agent.py').read_text(encoding='utf-8')
        return await self.execute(server_id,access,source,payload,180,resources)

    async def binaries(self,mtproxy=False):
        items={'xray':await asyncio.to_thread(fetch,'xray-linux',self.cache)}
        if mtproxy:items['mtg']=await asyncio.to_thread(fetch,'mtg-linux',self.cache)
        return items

    async def verify(self,profile,secret,event,host=None,port=None):
        result={}
        if profile.get('vpn',True):
            event('Проверяем HTTPS через настоящее VPN-подключение.')
            binary=await asyncio.to_thread(fetch,'xray-windows' if os.name=='nt' else 'xray-linux',self.cache)
            try:result['vpn']=await asyncio.to_thread(probe,binary,profile,secret,self.store.directory,host,port)
            except Exception:raise UserError('VPN не передаёт HTTPS с этого компьютера. Проверьте доступность портов и домен маскировки. Смена маршрута не будет подтверждена.') from None
        if profile.get('mtproxy'):
            from .mtprobe import probe as mt_probe
            event('Проверяем секрет MTProxy и ответ Telegram.')
            address=host or profile['public_host'];target_port=profile['exit_mt_port'] if host else profile['entry_mt_port']
            try:
                check=await asyncio.to_thread(mt_probe,address,target_port,secret['mtproxy_secret'])
                if not check.get('rpc_verified'):raise RuntimeError('rpc_unverified')
                result['telegram']=check
            except Exception:raise UserError('Telegram-прокси не прошёл проверку передачи данных. Смена маршрута не подтверждена.') from None
        return {'ok':True,'checked_at':time.time(),'checks':result}

    async def import_existing(self,value,access,event):
        entry=self.server(value['entry_id']);exit_server=self.server(value['exit_id'])
        event('Читаем существующий маршрут без изменения служб.')
        incoming=await self.execute(entry['id'],access,legacy.DISCOVER,{'kind':'entry'})
        if incoming['vpn']['host']!=exit_server['host']:
            raise UserError('Выбранный выход не совпадает с текущим маршрутом входного сервера. Выберите действующий выход.')
        outgoing=await self.execute(exit_server['id'],access,legacy.DISCOVER,{'kind':'exit'})
        parsed=legacy.parse_exit(outgoing);secret=parsed['secret']
        profile={'id':uuid.uuid4().hex,'name':value.get('name') or 'Постоянное подключение','mode':'relay',
                 'entry_id':entry['id'],'exit_id':exit_server['id'],'public_host':value.get('public_host') or entry['host'],
                 'entry_vpn_port':incoming['vpn']['port'],'exit_vpn_port':parsed['vpn_port'],
                 'entry_mt_port':incoming.get('mt',{}).get('port',8444),'exit_mt_port':parsed['mt_port'],
                 'vpn':True,'mtproxy':bool(incoming.get('mt') and secret.get('mtproxy_secret')),
                 'kind':'legacy','status':'saved','created_at':time.time(),'client_count':len(secret['clients'])}
        secret['legacy_entry']=incoming
        self.store.save_profile(profile,secret)
        self.store.backup_profile(profile['id'])
        event('Ссылки, ключи и исходный маршрут сохранены в защищённом хранилище.')
        try:
            profile['last_check']=await self.verify(profile,secret,event)
            profile['status']='active'
        except UserError as error:
            profile['last_check']={'ok':False,'message':str(error),'checked_at':time.time()};profile['status']='needs_check'
        self.store.save_profile(profile,secret)
        return {'profile_id':profile['id'],'status':profile['status']}

    def create(self,value):
        self.server(value['exit_id'])
        if value['mode']=='relay':
            self.server(value['entry_id'])
            if value['entry_id']==value['exit_id']:raise UserError('Вход и выход должны быть разными серверами.')
        if not value['vpn'] and not value['mtproxy']:raise UserError('Выберите хотя бы один сервис.')
        secret=identity(value['name'],value['server_name'])
        profile={key:item for key,item in value.items() if key!='server_name'}
        profile.update(id=uuid.uuid4().hex,kind='managed',status='draft',created_at=time.time(),client_count=1)
        self.store.save_profile(profile,secret)
        return profile

    async def install_exit(self,profile,secret,access,event):
        event('Загружаем проверенные Xray'+(' и MTProxy.' if profile['mtproxy'] else '.'))
        resources=await self.binaries(profile['mtproxy'])
        event('Устанавливаем отдельные службы на выбранном выходном VPS.')
        return await self.remote(profile['exit_id'],access,{'action':'install','kind':'exit','profile_id':profile['id'],
          'vpn':profile['vpn'],'mtproxy':profile['mtproxy'],'xray_config':exit_config(profile,secret),
          'mt_port':profile['exit_mt_port'],'mt_secret':secret['mtproxy_secret'],'configure_firewall':True},resources)

    async def route(self,profile,secret,access,event):
        target=self.server(profile['exit_id'])['host']
        if profile['kind']=='legacy':
            units={}
            for key,port in [('vpn',profile['exit_vpn_port']),('mt',profile['exit_mt_port'])]:
                if key in secret['legacy_entry'] and (key=='vpn' and profile['vpn'] or key=='mt' and profile['mtproxy']):
                    item=copy.deepcopy(secret['legacy_entry'][key]);item['target_port']=port;units[item['unit']]=item
            return await self.remote(profile['entry_id'],access,{'action':'legacy-route','target':target,'units':units})
        routes=[]
        if profile['vpn']:routes.append({'listen':profile['entry_vpn_port'],'host':target,'port':profile['exit_vpn_port']})
        if profile['mtproxy']:routes.append({'listen':profile['entry_mt_port'],'host':target,'port':profile['exit_mt_port']})
        return await self.remote(profile['entry_id'],access,{'action':'install','kind':'entry','profile_id':profile['id'],
               'routes':routes,'configure_firewall':True,'relay_source':(Path(__file__).parent/'relay.py').read_text(encoding='utf-8')})

    async def deploy(self,profile_id,access,event,target_id=None,vpn_port=None,mt_port=None):
        old=self.profile(profile_id);secret=old.pop('secret');profile=copy.deepcopy(old)
        if target_id:profile['exit_id']=target_id
        if vpn_port:profile['exit_vpn_port']=vpn_port
        if mt_port:profile['exit_mt_port']=mt_port
        target=self.server(profile['exit_id'])
        if profile['mode']=='relay' and self.server(profile['entry_id'])['host']==target['host']:raise UserError('Выход должен отличаться от входного сервера.')
        previous_links=links(old,secret)
        self.store.backup_profile(profile_id)
        event('Сохранили резервную копию ссылок, ключей и предыдущего маршрута.')
        # Download the client before the timed route change.
        if profile['vpn']:await asyncio.to_thread(fetch,'xray-windows' if os.name=='nt' else 'xray-linux',self.cache)
        await self.install_exit(profile,secret,access,event)
        await self.verify(profile,secret,event,target['host'],profile['exit_vpn_port'])
        transaction=None
        try:
            if profile['mode']=='relay':
                event('Переключаем постоянный вход. При потере связи сервер сам вернёт прежний маршрут через 120 секунд.')
                transaction=await self.route(profile,secret,access,event)
            else:
                if profile['public_host']!=target['host']:
                    import socket
                    if socket.gethostbyname(profile['public_host'])!=socket.gethostbyname(target['host']):
                        raise UserError('Обновите DNS вашего постоянного домена на новый VPS, затем повторите проверку.')
                elif target_id and target_id!=old['exit_id']:
                    raise UserError('Для сохранения прямой ссылки при замене VPS нужен постоянный домен. Выберите relay или настройте домен.')
            profile['last_check']=await self.verify(profile,secret,event)
            if transaction and transaction.get('ticket'):
                result=await self.remote(profile['entry_id'],access,{'action':'confirm','ticket':transaction['ticket']})
                if not result.get('ok'):raise UserError('Сервер уже выполнил откат. Повторите проверку прежнего маршрута.')
        except BaseException:
            if transaction and transaction.get('ticket'):
                try:await self.remote(profile['entry_id'],access,{'action':'rollback','ticket':transaction['ticket']})
                except Exception:event('Связь потеряна. Серверный таймер вернёт прежний маршрут автоматически.')
            raise
        if links(profile,secret)!=previous_links:raise UserError('Операция меняет постоянную ссылку и остановлена.')
        profile['status']='active';profile['updated_at']=time.time()
        self.store.save_profile(profile,secret)
        event('Трафик проверен. Постоянные ссылки сохранены без изменений.')
        return {'profile_id':profile_id,'links_changed':False,'status':'active'}

    async def check(self,profile_id,access,event):
        profile=self.profile(profile_id);secret=profile.pop('secret')
        try:
            profile['last_check']=await self.verify(profile,secret,event);profile['status']='active'
        except UserError as error:
            profile['last_check']={'ok':False,'message':str(error),'checked_at':time.time()};profile['status']='needs_check'
        self.store.save_profile(profile,secret)
        return {'profile_id':profile_id,'check':profile['last_check']}
