"""Executed on an explicitly selected Ubuntu VPS with JSON on stdin; never imported by the desktop app."""
import hashlib
import json
import os
from pathlib import Path
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import base64
import fcntl

def transaction(files,units,active,created):
    import secrets
    ticket=secrets.token_hex(8)
    directory=Path('/var/lib/relaydock2/jobs');directory.mkdir(parents=True,exist_ok=True,mode=0o700)
    state={'phase':'pending','files':{key:base64.b64encode(value).decode() for key,value in files.items()},'units':units,'active':active,'created':created}
    write(directory/(ticket+'.json'),json.dumps(state))
    program=Path('/opt/relaydock2/transaction.py')
    program.parent.mkdir(parents=True,exist_ok=True,mode=0o755);program.parent.chmod(0o755)
    write(program,TRANSACTION_CODE,0o700)
    run(['systemd-run','--quiet','--on-active=120s','--unit','relaydock2-rollback-'+ticket,'/usr/bin/python3',str(program),ticket,'rollback'])
    return ticket

TRANSACTION_CODE=r'''
import base64,fcntl,json,os,pathlib,subprocess,sys
ticket,action=sys.argv[1:3]
if len(ticket)!=16 or any(x not in '0123456789abcdef' for x in ticket):raise SystemExit(2)
p=pathlib.Path('/var/lib/relaydock2/jobs')/(ticket+'.json')
with open(str(p)+'.lock','a') as lock:
 fcntl.flock(lock,fcntl.LOCK_EX)
 value=json.loads(p.read_text())
 if value['phase']!='pending':
  print(json.dumps({'ok':action=='confirm' and value['phase']=='committed','phase':value['phase']}));raise SystemExit(0)
 if action=='confirm':
  value['phase']='committed';p.write_text(json.dumps(value));subprocess.run(['systemctl','stop','relaydock2-rollback-'+ticket+'.timer'],capture_output=True)
 else:
  for name in value['units']:subprocess.run(['systemctl','stop',name],capture_output=True)
  for path,data in value['files'].items():
   target=pathlib.Path(path);target.parent.mkdir(parents=True,exist_ok=True);target.write_bytes(base64.b64decode(data));target.chmod(0o644 if path.endswith('.service') or path.endswith('.conf') else 0o600)
  for path in value['created']:pathlib.Path(path).unlink(missing_ok=True)
  subprocess.run(['systemctl','daemon-reload'],capture_output=True)
  for name in value['units']:
   if value['active'].get(name):subprocess.run(['systemctl','start',name],capture_output=True)
  value['phase']='rolled_back';p.write_text(json.dumps(value))
 print(json.dumps({'ok':True,'phase':value['phase']}))
'''

def run(args,timeout=90):
    p=subprocess.run(args,capture_output=True,timeout=timeout)
    if p.returncode:raise RuntimeError('command_failed:'+args[0])
    return p.stdout.decode(errors='replace')

def write(path,data,mode=0o600):
    path=Path(path);path.parent.mkdir(parents=True,exist_ok=True,mode=0o700)
    fd,temp=tempfile.mkstemp(prefix='.rd-',dir=path.parent)
    try:
        os.fchmod(fd,mode)
        with os.fdopen(fd,'wb') as out:out.write(data if isinstance(data,bytes) else data.encode())
        os.replace(temp,path)
    finally:
        if os.path.exists(temp):os.unlink(temp)

def available(port):
    if not isinstance(port,int) or not 1<=port<=65535:raise RuntimeError('invalid_port')
    with socket.socket() as sock:
        try:sock.bind(('0.0.0.0',port))
        except OSError:raise RuntimeError('port_in_use:'+str(port)) from None

def install_binary(payload,name):
    item=payload['binaries'][name]
    source=Path(item['temporary'])
    if not str(source).startswith('/tmp/relaydock2-'):raise RuntimeError('invalid_stage')
    if hashlib.sha256(source.read_bytes()).hexdigest()!=item['sha256']:raise RuntimeError('binary_checksum')
    target=Path('/opt/relaydock2')/name
    target.parent.mkdir(parents=True,exist_ok=True,mode=0o755);target.parent.chmod(0o755)
    write(target,source.read_bytes(),0o755)
    source.unlink()
    return str(target)

def firewall(ports):
    if shutil.which('ufw') and 'Status: active' in run(['ufw','status']):
        for port in ports:run(['ufw','allow',str(port)+'/tcp'])

def service(profile_id,kind,exec_start,credential):
    credential_name='config'+Path(credential).suffix
    exec_start=exec_start.replace('%d/config','%d/'+credential_name)
    return f'''[Unit]
Description=RelayDock managed {kind}
Wants=network-online.target
After=network-online.target
[Service]
Type=simple
DynamicUser=yes
LoadCredential={credential_name}:{credential}
ExecStart={exec_start}
Restart=on-failure
RestartSec=2
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=strict
ProtectHome=yes
AmbientCapabilities=CAP_NET_BIND_SERVICE
CapabilityBoundingSet=CAP_NET_BIND_SERVICE
RestrictAddressFamilies=AF_UNIX AF_INET AF_INET6
LimitNOFILE=65536
[Install]
WantedBy=multi-user.target
'''

def managed_install(payload):
    release=Path('/etc/os-release').read_text()
    if 'ID=ubuntu' not in release or 'VERSION_ID="24.04"' not in release:raise RuntimeError('unsupported_os')
    import platform
    if platform.machine() not in ['x86_64','amd64']:raise RuntimeError('unsupported_architecture')
    profile_id=payload['profile_id']
    if not re.fullmatch('[a-f0-9]{32}',profile_id):raise RuntimeError('invalid_profile_id')
    kind=payload['kind'];base=Path('/etc/relaydock2')/profile_id
    ownership=base/'owner.json'
    if ownership.exists() and json.loads(ownership.read_text())['profile_id']!=profile_id:raise RuntimeError('owner_mismatch')
    units=[];ports=[];backup={};created=[]
    if kind=='exit':
        if payload['vpn']:
            port=payload['xray_config']['inbounds'][0]['port'];ports.append(port)
            name=f'relaydock2-{profile_id}-vpn.service'
            units.append(name)
            if not Path('/etc/systemd/system',name).exists():available(port)
            binary=install_binary(payload,'xray')
            config=base/'xray.json'
            files={str(config):json.dumps(payload['xray_config']),'/etc/systemd/system/'+name:service(profile_id,'VPN',binary+' run -config %d/config',str(config))}
        else:files={}
        if payload['mtproxy']:
            port=payload['mt_port'];ports.append(port)
            name=f'relaydock2-{profile_id}-mtproxy.service';units.append(name)
            if not Path('/etc/systemd/system',name).exists():available(port)
            binary=install_binary(payload,'mtg');config=base/'mtg.toml'
            text='\n'.join(['debug = false','secret = '+json.dumps(payload['mt_secret']),f'bind-to = "0.0.0.0:{port}"',
                 'prefer-ip = "only-ipv4"','auto-update = false','[defense.blocklist]','enabled = false',''])
            files[str(config)]=text;files['/etc/systemd/system/'+name]=service(profile_id,'Telegram',binary+' run %d/config',str(config))
    elif kind=='entry':
        name=f'relaydock2-{profile_id}-entry.service';units.append(name)
        ports=[route['listen'] for route in payload['routes']]
        if not Path('/etc/systemd/system',name).exists():
            for port in ports:available(port)
        relay=Path('/opt/relaydock2/relay.py');write(relay,payload['relay_source'],0o755)
        config=base/'routes.json'
        files={str(config):json.dumps(payload['routes']),'/etc/systemd/system/'+name:service(profile_id,'entry','/usr/bin/python3 '+str(relay)+' %d/config',str(config))}
    else:raise RuntimeError('unknown_kind')
    for path in files:
        p=Path(path)
        if p.exists():backup[path]=p.read_bytes()
        else:created.append(path)
    old_active={name:subprocess.run(['systemctl','is-active','--quiet',name]).returncode==0 for name in units}
    ticket=transaction(backup,units,old_active,created) if kind=='entry' else None
    try:
        for path,data in files.items():write(path,data,0o644 if path.endswith('.service') else 0o600)
        write(ownership,json.dumps({'profile_id':profile_id,'kind':kind}))
        run(['systemctl','daemon-reload'])
        for name in units:run(['systemctl','enable',name]);run(['systemctl','restart',name])
        for port in ports:
            for _ in range(60):
                try:
                    with socket.create_connection(('127.0.0.1',port),timeout=.2):break
                except OSError:time.sleep(.2)
            else:raise RuntimeError('service_not_listening:'+str(port))
        if payload.get('configure_firewall'):firewall(ports)
    except BaseException:
        for name in units:subprocess.run(['systemctl','stop',name],capture_output=True)
        for path,data in backup.items():write(path,data,0o644 if path.endswith('.service') else 0o600)
        for path in created:Path(path).unlink(missing_ok=True)
        run(['systemctl','daemon-reload'])
        for name in units:
            if old_active[name]:subprocess.run(['systemctl','start',name],capture_output=True)
        raise
    return {'ok':True,'units':units,'ports':ports,'ticket':ticket}

def legacy_route(payload):
    """Switch only previously imported forwarders; keep a reversible unit override."""
    target=payload['target']
    if not re.fullmatch('[a-zA-Z0-9.-]+',target):raise RuntimeError('invalid_host')
    backup={};names=[]
    for name,value in payload['units'].items():
        if name not in ['codex-forward-vpn.service','codex-forward-mtproxy.service']:raise RuntimeError('unsupported_unit')
        destination=f'TCP4:{target}:{int(value["target_port"])}'
        text=value['text']
        lines=[line for line in text.splitlines() if line.startswith('ExecStart=') and line!='ExecStart=']
        if not lines:raise RuntimeError('unsupported_unit')
        original=value.get('exec_start') or lines[-1].split('=',1)[1]
        updated=re.sub(r'TCP(?:4|6)?(?:-CONNECT)?:[^\s,:]+:\d+',destination,original)
        if updated==original and destination not in original:raise RuntimeError('no_route_found')
        path=Path('/etc/systemd/system')/(name+'.d')/'90-relaydock.conf'
        backup[str(path)]=path.read_text() if path.exists() else None
        value['new_text']='[Service]\nExecStart=\nExecStart='+updated+'\n'
        names.append(name)
    ticket=transaction({path:content.encode() for path,content in backup.items() if content is not None},names,{name:True for name in names},[path for path,content in backup.items() if content is None])
    for name,value in payload['units'].items():
        write(Path('/etc/systemd/system')/(name+'.d')/'90-relaydock.conf',value['new_text'],0o644)
    run(['systemctl','daemon-reload'])
    try:
        for name in names:run(['systemctl','restart',name])
    except BaseException:
        for path,content in backup.items():
            if content is None:Path(path).unlink(missing_ok=True)
            else:write(path,content,0o644)
        run(['systemctl','daemon-reload'])
        for name in names:subprocess.run(['systemctl','restart',name],capture_output=True)
        raise
    return {'ok':True,'backup':backup,'units':names,'ticket':ticket}

if __name__=='__main__':
    try:
        if os.getuid()!=0:raise RuntimeError('root_required')
        payload=json.load(sys.stdin)
        if payload['action']=='install':result=managed_install(payload)
        elif payload['action']=='legacy-route':result=legacy_route(payload)
        elif payload['action'] in ['confirm','rollback']:
            ticket=payload['ticket']
            if not re.fullmatch('[a-f0-9]{16}',ticket):raise RuntimeError('invalid_ticket')
            result=json.loads(run(['/usr/bin/python3','/opt/relaydock2/transaction.py',ticket,payload['action']]))
        else:raise RuntimeError('unsupported_action')
        print(json.dumps(result))
    except Exception as error:
        # Deliberately omit raw commands/configuration and secrets.
        print(json.dumps({'ok':False,'error':str(error) if isinstance(error,RuntimeError) else type(error).__name__}))
        sys.exit(1)
