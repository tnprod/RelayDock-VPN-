import argparse
import tempfile
import asyncio
import json
import os
from pathlib import Path
import subprocess
import sys
import time
import zipfile

import asyncssh
import httpx

PROJECT = Path(__file__).resolve().parent.parent
sys.path[:0] = [str(PROJECT), str(PROJECT/'tests')]
from test_ssh import REPORT

parser=argparse.ArgumentParser(description='Check packaged RelayDock on a local SSH fixture')
choice=parser.add_mutually_exclusive_group(required=True)
choice.add_argument('--archive',type=Path)
choice.add_argument('--exe',type=Path)
args=parser.parse_args()
if os.name != 'nt':
    parser.error('This smoke test needs Windows')
temporary=tempfile.TemporaryDirectory(prefix='relaydock-release-test-')
WORK=Path(temporary.name)
DATA=WORK/'data'
if args.archive:
    with zipfile.ZipFile(args.archive) as archive:
        archive.extractall(WORK/'unpacked')
    EXE=WORK/'unpacked'/'RelayDock'/'RelayDock.exe'
else:
    EXE=args.exe.resolve()
CAPTURE = WORK/'capture_browser.py'
CAPTURE.write_text("import os,sys\nfrom pathlib import Path\nPath(os.environ['RD_CAPTURE_FILE']).write_text(sys.argv[1],encoding='utf-8')\n",encoding='utf-8')


class Fixture(asyncssh.SSHServer):
    key = None
    passwords = []
    commands = []
    def begin_auth(self, username):
        return True
    def password_auth_supported(self):
        return True
    def public_key_auth_supported(self):
        return True
    def validate_password(self, username, password):
        self.passwords.append(password)
        return username == 'operator' and password == 'release-test-secret'
    def validate_public_key(self, username, key):
        return username == 'operator' and key == self.key.convert_to_public()


async def process_factory(process):
    script = await process.stdin.read()
    Fixture.commands.append(process.command)
    if process.command != 'sh -s' or 'RD2:os' not in script:
        process.exit(1)
        return
    process.stdout.write(REPORT)
    process.exit(0)


checks = []
def check(condition, label):
    if not condition:
        raise AssertionError(label)
    checks.append(label)
    print('PASS:', label, flush=True)


async def launch(number):
    capture_file=WORK/f'url-{number}.txt'
    if capture_file.exists():
        capture_file.unlink()
    env=dict(os.environ, BROWSER=f'"{Path(sys.executable).as_posix()}" "{CAPTURE.as_posix()}" %s', RD_CAPTURE_FILE=str(capture_file))
    log=(WORK/f'process-{number}.log').open('wb')
    child=subprocess.Popen([str(EXE),'--data-dir',str(DATA)],env=env,stdout=log,stderr=log,
                           creationflags=subprocess.CREATE_NO_WINDOW)
    try:
        for _ in range(250):
            if capture_file.exists():
                url=capture_file.read_text(encoding='utf-8')
                if '#token=' in url:
                    base,token=url.split('/#token=',1)
                    return child,log,base,token
            if child.poll() is not None:
                raise RuntimeError('Frozen app exited; inspect local test log')
            await asyncio.sleep(.1)
        raise TimeoutError('Frozen app did not open browser')
    except BaseException:
        child.terminate();child.wait(timeout=5);log.close()
        raise


async def main():
    key=asyncssh.generate_private_key('ssh-ed25519')
    Fixture.key=asyncssh.generate_private_key('ssh-ed25519')
    encrypted=WORK/'temporary-test-key'
    Fixture.key.write_private_key(encrypted,passphrase='release-test-phrase')
    fixture=await asyncssh.create_server(Fixture,'127.0.0.1',0,server_host_keys=[key],process_factory=process_factory)
    ssh_port=fixture.get_port()
    child=None;log=None
    try:
        child,log,base,token=await launch(1)
        async with httpx.AsyncClient(base_url=base,headers={'X-RelayDock-Client':'local'},timeout=20) as client:
            root=await client.get('/')
            check(root.status_code==200 and 'RelayDock' in root.text,'Frozen EXE serves interface after archive extraction')
            check((await client.get('/assets/app.js')).status_code==200,'Bundled JS is available')
            check((await client.get('/assets/app.css')).status_code==200,'Bundled CSS is available')
            check((await client.get('/api/state')).status_code==401,'API blocks unauthenticated requests')
            check((await client.post('/api/session',json={'token':token})).status_code==200,'Normal launcher creates valid browser session')
            check((await client.get('/api/state',headers={'Origin':'https://other.example'})).status_code==403,'Frozen API blocks cross-origin requests')
            async def add(name,method='password',path=''):
                value={'name':name,'host':'127.0.0.1','port':ssh_port,'username':'operator','auth_method':method,'key_path':path}
                r=await client.post('/api/servers',json=value)
                check(r.status_code==200,f'Add server with {method} authentication')
                return r.json()['id']
            async def trust(server_id):
                r=await client.post(f'/api/servers/{server_id}/fingerprint',json={})
                check(r.status_code==200,'Get host key without authentication')
                value=r.json()
                check(value['fingerprint']==key.get_fingerprint('sha256'),'Fingerprint matches independent test-server key')
                r=await client.post(f'/api/servers/{server_id}/trust',json={'challenge':value['challenge'],'fingerprint':value['fingerprint']})
                check(r.status_code==200,'Pin confirmed host key')
            server_id=await add('Release password test')
            r=await client.post(f'/api/servers/{server_id}/audit',json={'password':'release-test-secret'})
            check(r.status_code==400 and r.json().get('code')=='trust_required','Credentials are not sent before host key confirmation')
            check(Fixture.passwords==[],'Test server received no password before confirmation')
            await trust(server_id)
            r=await client.post(f'/api/servers/{server_id}/audit',json={'password':'wrong-secret'})
            check(r.status_code==400 and r.json().get('code')=='authentication_failed','Wrong password produces safe error')
            check('wrong-secret' not in r.text,'Wrong password is not echoed')
            r=await client.post(f'/api/servers/{server_id}/audit',json={'password':'release-test-secret'})
            check(r.status_code==200 and r.json()['report']['tcp_ports']==[22,443],'Packaged app completes real password SSH exchange')
            key_id=await add('Release encrypted-key test','key',str(encrypted))
            await trust(key_id)
            r=await client.post(f'/api/servers/{key_id}/audit',json={'passphrase':'release-test-phrase'})
            check(r.status_code==200 and r.json()['report']['scope']=='read_only','Packaged bcrypt/crypto supports encrypted OpenSSH keys')
            plan=await client.post('/api/plan',json={'mode':'direct','manager':'3x-ui','exit_id':server_id,'mtproxy':True})
            check(plan.status_code==200 and not plan.json()['executable'],'Scheme saved without pretending installation is implemented')
            state=(await client.get('/api/state')).json()
            check(len(state['servers'])==2,'Both server records are present')
            check(all(value not in json.dumps(state) for value in ['release-test-secret','release-test-phrase']),'State API contains no authentication secrets')
            old_session=client.cookies.get('rd_session')
            fixture.close();await fixture.wait_closed()
            rotated=asyncssh.generate_private_key('ssh-ed25519')
            fixture=await asyncssh.create_server(Fixture,'127.0.0.1',ssh_port,server_host_keys=[rotated],process_factory=process_factory)
            before=len(Fixture.passwords)
            r=await client.post(f'/api/servers/{server_id}/audit',json={'password':'release-test-secret'})
            check(r.status_code==400 and r.json().get('code')=='host_key_changed','Packaged app blocks changed server host key')
            check(len(Fixture.passwords)==before,'Changed-key server receives no password')
            fixture.close();await fixture.wait_closed()
            r=await client.post(f'/api/servers/{server_id}/audit',json={'password':'release-test-secret'})
            check(r.status_code==400 and r.json().get('code')=='connection_failed','Unavailable SSH server produces safe error')
        child.terminate();child.wait(timeout=10);log.close();child=None;log=None
        child,log,base,token=await launch(2)
        async with httpx.AsyncClient(base_url=base,headers={'X-RelayDock-Client':'local'},timeout=20) as client:
            r=await client.get('/api/state',cookies={'rd_session':old_session})
            check(r.status_code==401,'Restart invalidates old session')
            await client.post('/api/session',json={'token':token})
            state=(await client.get('/api/state')).json()
            check(len(state['servers'])==2 and state['servers'][0]['report'],'Records and audit survive process restart')
            check(state['plan']['manager']=='3x-ui','Scheme survives process restart')
            r=await client.delete(f'/api/servers/{server_id}')
            check(r.status_code==200,'Remove local server record')
            state=(await client.get('/api/state')).json()
            check(len(state['servers'])==1,'Local record is removed')
            check(state['plan'] is None or state['plan'].get('exit_id')!=server_id,'Saved scheme does not reference a deleted server')
        for path in (p for p in DATA.rglob('*') if p.is_file()):
            content=path.read_bytes()
            check(b'release-test-secret' not in content and b'release-test-phrase' not in content,'No password or key passphrase in on-disk state')
    finally:
        fixture.close();await fixture.wait_closed()
        if child is not None:
            child.terminate();child.wait(timeout=10)
        if log is not None:
            log.close()
        for log_path in WORK.glob('process-*.log'):
            for line in log_path.read_text(encoding='utf-8',errors='replace').splitlines():
                if 'SSH failure type=' in line:
                    print(line,flush=True)
        (WORK/'checks.json').write_text(json.dumps({'passed':checks},ensure_ascii=False,indent=2),encoding='utf-8')
    print(json.dumps({'passed':len(checks),'checks':checks},ensure_ascii=False,indent=2))

try:
    asyncio.run(main())
finally:
    temporary.cleanup()
