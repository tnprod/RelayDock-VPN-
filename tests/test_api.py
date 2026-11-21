import tempfile
import unittest
import asyncssh
from fastapi.testclient import TestClient
from relaydock.api import create_app
from relaydock.ssh import parse_report
from test_ssh import REPORT


class FakeSSH:
    def __init__(self):
        self.key = asyncssh.generate_private_key('ssh-ed25519')
        self.calls = []
    async def fingerprint(self, server):
        self.calls.append('fingerprint')
        return {'host_key': self.key.export_public_key().decode(),
                'fingerprint': self.key.get_fingerprint('sha256'), 'algorithm': 'ssh-ed25519'}
    async def audit(self, server, credentials):
        self.calls.append('audit')
        if not server.get('host_key'):
            from relaydock.ssh import UserError
            raise UserError('Нужно подтверждение', 'trust_required')
        return parse_report(REPORT)


class APITests(unittest.TestCase):
    def setUp(self):
        self.directory = tempfile.TemporaryDirectory()
        self.ssh = FakeSSH()
        self.app = create_app(self.directory.name, 'test-bootstrap', self.ssh)
        self.client = TestClient(self.app)
        self.client.__enter__()
        self.headers = {'X-RelayDock-Client': 'local'}
        self.client.post('/api/session', json={'token': 'test-bootstrap'}, headers=self.headers)

    def tearDown(self):
        self.client.__exit__(None, None, None)
        self.directory.cleanup()

    def post(self, path, data):
        return self.client.post('/api/' + path, json=data, headers=self.headers)

    def add(self, host='vps.example.net', **kwargs):
        return self.post('servers', dict(name='Test VPS', host=host, **kwargs)).json()

    def trust(self, server):
        value = self.post(f'servers/{server["id"]}/fingerprint', {}).json()
        return self.post(f'servers/{server["id"]}/trust',
                         {'challenge': value['challenge'], 'fingerprint': value['fingerprint']})

    def test_password_server_needs_no_key(self):
        server = self.add()
        self.assertEqual(server['auth_method'], 'password')
        self.assertEqual(server['key_path'], '')

    def test_cross_origin_and_rebinding_rejected(self):
        r = self.client.get('/api/state', headers={'Origin': 'https://other.example'})
        self.assertEqual(r.status_code, 403)
        r = self.client.get('/api/state', headers={'Host': 'attacker.example'})
        self.assertEqual(r.status_code, 403)
        r = self.client.get('/api/state', headers={'Sec-Fetch-Site': 'cross-site'})
        self.assertEqual(r.status_code, 403)

    def test_api_requires_session_and_non_simple_header(self):
        self.assertEqual(self.client.post('/api/servers', json={}).status_code, 403)
        self.client.cookies.clear()
        self.assertEqual(self.client.get('/api/state').status_code, 401)
        self.assertEqual(self.post('session', {'token': 'wrong-token'}).status_code, 401)

    def test_validated_inputs_are_not_echoed(self):
        response = self.post('servers', {'name': 'VPS', 'host': 'vps.example.net', 'password': 'never-echo-me'})
        self.assertEqual(response.status_code, 422)
        self.assertNotIn('never-echo-me', response.text)

    def test_trust_challenge_cannot_be_forged_or_replayed(self):
        server = self.add()
        path = f'servers/{server["id"]}'
        value = self.post(path + '/fingerprint', {}).json()
        self.assertEqual(self.post(path+'/trust', {'challenge':'x'*25,'fingerprint':value['fingerprint']}).status_code, 400)
        body = {'challenge':value['challenge'], 'fingerprint':value['fingerprint']}
        self.assertEqual(self.post(path+'/trust', body).status_code, 200)
        self.assertEqual(self.post(path+'/trust', body).status_code, 400)
        self.assertNotIn('host_key', self.client.get('/api/state').text)

    def test_audit_and_secrets_not_persisted(self):
        server = self.add()
        self.assertEqual(self.trust(server).status_code, 200)
        result = self.post(f'servers/{server["id"]}/audit', {'password':'temporary-test-secret'})
        self.assertEqual(result.status_code, 200)
        self.assertEqual(result.json()['report']['tcp_ports'], [22, 443])
        from pathlib import Path
        for path in Path(self.directory.name).rglob('*'):
            if path.is_file():self.assertNotIn(b'temporary-test-secret', path.read_bytes())
        self.assertNotIn('temporary-test-secret', self.client.get('/api/state').text)

    def test_relay_requires_distinct_servers(self):
        server = self.add()
        result = self.post('plan', {'mode':'relay','entry_id':server['id'],'exit_id':server['id']})
        self.assertEqual(result.status_code, 400)

    def test_plan_is_honest_and_persists(self):
        server = self.add()
        result = self.post('plan', {'mode':'direct','exit_id':server['id'], 'manager':'3x-ui', 'mtproxy':True})
        self.assertEqual(result.status_code, 200)
        self.assertFalse(result.json()['executable'])
        self.assertTrue(result.json()['blockers'])
        self.assertEqual(self.client.get('/api/state').json()['plan']['manager'], '3x-ui')

    def test_no_services_is_invalid(self):
        self.assertEqual(self.post('plan', {'vpn':False, 'mtproxy':False}).status_code, 400)

    def test_forget_does_not_call_remote(self):
        server = self.add()
        self.client.delete(f'/api/servers/{server["id"]}', headers=self.headers)
        self.assertEqual(self.ssh.calls, [])
        self.assertEqual(self.client.get('/api/state').json()['servers'], [])

    def test_invalid_hosts(self):
        for host in ['-oProxyCommand=bad', 'http://vps.example.net', 'x;bad', 'vps.example.net:22']:
            self.assertEqual(self.post('servers', {'name':'VPS', 'host':host}).status_code, 422)

    def test_forget_server_invalidates_related_plan(self):
        server = self.add()
        self.post('plan', {'exit_id':server['id']})
        self.client.delete(f'/api/servers/{server["id"]}', headers=self.headers)
        self.assertIsNone(self.client.get('/api/state').json()['plan'])

    def test_picker_returns_selected_path_and_api_stays_alive(self):
        from unittest.mock import patch
        with patch('relaydock.api.select_private_key', return_value='test-key'):
            response = self.post('select-key', {})
        self.assertEqual(response.json(), {'path': 'test-key'})
        self.assertEqual(self.client.get('/api/state').status_code, 200)

    def test_picker_cancel_is_not_an_error(self):
        from unittest.mock import patch
        with patch('relaydock.api.select_private_key', return_value=''):
            response = self.post('select-key', {})
        self.assertEqual(response.status_code, 200)
        self.assertEqual(response.json(), {'path': ''})

    def test_picker_failure_is_redacted_and_api_stays_alive(self):
        from unittest.mock import patch
        with patch('relaydock.api.select_private_key', side_effect=RuntimeError('private-path-must-not-leak')):
            response = self.post('select-key', {})
        self.assertEqual(response.status_code, 400)
        self.assertEqual(response.json()['code'], 'picker_failed')
        self.assertNotIn('private-path-must-not-leak', response.text)
        self.assertEqual(self.client.get('/api/state').status_code, 200)

    def test_picker_is_serialized_without_blocking_other_requests(self):
        from concurrent.futures import ThreadPoolExecutor
        from unittest.mock import patch
        import threading
        opened, release = threading.Event(), threading.Event()
        def choose():
            opened.set()
            release.wait(timeout=5)
            return ''
        with patch('relaydock.api.select_private_key', side_effect=choose), ThreadPoolExecutor() as pool:
            future = pool.submit(self.post, 'select-key', {})
            try:
                self.assertTrue(opened.wait(timeout=2))
                response = self.post('select-key', {})
                self.assertEqual(response.status_code, 400)
                self.assertEqual(response.json()['code'], 'picker_busy')
                self.assertEqual(self.client.get('/api/state').status_code, 200)
            finally:
                release.set()
            self.assertEqual(future.result(timeout=3).status_code, 200)

    def test_browser_key_upload_is_encrypted(self):
        from pathlib import Path
        material=asyncssh.generate_private_key('ssh-ed25519').export_private_key().decode()
        response=self.post('keys',{'name':'test_key','content':material})
        self.assertEqual(response.status_code,200)
        self.assertTrue(response.json()['reference'].startswith('vault:'))
        for path in Path(self.directory.name).rglob('*'):
            if path.is_file():self.assertNotIn(material.encode(),path.read_bytes())

    def test_connection_identity_links_qr_and_backups(self):
        server=self.add();self.trust(server)
        response=self.post('profiles',{'name':'Test VPN','mode':'direct','exit_id':server['id'],'public_host':'vpn.example.net',
                           'entry_vpn_port':443,'exit_vpn_port':443,'mtproxy':False})
        self.assertEqual(response.status_code,200)
        profile=response.json();profile_id=profile['id']
        self.assertEqual(profile['status'],'draft')
        value=self.client.get(f'/api/profiles/{profile_id}/links').json()['links']
        self.assertTrue(value[0]['uri'].startswith('vless://'))
        self.assertNotIn('private_key',self.client.get('/api/state').text)
        qr=self.client.get(f'/api/profiles/{profile_id}/qr/0')
        self.assertEqual(qr.status_code,200)
        self.assertTrue(qr.content.startswith(b'\x89PNG\r\n\x1a\n'))
        self.assertEqual(self.post(f'profiles/{profile_id}/backup',{}).status_code,200)
        self.assertEqual(len(self.client.get(f'/api/profiles/{profile_id}/backups').json()['backups']),1)
        secret=self.app.state.store.profile(profile_id,True)['secret']
        from relaydock.profiles import links
        changed={**profile,'exit_id':'another-server'}
        self.assertEqual(links(profile,secret),links(changed,secret))
        from pathlib import Path
        self.assertNotIn(secret['private_key'].encode(),(Path(self.directory.name)/'state.db').read_bytes())
        self.assertEqual(self.client.delete(f'/api/servers/{server["id"]}',headers=self.headers).status_code,400)
