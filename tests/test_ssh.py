import asyncio
import unittest
from unittest.mock import patch
import asyncssh
from relaydock.models import Credentials
from relaydock.ssh import AUDIT_SCRIPT, SSHService, UserError, parse_report

REPORT = '''RD2:os
PRETTY_NAME="Ubuntu 24.04 LTS"
ID=ubuntu
VERSION_ID="24.04"
RD2:arch
x86_64
RD2:uid
0
RD2:sudo
root
RD2:memory
2097152
RD2:disk
10485760
RD2:ports
LISTEN 0 128 0.0.0.0:22 0.0.0.0:*
LISTEN 0 128 [::]:443 [::]:*
RD2:services
xray=active
x-ui=inactive
mtg=inactive
docker=inactive
RD2:docker
RD2:firewall
Status: inactive
'''


class SSHTests(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.host_key = asyncssh.generate_private_key('ssh-ed25519')
        self.client_key = asyncssh.generate_private_key('ssh-ed25519')
        self.password_attempts = []
        self.commands = []
        owner = self

        class Server(asyncssh.SSHServer):
            def begin_auth(self, username):
                return True
            def password_auth_supported(self):
                return True
            def public_key_auth_supported(self):
                return True
            def validate_password(self, username, password):
                owner.password_attempts.append(password)
                return username == 'operator' and password == 'test-password-only'
            def validate_public_key(self, username, key):
                return username == 'operator' and key == owner.client_key.convert_to_public()

        async def handle(process):
            self.commands.append((process.command, await process.stdin.read()))
            process.stdout.write(REPORT)
            process.exit(0)

        self.listener = await asyncssh.create_server(Server, '127.0.0.1', 0,
                                                    server_host_keys=[self.host_key], process_factory=handle)
        self.server = {'host': '127.0.0.1', 'port': self.listener.get_port(), 'username': 'operator',
                       'auth_method': 'password', 'key_path': '',
                       'host_key': self.host_key.export_public_key().decode()}
        self.service = SSHService()

    async def asyncTearDown(self):
        self.listener.close()
        await self.listener.wait_closed()

    async def test_fingerprint_does_not_authenticate(self):
        value = await self.service.fingerprint(self.server)
        self.assertEqual(value['fingerprint'], self.host_key.get_fingerprint('sha256'))
        self.assertEqual(self.password_attempts, [])
        self.assertEqual(self.commands, [])

    async def test_password_audit_runs_only_fixed_readonly_script(self):
        result = await self.service.audit(self.server, Credentials(password='test-password-only'))
        self.assertEqual(result['os'], 'Ubuntu 24.04 LTS')
        self.assertEqual(result['tcp_ports'], [22, 443])
        self.assertEqual(result['services']['xray'], 'active')
        self.assertEqual(result['scope'], 'read_only')
        self.assertEqual(self.commands, [('sh -s', AUDIT_SCRIPT)])

    async def test_wrong_password_is_redacted(self):
        with self.assertRaises(UserError) as ctx:
            await self.service.audit(self.server, Credentials(password='secret-must-not-appear'))
        self.assertEqual(ctx.exception.code, 'authentication_failed')
        self.assertNotIn('secret-must-not-appear', str(ctx.exception))

    async def test_changed_host_key_stops_before_password(self):
        self.server['host_key'] = asyncssh.generate_private_key('ssh-ed25519').export_public_key().decode()
        with self.assertRaises(UserError) as ctx:
            await self.service.audit(self.server, Credentials(password='test-password-only'))
        self.assertEqual(ctx.exception.code, 'host_key_changed')
        self.assertEqual(self.password_attempts, [])

    async def test_untrusted_server_is_not_contacted(self):
        self.server['host_key'] = None
        with self.assertRaises(UserError) as ctx:
            await self.service.audit(self.server, Credentials(password='test-password-only'))
        self.assertEqual(ctx.exception.code, 'trust_required')
        self.assertEqual(self.password_attempts, [])

    async def test_encrypted_private_key_authentication(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-key'
            self.client_key.write_private_key(path, passphrase='test-phrase-only')
            self.server.update(auth_method='key', key_path=str(path))
            result = await self.service.audit(self.server, Credentials(passphrase='test-phrase-only'))
            self.assertTrue(result['install_os_supported'])
            self.assertEqual(self.password_attempts, [])

    async def test_bad_key_passphrase_does_not_leak(self):
        import tempfile
        from pathlib import Path
        with tempfile.TemporaryDirectory() as directory:
            path = Path(directory) / 'test-key'
            self.client_key.write_private_key(path, passphrase='correct-phrase')
            self.server.update(auth_method='key', key_path=str(path))
            with self.assertRaises(UserError) as ctx:
                await self.service.audit(self.server, Credentials(passphrase='wrong-phrase'))
            self.assertEqual(ctx.exception.code, 'key_invalid')
            self.assertNotIn(str(path), str(ctx.exception))
            self.assertEqual(self.password_attempts, [])

    async def test_agent_mode_does_not_fallback_to_local_private_keys(self):
        self.server['auth_method'] = 'agent'
        with patch('relaydock.ssh.asyncssh.connect', side_effect=OSError('no-agent')) as connect:
            with self.assertRaises(UserError):
                await self.service.audit(self.server, Credentials())
        options = connect.call_args.kwargs
        self.assertIsNone(options['client_keys'])
        self.assertIsNone(options['password'])
        self.assertNotIn('agent_path', options)
        self.assertIsNone(options['gss_host'])
        self.assertFalse(options['gss_auth'])
        self.assertFalse(options['gss_kex'])


class ParserTests(unittest.TestCase):
    def test_unknown_os_and_permissions_are_reported(self):
        value = parse_report('RD2:os\nID=debian\nRD2:sudo\nunavailable\n')
        self.assertFalse(value['install_os_supported'])
        self.assertGreaterEqual(len(value['warnings']), 2)
        self.assertIsNone(value['memory_kib'])

    def test_malformed_port_output_is_ignored(self):
        value = parse_report('RD2:ports\nbad\nLISTEN 0 128 invalid:*\n')
        self.assertEqual(value['tcp_ports'], [])
