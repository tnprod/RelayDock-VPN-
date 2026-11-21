import json
import os
import sqlite3
import threading
import uuid
from datetime import datetime, timezone
from pathlib import Path


def now():
    return datetime.now(timezone.utc).isoformat()


def default_data_dir():
    if os.name == 'nt':
        return Path(os.environ.get('LOCALAPPDATA', Path.home() / 'AppData' / 'Local')) / 'RelayDock'
    return Path(os.environ.get('XDG_DATA_HOME', Path.home() / '.local' / 'share')) / 'relaydock'


class Store:
    def __init__(self, directory):
        self.directory = Path(directory)
        self.directory.mkdir(parents=True, exist_ok=True, mode=0o700)
        self.lock = threading.RLock()
        self.db = sqlite3.connect(self.directory / 'state.db', check_same_thread=False)
        self.db.row_factory = sqlite3.Row
        with self.db:
            self.db.executescript('''
            CREATE TABLE IF NOT EXISTS servers (
              id TEXT PRIMARY KEY, config TEXT NOT NULL, host_key TEXT,
              fingerprint TEXT, report TEXT, checked_at TEXT, created_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS settings (key TEXT PRIMARY KEY, value TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS profiles (id TEXT PRIMARY KEY, public TEXT NOT NULL, secret TEXT NOT NULL, updated_at TEXT NOT NULL);
            CREATE TABLE IF NOT EXISTS backups (id TEXT PRIMARY KEY, profile_id TEXT NOT NULL, public TEXT NOT NULL, secret TEXT NOT NULL, created_at TEXT NOT NULL);
            ''')

    def close(self):
        self.db.close()

    @staticmethod
    def decode(row, private=False):
        if row is None:
            return None
        result = json.loads(row['config'])
        result.update(id=row['id'], fingerprint=row['fingerprint'],
                      report=json.loads(row['report']) if row['report'] else None,
                      checked_at=row['checked_at'], created_at=row['created_at'])
        if private:
            result['host_key'] = row['host_key']
        return result

    def list(self):
        with self.lock:
            return [self.decode(r) for r in self.db.execute('SELECT * FROM servers ORDER BY created_at')]

    def get(self, server_id, private=False):
        with self.lock:
            return self.decode(self.db.execute('SELECT * FROM servers WHERE id=?', (server_id,)).fetchone(), private)

    def create(self, value):
        server_id = str(uuid.uuid4())
        with self.lock, self.db:
            self.db.execute('INSERT INTO servers(id,config,created_at) VALUES(?,?,?)',
                            (server_id, json.dumps(value), now()))
        return self.get(server_id)

    def trust(self, server_id, host_key, fingerprint):
        with self.lock, self.db:
            self.db.execute('UPDATE servers SET host_key=?,fingerprint=? WHERE id=?',
                            (host_key, fingerprint, server_id))

    def report(self, server_id, report):
        with self.lock, self.db:
            self.db.execute('UPDATE servers SET report=?,checked_at=? WHERE id=?',
                            (json.dumps(report, ensure_ascii=False), now(), server_id))

    def delete(self, server_id):
        with self.lock, self.db:
            for row in self.db.execute('SELECT public FROM profiles'):
                item=json.loads(row[0])
                if server_id in {item.get('entry_id'),item.get('exit_id')}:
                    raise ValueError('Сервер используется VPN-профилем. Сначала перенесите подключение.')
            self.db.execute('DELETE FROM servers WHERE id=?', (server_id,))
            row = self.db.execute('SELECT value FROM settings WHERE key=?', ('plan',)).fetchone()
            if row:
                plan = json.loads(row[0])
                if server_id in {plan.get('entry_id'), plan.get('exit_id')}:
                    self.db.execute('DELETE FROM settings WHERE key=?', ('plan',))

    def get_plan(self):
        with self.lock:
            row = self.db.execute('SELECT value FROM settings WHERE key=?', ('plan',)).fetchone()
            return json.loads(row[0]) if row else None

    def save_plan(self, plan):
        with self.lock, self.db:
            self.db.execute('INSERT OR REPLACE INTO settings(key,value) VALUES(?,?)', ('plan', json.dumps(plan)))

    def profiles(self):
        with self.lock:
            return [json.loads(row[0]) for row in self.db.execute('SELECT public FROM profiles ORDER BY updated_at DESC')]

    def profile(self,profile_id,private=False):
        with self.lock:
            row=self.db.execute('SELECT public,secret FROM profiles WHERE id=?',(profile_id,)).fetchone()
            if not row:return None
            value=json.loads(row[0])
            if private:
                from .vault import Vault
                value['secret']=Vault(self.directory).decrypt(row[1])
            return value

    def save_profile(self,value,secret):
        from .vault import Vault
        encrypted=Vault(self.directory).encrypt(secret)
        with self.lock,self.db:
            self.db.execute('INSERT OR REPLACE INTO profiles(id,public,secret,updated_at) VALUES(?,?,?,?)',
                            (value['id'],json.dumps(value,ensure_ascii=False),encrypted,now()))

    def backup_profile(self,profile_id):
        from .vault import Vault
        value=self.profile(profile_id,True)
        if not value:raise ValueError('Подключение не найдено')
        secret=value.pop('secret')
        backup_id=str(uuid.uuid4())
        with self.lock,self.db:
            self.db.execute('INSERT INTO backups VALUES(?,?,?,?,?)',(backup_id,profile_id,json.dumps(value,ensure_ascii=False),Vault(self.directory).encrypt(secret),now()))
        return backup_id

    def backups(self,profile_id):
        with self.lock:
            return [dict(row) for row in self.db.execute('SELECT id,profile_id,created_at FROM backups WHERE profile_id=? ORDER BY created_at DESC',(profile_id,))]
