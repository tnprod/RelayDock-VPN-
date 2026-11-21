import json
import os
from pathlib import Path
import socket
import ssl
import struct
import subprocess
import tempfile
import time
from .profiles import client_config

def exact(sock,count):
    value=b''
    while len(value)<count:
        part=sock.recv(count-len(value))
        if not part:raise RuntimeError('Соединение закрыто до ответа.')
        value+=part
    return value

def free_port():
    with socket.socket() as listener:
        listener.bind(('127.0.0.1',0));return listener.getsockname()[1]

def via_socks(port,host='example.com',path='/'):
    started=time.monotonic()
    connection=socket.create_connection(('127.0.0.1',port),timeout=15)
    connection.settimeout(20)
    try:
        connection.sendall(b'\x05\x01\x00')
        if exact(connection,2)!=b'\x05\x00':raise RuntimeError('SOCKS не готов')
        name=host.encode('idna')
        connection.sendall(b'\x05\x01\x00\x03'+bytes([len(name)])+name+struct.pack('!H',443))
        response=exact(connection,4)
        if response[1]!=0:raise RuntimeError('Выходной сервер не установил соединение с сайтом.')
        count={1:4,4:16}.get(response[3])
        if response[3]==3:count=exact(connection,1)[0]
        if count is None:raise RuntimeError('Некорректный ответ SOCKS')
        exact(connection,count+2)
        with ssl.create_default_context().wrap_socket(connection,server_hostname=host) as secure:
            secure.sendall(f'GET {path} HTTP/1.1\r\nHost: {host}\r\nConnection: close\r\nUser-Agent: RelayDock-check\r\n\r\n'.encode())
            data=b''
            while b'\r\n' not in data and len(data)<8192:
                chunk=secure.recv(4096)
                if not chunk:break
                data+=chunk
            status=data.split(b'\r\n',1)[0].split()
            if len(status)<2 or not status[1].isdigit():raise RuntimeError('Сайт не вернул HTTP-ответ через VPN.')
            code=int(status[1])
            if not 200<=code<400:raise RuntimeError('HTTP-проверка VPN не прошла.')
            return {'ok':True,'https_status':code,'rtt_ms':round((time.monotonic()-started)*1000), 'checked_at':time.time(), 'target':'https://example.com/'}
    finally:
        connection.close()

def probe(binary,profile,secret,directory,host=None,port=None):
    socks=free_port()
    with tempfile.TemporaryDirectory(prefix='probe-',dir=directory) as directory:
        config=Path(directory)/'client.json';config.write_text(json.dumps(client_config(profile,secret,socks,host,port)),encoding='utf-8');config.chmod(0o600)
        log=(Path(directory)/'xray.log').open('wb')
        process=subprocess.Popen([str(binary),'run','-config',str(config)],stdout=log,stderr=log,
                                  creationflags=subprocess.CREATE_NO_WINDOW if os.name=='nt' else 0)
        try:
            for _ in range(80):
                if process.poll() is not None:raise RuntimeError('Проверочный Xray не запустился.')
                try:
                    with socket.create_connection(('127.0.0.1',socks),timeout=.1):break
                except OSError:time.sleep(.1)
            return via_socks(socks)
        finally:
            process.terminate()
            try:process.wait(timeout=5)
            except subprocess.TimeoutExpired:process.kill();process.wait()
            log.close()
