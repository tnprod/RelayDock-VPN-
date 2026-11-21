#!/usr/bin/env python3
"""Authenticate FakeTLS and, when cryptography is installed, verify Telegram resPQ.
No Telegram account, API ID, auth key, or user messages are involved.
"""
import hashlib,hmac,json,secrets,socket,ssl,struct,sys,time

def exact(sock,length):
    result=bytearray()
    while len(result)<length:
        part=sock.recv(length-len(result))
        if not part:raise RuntimeError('Peer closed the connection')
        result.extend(part)
    return bytes(result)

def record(sock):
    header=exact(sock,5)
    size=int.from_bytes(header[3:5],'big')
    if size>18432:raise RuntimeError('Invalid TLS record size')
    return header+exact(sock,size)

def frame(data):
    return b'\x17\x03\x03'+len(data).to_bytes(2,'big')+data

def probe(host,port,secret,timeout=12):
    raw=bytes.fromhex(secret)
    if len(raw)<18 or raw[0]!=0xee:raise ValueError('Expected a FakeTLS secret')
    key=raw[1:17];domain=raw[17:].decode('ascii')
    context=ssl.create_default_context();context.minimum_version=ssl.TLSVersion.TLSv1_3
    incoming=ssl.MemoryBIO();outgoing=ssl.MemoryBIO()
    tls=context.wrap_bio(incoming,outgoing,server_side=False,server_hostname=domain)
    try:tls.do_handshake()
    except ssl.SSLWantReadError:pass
    hello=bytearray(outgoing.read())
    if hello[:3]!=b'\x16\x03\x01' or len(hello)!=5+int.from_bytes(hello[3:5],'big'):
        raise RuntimeError('Unexpected OpenSSL ClientHello framing')
    hello[11:43]=bytes(32)
    client_random=bytearray(hmac.new(key,hello,hashlib.sha256).digest())
    timestamp=struct.pack('<I',int(time.time()))
    for i in range(4):client_random[28+i]^=timestamp[i]
    hello[11:43]=client_random
    started=time.monotonic()
    with socket.create_connection((host,int(port)),timeout=timeout) as sock:
        sock.settimeout(timeout);sock.sendall(hello)
        packets=[record(sock) for _ in range(3)]
        if [p[0] for p in packets]!=[0x16,0x14,0x17]:raise RuntimeError('Unexpected FakeTLS server records')
        server=bytearray(b''.join(packets));server_random=bytes(server[11:43]);server[11:43]=bytes(32)
        expected=hmac.new(key,bytes(client_random)+server,hashlib.sha256).digest()
        if not hmac.compare_digest(expected,server_random):raise RuntimeError('MTProxy secret authentication failed')
        result={'faketls_authenticated':True,'server':host,'port':int(port),'domain':domain}
        try:
            from cryptography.hazmat.primitives.ciphers import Cipher,algorithms,modes
        except ImportError:
            result['rpc_verified']=False;result['rpc_note']='Install python3-cryptography to verify the Telegram RPC exchange'
            return result
        while True:
            initial=bytearray(secrets.token_bytes(64))
            if initial[0]!=0xef and initial[:4] not in [b'HEAD',b'POST',b'GET ',b'OPTI',b'\xee'*4,b'\xdd'*4,b'\x16\x03\x01\x02'] and initial[4:8]!=bytes(4):break
        initial[56:60]=b'\xdd'*4;initial[60:62]=struct.pack('<h',2)
        reverse=bytes(initial[::-1])
        encrypt=Cipher(algorithms.AES(hashlib.sha256(bytes(initial[8:40])+key).digest()),modes.CTR(bytes(initial[40:56]))).encryptor()
        decrypt=Cipher(algorithms.AES(hashlib.sha256(reverse[8:40]+key).digest()),modes.CTR(reverse[40:56])).decryptor()
        encrypted=encrypt.update(bytes(initial))
        obfuscated=bytes(initial[:56])+encrypted[56:64]
        nonce=secrets.token_bytes(16)
        body=struct.pack('<I',0xbe7e8ef1)+nonce
        message=bytes(8)+struct.pack('<QI',(int(time.time()*2**32)&~3),len(body))+body
        payload=encrypt.update(struct.pack('<I',len(message))+message)
        sock.sendall(frame(obfuscated+payload))
        data=bytearray()
        while len(data)<4:
            part=record(sock)
            if part[0]==0x17:data.extend(decrypt.update(part[5:]))
        length=struct.unpack('<I',data[:4])[0]
        if not 40<=length<=512:raise RuntimeError('Invalid MTProto reply length: '+str(length))
        while len(data)<4+length:
            part=record(sock)
            if part[0]==0x17:data.extend(decrypt.update(part[5:]))
        reply=data[4:4+length]
        if reply[20:24]!=struct.pack('<I',0x05162463) or reply[24:40]!=nonce:
            raise RuntimeError('Telegram did not return matching resPQ')
        result.update(rpc_verified=True,rtt_ms=round((time.monotonic()-started)*1000,1))
        return result

if __name__=='__main__':
    config=json.load(open(sys.argv[1]))
    mt=config.get('mtproxy',config)
    host=sys.argv[2] if len(sys.argv)>2 else config.get('address','127.0.0.1')
    port=int(sys.argv[3]) if len(sys.argv)>3 else mt.get('port',8444)
    print(json.dumps(probe(host,port,mt['secret']),indent=2))
