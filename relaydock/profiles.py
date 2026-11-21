import base64
import secrets
import uuid
from urllib.parse import urlencode
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding,PublicFormat,PrivateFormat,NoEncryption

def public_key(private):
    key=X25519PrivateKey.from_private_bytes(base64.urlsafe_b64decode(private+'='*(-len(private)%4)))
    return base64.urlsafe_b64encode(key.public_key().public_bytes(Encoding.Raw,PublicFormat.Raw)).decode().rstrip('=')

def identity(name='Основной профиль',server_name='www.apple.com'):
    private=X25519PrivateKey.generate().private_bytes(Encoding.Raw,PrivateFormat.Raw,NoEncryption())
    return {'private_key':base64.urlsafe_b64encode(private).decode().rstrip('='),'short_id':secrets.token_hex(8),
            'server_name':server_name,'clients':[{'id':str(uuid.uuid4()),'name':name,'flow':'xtls-rprx-vision'}],
            'mtproxy_secret':'ee'+secrets.token_hex(16)+server_name.encode('ascii').hex()}

def links(profile,secret):
    host=profile['public_host'];host='['+host+']' if ':' in host else host
    result=[]
    if profile.get('vpn',True):
        for client in secret['clients']:
            query=urlencode({'type':'tcp','encryption':'none','security':'reality','pbk':public_key(secret['private_key']),
                             'fp':'chrome','sni':secret['server_name'],'sid':secret['short_id'],'flow':client.get('flow','xtls-rprx-vision'),'spx':'/'})
            from urllib.parse import quote
            result.append({'kind':'vpn','name':client.get('name') or profile['name'],
                           'uri':f'vless://{client["id"]}@{host}:{profile["entry_vpn_port"]}?{query}#{quote(client.get("name") or profile["name"])}'})
    if profile.get('mtproxy'):
        result.append({'kind':'telegram','name':'Telegram','uri':'https://t.me/proxy?'+urlencode({'server':profile['public_host'],
                      'port':profile['entry_mt_port'],'secret':secret['mtproxy_secret']})})
    return result

def exit_config(profile,secret):
    return {'log':{'loglevel':'warning'},'inbounds':[{'tag':'vpn','listen':'0.0.0.0','port':profile['exit_vpn_port'],
             'protocol':'vless','settings':{'clients':[{'id':c['id'],'email':c.get('name','client'),'flow':c.get('flow','xtls-rprx-vision')} for c in secret['clients']], 'decryption':'none'},
             'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'show':False,'dest':secret['server_name']+':443',
             'xver':0,'serverNames':[secret['server_name']],'privateKey':secret['private_key'],'shortIds':[secret['short_id']]}}}],
             'outbounds':[{'protocol':'freedom','tag':'internet'}]}

def client_config(profile,secret,socks_port,host=None,port=None):
    return {'log':{'loglevel':'warning'},'inbounds':[{'listen':'127.0.0.1','port':socks_port,'protocol':'socks',
             'settings':{'auth':'noauth','udp':True}}],'outbounds':[{'protocol':'vless','settings':{'vnext':[{'address':host or profile['public_host'],
             'port':port or profile['entry_vpn_port'],'users':[{'id':secret['clients'][0]['id'],'encryption':'none','flow':secret['clients'][0].get('flow','xtls-rprx-vision')}]}]},
             'streamSettings':{'network':'tcp','security':'reality','realitySettings':{'serverName':secret['server_name'],
             'fingerprint':'chrome','password':public_key(secret['private_key']),'shortId':secret['short_id']}}}]}
