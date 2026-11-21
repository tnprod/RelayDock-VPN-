"""Read-only import of previously generated cascade units. Imported data stays encrypted."""
DISCOVER = r'''
import json,pathlib,re,shlex,subprocess,sys,tomllib
p=json.load(sys.stdin)
def unit(name):
 r=subprocess.run(['systemctl','cat',name],capture_output=True,text=True,timeout=12)
 if r.returncode:raise RuntimeError('unit_missing')
 text=r.stdout
 line=[x.split('=',1)[1] for x in text.splitlines() if x.startswith('ExecStart=') and x!='ExecStart='][-1]
 env={}
 for setting in text.splitlines():
  if setting.startswith('EnvironmentFile='):
   for filename in shlex.split(setting.split('=',1)[1]):
    file=pathlib.Path(filename.lstrip('-'))
    if file.is_file():
     for row in file.read_text().splitlines():
      if '=' in row and not row.lstrip().startswith('#'):
       key,value=row.split('=',1);env[key.strip()]=value.strip().strip(chr(34)).strip(chr(39))
  elif setting.startswith('Environment='):
   for row in shlex.split(setting.split('=',1)[1]):
    if '=' in row:
     key,value=row.split('=',1);env[key]=value
 line=re.sub(r'\$\{([A-Za-z_][A-Za-z0-9_]*)\}',lambda match:env.get(match[1],match[0]),line)
 credentials={}
 for setting in text.splitlines():
  if setting.startswith('LoadCredential='):
   key,path=setting.split('=',1)[1].split(':',1);credentials['%d/'+key]=path
 args=[credentials.get(arg,arg) for arg in shlex.split(line)]
 return {'unit':name,'text':text,'exec_start':line,'argv':args}
if p['kind']=='entry':
 result={}
 for key,name in [('vpn','codex-forward-vpn.service'),('mt','codex-forward-mtproxy.service')]:
  try:
   value=unit(name);args=' '.join(value['argv'])
   listen=re.search(r'TCP(?:4|6)?-LISTEN:(\d+)',args)
   dest=re.search(r'TCP(?:4|6)?(?:-CONNECT)?:([^\s,:]+):(\d+)',args)
   if not listen or not dest:raise RuntimeError('unsupported_forwarder')
   value.update(port=int(listen[1]),host=dest[1],target_port=int(dest[2]))
   result[key]=value
  except Exception:
   if key=='vpn':raise
 print(json.dumps(result))
else:
 result={}
 v=unit('codex-exit-vpn.service');args=v['argv']
 flag=next(x for x in ['-config','-c','--config'] if x in args)
 path=args[args.index(flag)+1]
 v['config']=json.loads(pathlib.Path(path).read_text());v['path']=path;result['vpn']=v
 try:
  m=unit('codex-exit-mtproxy.service');path=m['argv'][-1]
  m['config']=tomllib.loads(pathlib.Path(path).read_text());m['path']=path;result['mt']=m
 except Exception:pass
 print(json.dumps(result))
'''

def parse_exit(value):
    config=value['vpn']['config']
    inbound=next(x for x in config['inbounds'] if x.get('protocol')=='vless' and x.get('streamSettings',{}).get('security')=='reality')
    reality=inbound['streamSettings']['realitySettings']
    return {'secret':{'private_key':reality['privateKey'],'server_name':reality['serverNames'][0],
             'short_id':reality['shortIds'][0], 'clients':[{'id':c['id'],'flow':c.get('flow',''),'name':c.get('email') or f'Клиент {i+1}'}
             for i,c in enumerate(inbound['settings']['clients'])],
             'mtproxy_secret':value.get('mt',{}).get('config',{}).get('secret','')},
             'vpn_port':int(inbound['port']), 'mt_port':int(str(value.get('mt',{}).get('config',{}).get('bind-to','0.0.0.0:8444')).rsplit(':',1)[1])}
