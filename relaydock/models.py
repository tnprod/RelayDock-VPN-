import ipaddress
import re
from typing import Literal
from pydantic import BaseModel, ConfigDict, Field, SecretStr, field_validator


class ServerInput(BaseModel):
    model_config = ConfigDict(extra='forbid', str_strip_whitespace=True)
    name: str = Field(min_length=1, max_length=80)
    host: str = Field(min_length=1, max_length=253)
    port: int = Field(default=22, ge=1, le=65535)
    username: str = Field(default='root', min_length=1, max_length=64)
    auth_method: Literal['password', 'key', 'agent'] = 'password'
    key_path: str = Field(default='', max_length=2048)
    role: Literal['exit', 'entry', 'unassigned'] = 'exit'

    @field_validator('host')
    @classmethod
    def validate_host(cls, value):
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            labels = value.rstrip('.').split('.')
            if not all(re.fullmatch(r'[A-Za-z0-9](?:[A-Za-z0-9-]{0,61}[A-Za-z0-9])?', x) for x in labels):
                raise ValueError('Укажите IP-адрес или доменное имя без протокола и порта')
            return value.lower().rstrip('.')

    @field_validator('username')
    @classmethod
    def validate_user(cls, value):
        if not re.fullmatch(r'[a-zA-Z_][a-zA-Z0-9_.-]{0,63}\$?', value):
            raise ValueError('Некорректное имя пользователя SSH')
        return value

    @field_validator('key_path')
    @classmethod
    def validate_path(cls, value):
        if any(ord(x) < 32 for x in value):
            raise ValueError('Некорректный путь к ключу')
        return value


class Credentials(BaseModel):
    model_config = ConfigDict(extra='forbid')
    password: SecretStr = Field(default_factory=lambda: SecretStr(''), max_length=4096)
    passphrase: SecretStr = Field(default_factory=lambda: SecretStr(''), max_length=4096)


class TrustInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    challenge: str = Field(min_length=20, max_length=128)
    fingerprint: str = Field(min_length=20, max_length=128)


class PlanInput(BaseModel):
    model_config = ConfigDict(extra='forbid')
    mode: Literal['direct', 'relay'] = 'direct'
    manager: Literal['xray', '3x-ui'] = 'xray'
    vpn: bool = True
    mtproxy: bool = True
    entry_id: str | None = None
    exit_id: str | None = None


class ProfileInput(BaseModel):
    model_config=ConfigDict(extra='forbid',str_strip_whitespace=True)
    name:str=Field(min_length=1,max_length=80)
    mode:Literal['direct','relay']='relay'
    entry_id:str|None=None
    exit_id:str
    public_host:str
    entry_vpn_port:int=Field(default=8443,ge=1,le=65535)
    exit_vpn_port:int=Field(default=443,ge=1,le=65535)
    entry_mt_port:int=Field(default=8444,ge=1,le=65535)
    exit_mt_port:int=Field(default=8444,ge=1,le=65535)
    vpn:bool=True
    mtproxy:bool=True
    server_name:str='www.apple.com'
    _validate_public_host=field_validator('public_host','server_name')(ServerInput.validate_host.__func__)


class AccessInput(BaseModel):
    model_config=ConfigDict(extra='forbid')
    access:dict[str,Credentials]=Field(default_factory=dict)
    target_id:str|None=None
    vpn_port:int|None=Field(default=None,ge=1,le=65535)
    mt_port:int|None=Field(default=None,ge=1,le=65535)


class ImportInput(AccessInput):
    name:str=Field(default='Постоянное подключение',min_length=1,max_length=80)
    entry_id:str
    exit_id:str
    public_host:str=''
