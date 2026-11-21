"""Encrypt application secrets. Windows master key is protected for the current user."""
import ctypes
import json
import os
from pathlib import Path
from cryptography.fernet import Fernet, InvalidToken


def dpapi(data, decrypt=False):
    from ctypes import wintypes
    class Blob(ctypes.Structure):
        _fields_=[('size',wintypes.DWORD),('data',ctypes.POINTER(ctypes.c_ubyte))]
    source=ctypes.create_string_buffer(data)
    incoming=Blob(len(data),ctypes.cast(source,ctypes.POINTER(ctypes.c_ubyte)))
    outgoing=Blob()
    library=ctypes.WinDLL('crypt32',use_last_error=True)
    function=library.CryptUnprotectData if decrypt else library.CryptProtectData
    function.argtypes=[ctypes.POINTER(Blob),ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,ctypes.c_void_p,wintypes.DWORD,ctypes.POINTER(Blob)]
    function.restype=wintypes.BOOL
    if not function(ctypes.byref(incoming),None,None,None,None,1,ctypes.byref(outgoing)):
        raise RuntimeError('Не удалось открыть защищённое хранилище текущего пользователя Windows.')
    try:
        return ctypes.string_at(outgoing.data,outgoing.size)
    finally:
        free=ctypes.WinDLL('kernel32').LocalFree
        free.argtypes=[ctypes.c_void_p]
        free.restype=ctypes.c_void_p
        free(outgoing.data)


class Vault:
    def __init__(self,directory):
        self.path=Path(directory)/'vault.key'
        if self.path.exists():
            data=self.path.read_bytes()
            key=dpapi(data[4:],True) if data.startswith(b'DP2:') else data[4:]
        else:
            key=Fernet.generate_key()
            data=b'DP2:'+dpapi(key) if os.name=='nt' else b'FS2:'+key
            fd=os.open(self.path,os.O_WRONLY|os.O_CREAT|os.O_EXCL,0o600)
            with os.fdopen(fd,'wb') as stream:stream.write(data)
        self.cipher=Fernet(key)

    def encrypt(self,value):
        return self.cipher.encrypt(json.dumps(value,ensure_ascii=False).encode()).decode()

    def decrypt(self,value):
        try:return json.loads(self.cipher.decrypt(value.encode()))
        except (InvalidToken,ValueError):
            raise RuntimeError('Хранилище повреждено или открыто другим пользователем. Нужна резервная копия.') from None
