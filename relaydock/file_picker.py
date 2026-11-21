"""Native file selection. No Tcl/Tk runtime or cross-thread Tcl objects."""
import os


class PickerError(Exception):
    pass


def select_private_key():
    if os.name != 'nt':
        raise PickerError('Укажите путь к приватному ключу вручную. Системный выбор файла пока доступен только в Windows.')
    import ctypes
    from ctypes import wintypes

    class OpenFileName(ctypes.Structure):
        _fields_ = [
            ('lStructSize', wintypes.DWORD), ('hwndOwner', wintypes.HWND),
            ('hInstance', wintypes.HINSTANCE), ('lpstrFilter', wintypes.LPCWSTR),
            ('lpstrCustomFilter', wintypes.LPWSTR), ('nMaxCustFilter', wintypes.DWORD),
            ('nFilterIndex', wintypes.DWORD), ('lpstrFile', wintypes.LPWSTR),
            ('nMaxFile', wintypes.DWORD), ('lpstrFileTitle', wintypes.LPWSTR),
            ('nMaxFileTitle', wintypes.DWORD), ('lpstrInitialDir', wintypes.LPCWSTR),
            ('lpstrTitle', wintypes.LPCWSTR), ('Flags', wintypes.DWORD),
            ('nFileOffset', wintypes.WORD), ('nFileExtension', wintypes.WORD),
            ('lpstrDefExt', wintypes.LPCWSTR), ('lCustData', ctypes.c_ssize_t),
            ('lpfnHook', ctypes.c_void_p), ('lpTemplateName', wintypes.LPCWSTR),
            ('pvReserved', ctypes.c_void_p), ('dwReserved', wintypes.DWORD),
            ('FlagsEx', wintypes.DWORD),
        ]

    dialog = ctypes.WinDLL('comdlg32', use_last_error=True)
    dialog.GetOpenFileNameW.argtypes = [ctypes.POINTER(OpenFileName)]
    dialog.GetOpenFileNameW.restype = wintypes.BOOL
    dialog.CommDlgExtendedError.argtypes = []
    dialog.CommDlgExtendedError.restype = wintypes.DWORD
    buffer = ctypes.create_unicode_buffer(32768)
    options = OpenFileName()
    options.lStructSize = ctypes.sizeof(OpenFileName)
    options.lpstrFilter = 'Приватные SSH-ключи (все файлы)\0*\0\0'
    options.nFilterIndex = 1
    options.lpstrFile = ctypes.cast(buffer, wintypes.LPWSTR)
    options.nMaxFile = len(buffer)
    options.lpstrTitle = 'RelayDock — выберите приватный SSH-ключ'
    # FILEMUSTEXIST | PATHMUSTEXIST | EXPLORER | NOCHANGEDIR | DONTADDTORECENT.
    options.Flags = 0x1000 | 0x800 | 0x80000 | 0x8 | 0x2000000
    if dialog.GetOpenFileNameW(ctypes.byref(options)):
        return buffer.value
    if dialog.CommDlgExtendedError() == 0:
        return ''  # Cancel is a normal result, not a failed request.
    raise PickerError('Windows не удалось открыть выбор файла. Вставьте путь к ключу вручную.')
