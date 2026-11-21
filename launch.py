import argparse
import secrets
import socket
import threading
import time
import webbrowser
import uvicorn
from relaydock.api import create_app


def main():
    parser = argparse.ArgumentParser(description='RelayDock — локальное управление VPS')
    parser.add_argument('--no-browser', action='store_true')
    parser.add_argument('--port', type=int, default=0)
    parser.add_argument('--data-dir')
    args = parser.parse_args()
    token = secrets.token_urlsafe(32)
    app = create_app(args.data_dir, token)
    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(('127.0.0.1', args.port))
    listener.listen(128)
    port = listener.getsockname()[1]
    url = f'http://127.0.0.1:{port}/#token={token}'
    server = uvicorn.Server(uvicorn.Config(app, access_log=False, log_level='warning'))
    if not args.no_browser:
        def open_browser():
            while not server.started and not server.should_exit:
                time.sleep(0.1)
            if server.started:
                webbrowser.open(url)
        threading.Thread(target=open_browser, daemon=True).start()
    print('RelayDock 2.0 beta 2 — закройте это окно для остановки.')
    print('Откроется локальный интерфейс. Серверы автоматически не изменяются.')
    if args.no_browser:
        # Explicit developer mode only. Never log SSH credentials or tokens in normal launch.
        print(url, flush=True)
    try:
        server.run(sockets=[listener])
    finally:
        listener.close()


if __name__ == '__main__':
    main()
