"""Plain TCP relay. Client-to-exit encryption remains end to end."""
import asyncio
import json
import sys

async def bridge(reader,writer,route):
    other=None
    async def pump(source,target):
        try:
            while data:=await source.read(65536):
                target.write(data);await target.drain()
        finally:
            try:target.write_eof()
            except (AttributeError,OSError,RuntimeError):pass
    try:
        remote,other=await asyncio.wait_for(asyncio.open_connection(route['host'],route['port']),15)
        await asyncio.gather(pump(reader,other),pump(remote,writer))
    except (OSError,TimeoutError,ConnectionError):pass
    finally:
        for stream in [writer,other]:
            if stream:
                stream.close()
                try:await stream.wait_closed()
                except (OSError,ConnectionError):pass

async def main(routes):
    servers=[]
    for route in routes:
        async def handle(reader,writer,value=route):await bridge(reader,writer,value)
        servers.append(await asyncio.start_server(handle,'0.0.0.0',route['listen'],backlog=1024))
    await asyncio.gather(*(server.serve_forever() for server in servers))

if __name__=='__main__':
    with open(sys.argv[1]) as source:routes=json.load(source)
    asyncio.run(main(routes))
