$ErrorActionPreference = 'Stop'
Push-Location $PSScriptRoot
try {
    python -m PyInstaller --noconfirm --clean --onedir --name RelayDock --add-data 'relaydock/static;relaydock/static' --add-data 'relaydock/remote_agent.py;relaydock' --add-data 'relaydock/relay.py;relaydock' --hidden-import qrcode.image.pil --hidden-import qrcode.image.pure --hidden-import png --hidden-import bcrypt --hidden-import uvicorn.logging --hidden-import uvicorn.loops.auto --hidden-import uvicorn.protocols.http.h11_impl --hidden-import uvicorn.lifespan.on --exclude-module numpy --exclude-module pandas --exclude-module matplotlib --exclude-module scipy --exclude-module IPython launch.py
    if ($LASTEXITCODE -ne 0) { throw 'Windows build failed' }
    Copy-Item -LiteralPath (Join-Path $PSScriptRoot 'Запустить RelayDock.bat') -Destination 'dist/RelayDock/'
} finally {
    Pop-Location
}
