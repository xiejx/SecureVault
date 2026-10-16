# 打包便携加密保险箱为单文件 exe（免安装、双击即用）
# 用法：在 SecureVault 目录下执行  powershell -ExecutionPolicy Bypass -File build.ps1
$ErrorActionPreference = "Stop"
Set-Location -Path $PSScriptRoot

Write-Host "[1/3] 安装依赖…"
python -m pip install --upgrade -r requirements.txt

Write-Host "[2/3] 打包中…"
python -m PyInstaller `
    --noconfirm --clean --onefile --windowed `
    --name VaultApp `
    --collect-all tkinterdnd2 `
    vault_app.py

Write-Host "[3/3] 完成，可执行文件位于 dist\VaultApp.exe"
