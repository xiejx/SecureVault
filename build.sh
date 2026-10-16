#!/usr/bin/env bash
# 打包便携加密保险箱为 Linux 可执行文件（单文件、免安装）
# 用法：在 SecureVault 目录下执行  bash build.sh
#
# 前置条件：python3、python3-venv、python3-tk
#   Debian/Ubuntu: sudo apt-get install -y python3 python3-venv python3-tk
#
# 注意：PyInstaller 不支持交叉编译，必须在 Linux 上执行本脚本；
#       产物仅兼容 glibc 版本 >= 当前构建环境的发行版，想广兼容请用较老的基线环境构建。
set -euo pipefail
cd "$(dirname "$0")"

echo "[1/3] 安装依赖…"
python3 -m venv .venv
# shellcheck disable=SC1091
source .venv/bin/activate
python -m pip install --upgrade -r requirements.txt

echo "[2/3] 打包中…"
python -m PyInstaller \
    --noconfirm --clean --onefile --windowed \
    --name VaultApp \
    --collect-all tkinterdnd2 \
    vault_app.py

echo "[3/3] 完成，可执行文件位于 dist/VaultApp"
