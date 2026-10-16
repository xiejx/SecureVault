"""加密核心：Argon2id 口令派生、DEK 包装、AES-256-GCM 流式加解密。

设计要点
--------
* 口令 ---Argon2id--> KEK（密钥加密密钥，仅内存中短暂存在）
* 随机 DEK（数据加密密钥）由 KEK 用 AES-GCM 包装后存盘
  -> 改密码时只需重新包装 DEK，无需重加密全部文件
* 由 DEK 经 HKDF 派生两把子密钥：索引密钥、内容密钥
* 每个文件独立随机 nonce，AES-256-GCM 认证加密，AAD 绑定文件 ID
"""

from __future__ import annotations

import json
import os

from argon2.low_level import Type, hash_secret_raw
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

BLOB_MAGIC = b"VLTB01"      # 加密文件头标识（6 字节）
INDEX_MAGIC = b"VLTX01"     # 加密索引头标识（6 字节）
NONCE_LEN = 12
TAG_LEN = 16
KEY_LEN = 32
CHUNK_SIZE = 1 << 20        # 流式处理块大小 1 MiB

# Argon2id 参数：64 MiB 内存、3 轮迭代，兼顾安全与启动速度
ARGON2_TIME_COST = 3
ARGON2_MEMORY_COST = 65536   # KiB
ARGON2_PARALLELISM = 2


class VaultCryptoError(Exception):
    """加解密过程中的可预期错误（口令错误、数据损坏等）。"""


def make_kdf_params() -> dict:
    return {
        "time_cost": ARGON2_TIME_COST,
        "memory_cost": ARGON2_MEMORY_COST,
        "parallelism": ARGON2_PARALLELISM,
        "hash_len": KEY_LEN,
    }


def generate_salt() -> bytes:
    return os.urandom(16)


def derive_kek(password: str, salt: bytes, params: dict) -> bytes:
    """由口令和盐经 Argon2id 派生 KEK。"""
    return hash_secret_raw(
        secret=password.encode("utf-8"),
        salt=salt,
        time_cost=params["time_cost"],
        memory_cost=params["memory_cost"],
        parallelism=params["parallelism"],
        hash_len=params.get("hash_len", KEY_LEN),
        type=Type.ID,
    )


def _hkdf(dek: bytes, info: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=KEY_LEN, salt=None, info=info).derive(dek)


def wrap_dek(dek: bytes, kek: bytes) -> bytes:
    """用 KEK 包装 DEK，返回 nonce + 密文。"""
    nonce = os.urandom(NONCE_LEN)
    return nonce + AESGCM(kek).encrypt(nonce, dek, b"vault.dek")


def unwrap_dek(blob: bytes, kek: bytes) -> bytes:
    """解开 DEK；口令错误时 AES-GCM 校验失败。"""
    try:
        return AESGCM(kek).decrypt(blob[:NONCE_LEN], blob[NONCE_LEN:], b"vault.dek")
    except Exception as exc:  # InvalidTag 等
        raise VaultCryptoError("口令错误或保险箱已损坏") from exc


class VaultKeys:
    """解锁后驻留内存的派生密钥集合，锁定时应整体丢弃。"""

    def __init__(self, dek: bytes):
        self.dek = dek
        self._index_key = _hkdf(dek, b"vault.index")
        self._content_key = _hkdf(dek, b"vault.content")

    # ---- 索引（小数据，一次性 AEAD）----
    def encrypt_index(self, obj) -> bytes:
        nonce = os.urandom(NONCE_LEN)
        data = json.dumps(obj, ensure_ascii=False, separators=(",", ":")).encode("utf-8")
        return INDEX_MAGIC + nonce + AESGCM(self._index_key).encrypt(nonce, data, b"vault.index")

    def decrypt_index(self, blob: bytes):
        if not blob.startswith(INDEX_MAGIC):
            raise VaultCryptoError("索引文件格式不正确")
        off = len(INDEX_MAGIC)
        nonce = blob[off:off + NONCE_LEN]
        ct = blob[off + NONCE_LEN:]
        try:
            data = AESGCM(self._index_key).decrypt(nonce, ct, b"vault.index")
        except Exception as exc:
            raise VaultCryptoError("索引解密失败") from exc
        return json.loads(data.decode("utf-8"))

    # ---- 文件内容（流式，避免整文件载入内存）----
    def encrypt_file(self, src, dst, aad: bytes) -> int:
        nonce = os.urandom(NONCE_LEN)
        enc = Cipher(algorithms.AES(self._content_key), modes.GCM(nonce)).encryptor()
        enc.authenticate_additional_data(aad)

        dst.write(BLOB_MAGIC)
        dst.write(nonce)
        tag_pos = dst.tell()
        dst.write(b"\x00" * TAG_LEN)   # 先占位，finalize 后回填认证标签

        total = 0
        while True:
            chunk = src.read(CHUNK_SIZE)
            if not chunk:
                break
            total += len(chunk)
            dst.write(enc.update(chunk))
        dst.write(enc.finalize())

        end = dst.tell()
        dst.seek(tag_pos)
        dst.write(enc.tag)
        dst.seek(end)
        return total

    def decrypt_file(self, src, dst, aad: bytes) -> int:
        if src.read(len(BLOB_MAGIC)) != BLOB_MAGIC:
            raise VaultCryptoError("加密文件格式不正确")
        nonce = src.read(NONCE_LEN)
        tag = src.read(TAG_LEN)
        dec = Cipher(algorithms.AES(self._content_key), modes.GCM(nonce, tag)).decryptor()
        dec.authenticate_additional_data(aad)

        total = 0
        try:
            while True:
                chunk = src.read(CHUNK_SIZE)
                if not chunk:
                    break
                out = dec.update(chunk)
                total += len(out)
                dst.write(out)
            final = dec.finalize()   # 数据被篡改时在此抛出 InvalidTag
        except Exception as exc:     # InvalidTag 等
            raise VaultCryptoError("数据校验失败：文件可能已损坏或被篡改") from exc
        total += len(final)
        dst.write(final)
        return total
