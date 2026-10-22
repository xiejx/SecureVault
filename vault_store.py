"""保险箱存储层：目录布局、元数据、加密索引、文件与文件夹的增删改导出。

目录结构（便携模式，全部位于程序同级目录）
--------------------------------------------
vault/
├── meta.json          明文元数据：KDF 参数、盐、被包装的 DEK
├── index.enc          加密索引：文件夹层级 + 相对路径 / 大小 / 时间
└── data/
    └── <前两位>/
        └── <随机ID>.bin   每个文件独立 AES-256-GCM 加密，按 ID 前两位分片

索引中文件以「相对路径」记录（如 photos/2024/a.jpg），文件夹层级由索引
中的 folders 列表 + 文件路径共同还原，因此文件名与目录名都不会明文落盘。
"""

from __future__ import annotations

import base64
import json
import os
import uuid
from datetime import datetime
from pathlib import Path, PurePosixPath

from vault_crypto import (
    VaultCryptoError,
    VaultKeys,
    derive_kek,
    generate_salt,
    make_kdf_params,
    unwrap_dek,
    wrap_dek,
)

META_FILE = "meta.json"
INDEX_FILE = "index.enc"
DATA_DIR = "data"
META_APP = "PortableVault"
META_VERSION = 2                 # v1 = 扁平文件名；v2 = 相对路径 + 文件夹层级
DEFAULT_AUTO_LOCK = 600          # 默认 10 分钟无操作自动锁定
MIN_PASSWORD_LEN = 8

_INVALID_CHARS = '<>:"\\|?*'


class VaultError(Exception):
    """保险箱操作层面的错误。"""


# ---------------- 路径工具 ----------------
def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text.encode("ascii"))


def _now_iso() -> str:
    return datetime.now().astimezone().isoformat(timespec="seconds")


def _sanitize_segment(segment: str) -> str:
    """清洗单个路径片段，剔除非法字符与越权片段。"""
    segment = segment.strip()
    for ch in _INVALID_CHARS:
        segment = segment.replace(ch, "_")
    if segment in ("", ".", ".."):
        raise VaultError("文件名/文件夹名不合法")
    if segment != segment.strip("."):
        segment = segment.strip(".") or "unnamed"
    return segment


def normalize_rel(rel: str) -> str:
    """把任意输入规范成安全的相对路径（用 / 分隔）。"""
    rel = str(rel).replace("\\", "/")
    parts = [p for p in rel.split("/") if p not in ("", ".")]
    if any(p == ".." for p in parts):
        raise VaultError("路径不合法")
    if not parts:
        raise VaultError("路径不能为空")
    return "/".join(_sanitize_segment(p) for p in parts)


def parent_of(rel: str) -> str:
    return rel.rsplit("/", 1)[0] if "/" in rel else ""


def name_of(rel: str) -> str:
    return rel.rsplit("/", 1)[-1]


def ancestors_of(rel: str) -> list[str]:
    """返回 rel 的所有上级目录（由浅到深）。"""
    parts = rel.split("/")[:-1]
    return ["/".join(parts[:i]) for i in range(1, len(parts) + 1)]


def _atomic_write(path: Path, data: bytes) -> None:
    tmp = path.with_name(path.name + ".tmp")
    with open(tmp, "wb") as fh:
        fh.write(data)
        fh.flush()
        os.fsync(fh.fileno())
    os.replace(tmp, path)


def _read_json(path: Path) -> dict:
    with open(path, "r", encoding="utf-8") as fh:
        return json.load(fh)


def _secure_erase(path: Path, passes: int = 1) -> None:
    """用随机数据覆写文件后再删除，降低被恢复的可能。"""
    try:
        size = path.stat().st_size
        with open(path, "r+b") as fh:
            for _ in range(passes):
                fh.seek(0)
                left = size
                while left > 0:
                    n = min(left, 1 << 20)
                    fh.write(os.urandom(n))
                    left -= n
                fh.flush()
                os.fsync(fh.fileno())
        path.unlink()
    except OSError:
        path.unlink(missing_ok=True)


class Vault:
    def __init__(self, root: Path):
        self.root = Path(root)
        self.meta_path = self.root / META_FILE
        self.index_path = self.root / INDEX_FILE
        self.data_dir = self.root / DATA_DIR
        self.keys: VaultKeys | None = None
        self.index: dict | None = None
        self.auto_lock_seconds = DEFAULT_AUTO_LOCK

    # ---------------- 状态 ----------------
    @staticmethod
    def exists(root: Path) -> bool:
        return (Path(root) / META_FILE).is_file()

    @property
    def is_unlocked(self) -> bool:
        return self.keys is not None and self.index is not None

    # ---------------- 创建 / 解锁 / 锁定 ----------------
    @staticmethod
    def create(root: Path, password: str) -> "Vault":
        if Vault.exists(root):
            raise VaultError("该位置已存在保险箱")
        if len(password) < MIN_PASSWORD_LEN:
            raise VaultError(f"主密码至少需要 {MIN_PASSWORD_LEN} 个字符")

        vault = Vault(root)
        vault.root.mkdir(parents=True, exist_ok=True)
        vault.data_dir.mkdir(parents=True, exist_ok=True)

        params = make_kdf_params()
        salt = generate_salt()
        kek = derive_kek(password, salt, params)
        dek = os.urandom(32)

        meta = {
            "app": META_APP,
            "version": META_VERSION,
            "kdf": "argon2id",
            "kdf_params": params,
            "salt": _b64(salt),
            "wrapped_dek": _b64(wrap_dek(dek, kek)),
            "created": _now_iso(),
            "auto_lock_seconds": DEFAULT_AUTO_LOCK,
        }
        _atomic_write(vault.meta_path, json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"))

        vault.keys = VaultKeys(dek)
        vault.index = {"files": {}, "folders": []}
        vault._save_index()
        vault.auto_lock_seconds = DEFAULT_AUTO_LOCK
        return vault

    def unlock(self, password: str) -> bool:
        meta = _read_json(self.meta_path)
        kek = derive_kek(password, _unb64(meta["salt"]), meta["kdf_params"])
        try:
            dek = unwrap_dek(_unb64(meta["wrapped_dek"]), kek)
        except VaultCryptoError:
            return False   # 口令错误

        self.keys = VaultKeys(dek)
        try:
            self.index = self.keys.decrypt_index(self.index_path.read_bytes())
        except FileNotFoundError:
            self.index = {"files": {}, "folders": []}
        except VaultCryptoError as exc:
            self.keys = None
            raise VaultError(str(exc)) from exc
        self._migrate()
        self._migrate_blobs()
        self.auto_lock_seconds = int(meta.get("auto_lock_seconds", DEFAULT_AUTO_LOCK))
        return True

    def _migrate(self) -> None:
        """兼容 v1（扁平文件名）索引，升级为 v2（相对路径 + 文件夹）。"""
        self.index.setdefault("files", {})
        folders = self.index.setdefault("folders", [])
        if not isinstance(folders, list):
            folders = self.index["folders"] = []
        known = set(folders)
        for info in self.index["files"].values():
            if "path" not in info:                     # v1 的 name 字段
                info["path"] = normalize_rel(info.pop("name", "unnamed"))
            for ancestor in ancestors_of(info["path"]):
                known.add(ancestor)
        self.index["folders"] = sorted(known)

    def _migrate_blobs(self) -> None:
        """把旧版扁平的 data/<id>.bin 迁移到 data/<前两位>/<id>.bin。"""
        try:
            entries = list(os.scandir(self.data_dir))
        except (FileNotFoundError, OSError):
            return
        files = self.index["files"]
        for entry in entries:
            name = entry.name
            if not name.endswith(".bin") or not entry.is_file():
                continue
            fid = name[:-4]
            if fid not in files:
                continue
            target = self._blob_path(fid)
            if target.exists():
                continue
            target.parent.mkdir(parents=True, exist_ok=True)
            try:
                os.replace(entry.path, target)
            except OSError:
                pass

    def lock(self) -> None:
        self.keys = None
        self.index = None

    # ---------------- 索引基础 ----------------
    def _save_index(self) -> None:
        self.index["folders"] = sorted(set(self.index["folders"]))
        _atomic_write(self.index_path, self.keys.encrypt_index(self.index))

    def _blob_path(self, fid: str) -> Path:
        """密文按 ID 前两位分片存放：data/<前两位>/<id>.bin。"""
        return self.data_dir / fid[:2] / f"{fid}.bin"

    def _scratch(self, fid: str) -> Path:
        """写入前的临时文件，放在与目标相同的分片目录内，保证替换原子性。"""
        blob = self._blob_path(fid)
        blob.parent.mkdir(parents=True, exist_ok=True)
        return blob.with_name(f".{fid}.tmp")

    def _require_unlocked(self) -> None:
        if not self.is_unlocked:
            raise VaultError("保险箱处于锁定状态")

    def _taken_paths(self) -> set[str]:
        taken = {f.lower() for f in self.index["folders"]}
        taken |= {info["path"].lower() for info in self.index["files"].values()}
        return taken

    @staticmethod
    def _unique_rel(rel: str, taken: set[str]) -> str:
        if rel.lower() not in taken:
            return rel
        parent, name = parent_of(rel), name_of(rel)
        stem, suffix = PurePosixPath(name).stem, PurePosixPath(name).suffix
        i = 1
        while True:
            candidate = f"{parent}/{stem} ({i}){suffix}" if parent else f"{stem} ({i}){suffix}"
            if candidate.lower() not in taken:
                return candidate
            i += 1

    # ---------------- 查询 ----------------
    def list_files(self) -> list[dict]:
        self._require_unlocked()
        return [{"fid": fid, **info} for fid, info in self.index["files"].items()]

    def list_folders(self) -> list[str]:
        self._require_unlocked()
        return sorted(self.index["folders"])

    # ---------------- 导入（保留目录结构）----------------
    def add_files(self, items) -> tuple[int, list]:
        """items: 可迭代的 (源文件路径, 保险箱内相对路径)。

        返回 (成功数, 失败列表[ (名称, 原因) ])。
        """
        self._require_unlocked()
        folder_set = set(self.index["folders"])
        taken = self._taken_paths()
        added, failed = 0, []

        for src_raw, rel_raw in items:
            src = Path(src_raw)
            if not src.is_file():
                failed.append((str(src_raw), "不是有效的文件"))
                continue
            try:
                rel = self._unique_rel(normalize_rel(rel_raw), taken)
            except VaultError as exc:
                failed.append((Path(str(rel_raw)).name, str(exc)))
                continue

            fid = uuid.uuid4().hex
            tmp = self._scratch(fid)
            try:
                with open(src, "rb") as fin, open(tmp, "wb") as fout:
                    size = self.keys.encrypt_file(fin, fout, fid.encode("ascii"))
                os.replace(tmp, self._blob_path(fid))
            except (VaultCryptoError, OSError) as exc:
                tmp.unlink(missing_ok=True)
                failed.append((src.name, f"加密失败：{exc}"))
                continue

            stat = src.stat()
            self.index["files"][fid] = {
                "path": rel,
                "size": size,
                "mtime": datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds"),
                "added": _now_iso(),
            }
            for ancestor in ancestors_of(rel):
                folder_set.add(ancestor)
                taken.add(ancestor.lower())
            taken.add(rel.lower())
            added += 1

        self.index["folders"] = sorted(folder_set)
        self._save_index()
        return added, failed

    # ---------------- 导出 ----------------
    def extract_file(self, fid: str, dst_path) -> Path:
        """把保险箱内文件解密导出到 dst_path（若为目录则使用原文件名）。"""
        self._require_unlocked()
        entry = self.index["files"].get(fid)
        if entry is None:
            raise VaultError("文件不存在")

        dst = Path(dst_path)
        if dst.is_dir():
            dst = dst / name_of(entry["path"])
        dst.parent.mkdir(parents=True, exist_ok=True)
        tmp = dst.with_name(dst.name + ".vaulttmp")
        try:
            with open(self._blob_path(fid), "rb") as fin, open(tmp, "wb") as fout:
                self.keys.decrypt_file(fin, fout, fid.encode("ascii"))
            os.replace(tmp, dst)
        except VaultCryptoError as exc:
            tmp.unlink(missing_ok=True)
            raise VaultError("解密失败：数据可能已损坏或被篡改") from exc
        except FileNotFoundError as exc:
            tmp.unlink(missing_ok=True)
            raise VaultError("保险箱中缺少该文件的数据") from exc
        except OSError as exc:
            tmp.unlink(missing_ok=True)
            raise VaultError(f"写入目标失败：{exc}") from exc
        return dst

    def replace_file(self, fid: str, src_path) -> dict:
        """用磁盘上的新内容覆盖保险箱内同 ID 的文件（用于外部编辑后回存）。

        blob 路径由 fid 决定，AAD 也绑定 fid，因此原地替换不会破坏认证。
        """
        self._require_unlocked()
        info = self.index["files"].get(fid)
        if info is None:
            raise VaultError("文件不存在")
        src = Path(src_path)
        if not src.is_file():
            raise VaultError("源文件不存在")

        tmp = self._scratch(fid)
        try:
            with open(src, "rb") as fin, open(tmp, "wb") as fout:
                size = self.keys.encrypt_file(fin, fout, fid.encode("ascii"))
            os.replace(tmp, self._blob_path(fid))
        except (VaultCryptoError, OSError) as exc:
            tmp.unlink(missing_ok=True)
            raise VaultError(f"回存失败：{exc}") from exc

        stat = src.stat()
        info["size"] = size
        info["mtime"] = datetime.fromtimestamp(stat.st_mtime).astimezone().isoformat(timespec="seconds")
        self._save_index()
        return {"fid": fid, **info}

    # ---------------- 删除 ----------------
    def _drop_file(self, fid: str, secure: bool) -> None:
        blob = self._blob_path(fid)
        if blob.exists():
            if secure:
                _secure_erase(blob)
            else:
                blob.unlink()
        self.index["files"].pop(fid, None)

    def remove_file(self, fid: str, secure: bool = True) -> None:
        self._require_unlocked()
        if fid not in self.index["files"]:
            raise VaultError("文件不存在")
        self._drop_file(fid, secure)
        self._save_index()

    def remove_folder(self, rel: str, secure: bool = True) -> int:
        """递归删除文件夹及其内所有文件，返回删除的文件数。"""
        self._require_unlocked()
        rel = normalize_rel(rel)
        prefix = rel + "/"
        victims = [fid for fid, info in self.index["files"].items() if info["path"].startswith(prefix)]
        for fid in victims:
            self._drop_file(fid, secure)
        self.index["folders"] = [
            f for f in self.index["folders"] if f != rel and not f.startswith(prefix)
        ]
        self._save_index()
        return len(victims)

    # ---------------- 文件夹操作 ----------------
    def create_folder(self, rel: str) -> str:
        self._require_unlocked()
        taken = self._taken_paths()
        rel = self._unique_rel(normalize_rel(rel), taken)
        folder_set = set(self.index["folders"])
        for ancestor in ancestors_of(rel) + [rel]:
            folder_set.add(ancestor)
        self.index["folders"] = sorted(folder_set)
        self._save_index()
        return rel

    def rename_folder(self, rel: str, new_name: str) -> str:
        self._require_unlocked()
        rel = normalize_rel(rel)
        if rel not in self.index["folders"]:
            raise VaultError("文件夹不存在")
        parent = parent_of(rel)
        taken = self._taken_paths()
        prefix = rel + "/"
        for path in list(taken):                        # 释放旧路径及其后代
            if path == rel.lower() or path.startswith(prefix.lower()):
                taken.discard(path)
        new_rel = self._unique_rel(
            f"{parent}/{normalize_rel(new_name)}" if parent else normalize_rel(new_name), taken
        )
        self._rewrite_prefix(rel, new_rel)
        self._save_index()
        return new_rel

    def move_folder(self, rel: str, dest: str) -> str:
        self._require_unlocked()
        rel = normalize_rel(rel)
        dest = normalize_rel(dest) if dest else ""
        if dest == rel or dest.startswith(rel + "/"):
            raise VaultError("不能把文件夹移动到它自己或它的子目录中")
        if rel not in self.index["folders"]:
            raise VaultError("文件夹不存在")
        taken = self._taken_paths()
        for path in list(taken):
            if path == rel.lower() or path.startswith((rel + "/").lower()):
                taken.discard(path)
        target = f"{dest}/{name_of(rel)}" if dest else name_of(rel)
        new_rel = self._unique_rel(target, taken)
        self._rewrite_prefix(rel, new_rel)
        folder_set = set(self.index["folders"])
        for ancestor in ancestors_of(new_rel):
            folder_set.add(ancestor)
        self.index["folders"] = sorted(folder_set)
        self._save_index()
        return new_rel

    def _rewrite_prefix(self, old_rel: str, new_rel: str) -> None:
        """把文件夹及其所有后代的路径前缀整体替换。"""
        prefix = old_rel + "/"
        self.index["folders"] = [
            new_rel + f[len(old_rel):] if (f == old_rel or f.startswith(prefix)) else f
            for f in self.index["folders"]
        ]
        for info in self.index["files"].values():
            if info["path"].startswith(prefix):
                info["path"] = new_rel + info["path"][len(old_rel):]

    # ---------------- 文件改名 / 移动 ----------------
    def rename_file(self, fid: str, new_name: str) -> str:
        self._require_unlocked()
        info = self.index["files"].get(fid)
        if info is None:
            raise VaultError("文件不存在")
        parent = parent_of(info["path"])
        taken = self._taken_paths()
        taken.discard(info["path"].lower())
        new_rel = self._unique_rel(
            f"{parent}/{normalize_rel(new_name)}" if parent else normalize_rel(new_name), taken
        )
        info["path"] = new_rel
        self._save_index()
        return new_rel

    def move_files(self, fids, dest: str) -> int:
        """把若干文件移动到 dest 文件夹（"" 表示根目录）。"""
        self._require_unlocked()
        dest = normalize_rel(dest) if dest else ""
        taken = self._taken_paths()
        folder_set = set(self.index["folders"])
        moved = 0
        for fid in fids:
            info = self.index["files"].get(fid)
            if info is None:
                continue
            taken.discard(info["path"].lower())
            target = f"{dest}/{name_of(info['path'])}" if dest else name_of(info["path"])
            new_rel = self._unique_rel(target, taken)
            info["path"] = new_rel
            taken.add(new_rel.lower())
            for ancestor in ancestors_of(new_rel):
                folder_set.add(ancestor)
            moved += 1
        self.index["folders"] = sorted(folder_set)
        self._save_index()
        return moved

    # ---------------- 修改主密码 ----------------
    def change_password(self, old_password: str, new_password: str) -> bool:
        self._require_unlocked()
        if len(new_password) < MIN_PASSWORD_LEN:
            raise VaultError(f"新密码至少需要 {MIN_PASSWORD_LEN} 个字符")

        meta = _read_json(self.meta_path)
        kek = derive_kek(old_password, _unb64(meta["salt"]), meta["kdf_params"])
        try:
            unwrap_dek(_unb64(meta["wrapped_dek"]), kek)
        except VaultCryptoError:
            return False   # 原密码错误

        # 只需用新口令派生 KEK 重新包装同一把 DEK，无需重加密文件
        salt = generate_salt()
        new_kek = derive_kek(new_password, salt, meta["kdf_params"])
        meta["salt"] = _b64(salt)
        meta["wrapped_dek"] = _b64(wrap_dek(self.keys.dek, new_kek))
        meta["version"] = META_VERSION
        meta["password_changed"] = _now_iso()
        _atomic_write(self.meta_path, json.dumps(meta, ensure_ascii=False, indent=2).encode("utf-8"))
        return True
