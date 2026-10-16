"""便携加密保险箱 —— 图形界面（tkinter）。

特点：
* 免安装、双击即用：程序与保险箱数据放在同一目录，整个文件夹可直接搬上 U 盘
* 支持把文件 / 整个文件夹从资源管理器拖进窗口，目录层级会被完整保留
* 支持新建文件夹、重命名、移动到其他文件夹、递归删除
* 双击文件即可像资源管理器那样用系统默认程序打开，改动会在锁定/退出时自动回存
* 右键或工具栏「导出」可把文件按原目录结构解密还原到本地
* 空闲自动锁定，锁定后内存中的密钥被丢弃
"""

from __future__ import annotations

import ctypes
import os
import queue
import shutil
import sys
import tempfile
import threading
import time
from pathlib import Path, PurePosixPath

import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk

from vault_store import (
    DEFAULT_AUTO_LOCK,
    Vault,
    VaultError,
    ancestors_of,
    name_of,
    parent_of,
)

# ---- 拖拽支持（tkinterdnd2 可选，缺失时退化为按钮添加）----
DND_AVAILABLE = True
try:
    from tkinterdnd2 import DND_FILES, TkinterDnD
except Exception:  # pragma: no cover
    DND_AVAILABLE = False
    DND_FILES = None
    TkinterDnD = None

FOLDER_PREFIX = "folder:"
FILE_PREFIX = "file:"
ROOT_LABEL = "（根目录）"
WORKSPACE_PREFIX = "VaultApp_open_"     # 双击打开时的临时解密目录前缀


def app_dir() -> Path:
    """程序所在目录：打包后为 exe 所在目录，开发时为源码目录。"""
    if getattr(sys, "frozen", False):
        return Path(sys.executable).resolve().parent
    return Path(__file__).resolve().parent


VAULT_DIR = app_dir() / "vault"


def human_size(n: int) -> str:
    value = float(n)
    for unit in ("B", "KB", "MB", "GB", "TB"):
        if value < 1024 or unit == "TB":
            return f"{value:.0f} {unit}" if unit == "B" else f"{value:.1f} {unit}"
        value /= 1024
    return f"{value:.1f} TB"


def unique_target(target: Path) -> Path:
    """导出时避免覆盖同名文件。"""
    if not target.exists():
        return target
    stem, suffix = target.stem, target.suffix
    i = 1
    while True:
        candidate = target.with_name(f"{stem} ({i}){suffix}")
        if not candidate.exists():
            return candidate
        i += 1


def enable_high_dpi() -> None:
    """声明进程 DPI 感知，避免 Windows 对窗口内容做位图拉伸导致界面发虚。

    必须在创建 Tk 窗口之前调用。逐级降级：Win10 1703+ 的 PMv2 → Win8.1 的
    shcore → Vista 的 SetProcessDPIAware。
    """
    if sys.platform != "win32":
        return
    try:  # Windows 10 1703+：按显示器 DPI 感知（V2），最清晰
        fn = ctypes.windll.user32.SetProcessDpiAwarenessContext
        fn.argtypes = [ctypes.c_void_p]
        fn.restype = ctypes.c_bool
        if fn(ctypes.c_void_p(-4)):
            return
    except Exception:
        pass
    try:  # Windows 8.1+
        fn = ctypes.windll.shcore.SetProcessDpiAwareness
        fn.argtypes = [ctypes.c_int]
        fn.restype = ctypes.c_long
        if fn(2) == 0:
            return
    except Exception:
        pass
    try:  # Windows Vista+
        ctypes.windll.user32.SetProcessDPIAware()
    except Exception:
        pass


class PasswordDialog(tk.Toplevel):
    """口令输入弹窗，返回 dict[str, str] 或 None。"""

    def __init__(self, parent, title: str, fields: list[tuple[str, str]]):
        super().__init__(parent)
        self.title(title)
        self.resizable(False, False)
        self.transient(parent)
        self.result: dict[str, str] | None = None

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        self._vars: dict[str, tk.StringVar] = {}
        self._entries: list[ttk.Entry] = []
        self._show = tk.BooleanVar(value=False)

        for label, key in fields:
            row = ttk.Frame(body)
            row.pack(fill="x", pady=4)
            ttk.Label(row, text=label, width=10).pack(side="left")
            var = tk.StringVar()
            entry = ttk.Entry(row, textvariable=var, width=28, show="●")
            entry.pack(side="left", fill="x", expand=True)
            self._vars[key] = var
            self._entries.append(entry)
        if self._entries:
            self._entries[0].focus_set()

        ttk.Checkbutton(body, text="显示密码", variable=self._show, command=self._toggle_show).pack(
            anchor="e", pady=(6, 10)
        )

        buttons = ttk.Frame(body)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="取消", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="确定", command=self._confirm).pack(side="right")

        self.bind("<Return>", lambda _e: self._confirm())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.grab_set()

    def _toggle_show(self) -> None:
        show = "" if self._show.get() else "●"
        for entry in self._entries:
            entry.configure(show=show)

    def _confirm(self) -> None:
        self.result = {k: v.get() for k, v in self._vars.items()}
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


class FolderPickerDialog(tk.Toplevel):
    """选择目标文件夹。result: None=取消，""=根目录，其余为相对路径。"""

    def __init__(self, parent, folders: list[str]):
        super().__init__(parent)
        self.title("移动到…")
        self.resizable(False, False)
        self.transient(parent)
        self.result: str | None = None

        body = ttk.Frame(self, padding=16)
        body.pack(fill="both", expand=True)
        ttk.Label(body, text="目标文件夹：").pack(anchor="w")
        self._combo = ttk.Combobox(
            body, values=[ROOT_LABEL] + folders, state="readonly", width=36
        )
        self._combo.pack(fill="x", pady=(4, 12))
        self._combo.current(0)

        buttons = ttk.Frame(body)
        buttons.pack(fill="x")
        ttk.Button(buttons, text="取消", command=self._cancel).pack(side="right", padx=(6, 0))
        ttk.Button(buttons, text="确定", command=self._confirm).pack(side="right")

        self.bind("<Return>", lambda _e: self._confirm())
        self.bind("<Escape>", lambda _e: self._cancel())
        self.grab_set()

    def _confirm(self) -> None:
        value = self._combo.get()
        self.result = "" if value == ROOT_LABEL else value
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()


class VaultApp:
    def __init__(self):
        enable_high_dpi()
        self.root = TkinterDnD.Tk() if DND_AVAILABLE else tk.Tk()
        self.root.title("便携加密保险箱")
        self._scale = 1.0
        self._apply_dpi()
        self.root.geometry(f"{self._px(860)}x{self._px(580)}")
        self.root.minsize(self._px(680), self._px(460))

        self.vault = Vault(VAULT_DIR)
        self._last_activity = time.monotonic()
        self._busy = False
        self._auto_lock_job = None
        self._open_folders: set[str] = set()
        self._workspace_dir: Path | None = None
        self._opened: dict[str, dict] = {}   # fid -> {path, rel, size, mtime}
        self._purge_stale_workspaces()

        self._lock_frame = self._build_lock_view()
        self._main_frame = self._build_main_view()

        self._bind_activity()
        if DND_AVAILABLE:
            self._register_drop(self.root)

        self._show_lock(create=not Vault.exists(VAULT_DIR))
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ================= DPI 缩放 =================
    def _apply_dpi(self) -> None:
        """按显示器真实 DPI 设置 Tk 缩放，使 ttk 控件与字体尺寸匹配屏幕。"""
        dpi = 96.0
        try:
            dpi = float(self.root.winfo_fpixels("1i"))
        except tk.TclError:
            pass
        if sys.platform == "win32":
            try:
                dpi = max(dpi, float(ctypes.windll.user32.GetDpiForSystem()))
            except Exception:
                pass
        dpi = max(96.0, dpi)
        self._scale = dpi / 96.0
        try:
            self.root.tk.call("tk", "scaling", dpi / 72.0)
        except tk.TclError:
            pass

    def _px(self, value: float) -> int:
        """把按 96 DPI 设计的像素值换算到当前缩放。"""
        return max(1, int(round(value * self._scale)))

    # ================= 界面构建 =================
    def _build_lock_view(self) -> ttk.Frame:
        frame = ttk.Frame(self.root, padding=40)

        card = ttk.Frame(frame)
        card.place(relx=0.5, rely=0.45, anchor="center")

        ttk.Label(card, text="便携加密保险箱", font=("Segoe UI", 22, "bold")).pack()
        ttk.Label(
            card, text="在你的移动存储上创建一个受密码保护的私人文件夹",
            foreground="#666",
        ).pack(pady=(6, 22))

        self._is_create = not Vault.exists(VAULT_DIR)

        self._pw_var = tk.StringVar()
        self._pw2_var = tk.StringVar()
        self._show_pw = tk.BooleanVar(value=False)

        ttk.Label(card, text="主密码").pack(anchor="w")
        self._pw_entry = ttk.Entry(card, textvariable=self._pw_var, width=36, show="●")
        self._pw_entry.pack(fill="x", pady=(2, 10))

        self._pw2_label = ttk.Label(card, text="确认密码")
        self._pw2_entry = ttk.Entry(card, textvariable=self._pw2_var, width=36, show="●")

        ttk.Checkbutton(
            card, text="显示密码", variable=self._show_pw, command=self._toggle_lock_show,
        ).pack(anchor="e", pady=(0, 12))

        self._lock_btn = ttk.Button(card, text="解锁", command=self._on_lock_action, width=22)
        self._lock_btn.pack(pady=(4, 14))

        ttk.Label(
            card, text=f"保险箱位置：{VAULT_DIR}",
            foreground="#888", wraplength=self._px(360), justify="center",
        ).pack()
        hint = "拖拽文件或文件夹即可加密保存" if DND_AVAILABLE else "此构建未启用拖拽，请使用“添加文件”按钮"
        ttk.Label(card, text=hint, foreground="#888").pack(pady=(2, 0))

        self._pw_entry.bind("<Return>", lambda _e: self._on_lock_action())
        self._pw2_entry.bind("<Return>", lambda _e: self._on_lock_action())
        return frame

    def _build_main_view(self) -> ttk.Frame:
        frame = ttk.Frame(self.root)

        toolbar = ttk.Frame(frame, padding=(self._px(10), self._px(8)))
        toolbar.pack(fill="x")
        self._buttons: list[ttk.Button] = []
        for text, command in (
            ("新建文件夹", self._on_new_folder),
            ("添加文件", self._on_add_files),
            ("导出", self._on_export_selected),
            ("删除", self._on_delete),
            ("修改密码", self._on_change_password),
            ("锁定", self._on_lock_now),
        ):
            btn = ttk.Button(toolbar, text=text, command=command)
            btn.pack(side="left", padx=(0, 6))
            self._buttons.append(btn)

        self._progress = ttk.Progressbar(toolbar, mode="indeterminate", length=self._px(120))

        dnd_hint = "拖入文件/文件夹即可加密 · 双击文件可直接打开" if DND_AVAILABLE else "双击文件可直接打开"
        ttk.Label(toolbar, text=dnd_hint, foreground="#888").pack(side="right")

        tree_wrap = ttk.Frame(frame, padding=(self._px(10), 0))
        tree_wrap.pack(fill="both", expand=True)

        self._tree = ttk.Treeview(
            tree_wrap, columns=("size", "mtime"), show="tree headings", selectmode="extended",
        )
        self._tree.heading("#0", text="名称")
        self._tree.heading("size", text="大小")
        self._tree.heading("mtime", text="修改时间")
        self._tree.column("#0", width=self._px(420), anchor="w")
        self._tree.column("size", width=self._px(110), anchor="e")
        self._tree.column("mtime", width=self._px(180), anchor="center")

        vsb = ttk.Scrollbar(tree_wrap, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=vsb.set)
        self._tree.pack(side="left", fill="both", expand=True)
        vsb.pack(side="right", fill="y")

        self._tree.bind("<Double-1>", self._on_tree_double_click)
        self._tree.bind("<Delete>", lambda _e: self._on_delete())
        self._tree.bind("<F2>", lambda _e: self._on_rename())
        self._tree.bind("<<TreeviewOpen>>", lambda _e: self._remember_open(True))
        self._tree.bind("<<TreeviewClose>>", lambda _e: self._remember_open(False))

        self._menu = tk.Menu(self.root, tearoff=0)
        self._menu.add_command(label="打开", command=self._on_open_selected)
        self._menu.add_command(label="导出到本地…", command=self._on_export_selected)
        self._menu.add_command(label="移动到…", command=self._on_move)
        self._menu.add_command(label="重命名", command=self._on_rename)
        self._menu.add_separator()
        self._menu.add_command(label="删除", command=self._on_delete)
        self._menu.add_separator()
        self._menu.add_command(label="新建文件夹", command=self._on_new_folder)
        self._tree.bind("<Button-3>", self._on_tree_right_click)

        status = ttk.Frame(frame, padding=(self._px(10), self._px(6)))
        status.pack(fill="x")
        self._status_var = tk.StringVar(value="就绪")
        ttk.Label(status, textvariable=self._status_var, foreground="#444").pack(side="left")
        self._lock_var = tk.StringVar(value="")
        ttk.Label(status, textvariable=self._lock_var, foreground="#888").pack(side="right")

        if DND_AVAILABLE:
            self._register_drop(frame)
            self._register_drop(self._tree)
        return frame

    # ================= 拖拽 =================
    def _register_drop(self, widget) -> None:
        try:
            widget.drop_target_register(DND_FILES)
            widget.dnd_bind("<<Drop>>", self._on_drop)
        except Exception:
            pass

    def _on_drop(self, event) -> str:
        if not self.vault.is_unlocked or self._busy:
            return "break"
        try:
            paths = self.root.tk.splitlist(event.data)
        except tk.TclError:
            paths = [event.data]
        self._import_paths(paths, self._current_folder())
        return "break"

    # ================= 锁定 / 解锁 界面切换 =================
    def _show_lock(self, create: bool) -> None:
        self._is_create = create
        self._main_frame.pack_forget()
        self._lock_frame.pack(fill="both", expand=True)
        self._pw_var.set("")
        self._pw2_var.set("")
        if create:
            self._lock_btn.configure(text="创建保险箱")
            self._pw2_label.pack(anchor="w", pady=(6, 0))
            self._pw2_entry.pack(fill="x", pady=(2, 6))
        else:
            self._lock_btn.configure(text="解锁")
            self._pw2_label.pack_forget()
            self._pw2_entry.pack_forget()
        self.root.after(100, self._pw_entry.focus_set)

    def _show_main(self) -> None:
        self._lock_frame.pack_forget()
        self._main_frame.pack(fill="both", expand=True)
        self._open_folders = set()
        self._last_activity = time.monotonic()
        self._refresh()
        self._schedule_tick()

    def _toggle_lock_show(self) -> None:
        show = "" if self._show_pw.get() else "●"
        self._pw_entry.configure(show=show)
        self._pw2_entry.configure(show=show)

    def _on_lock_action(self) -> None:
        password = self._pw_var.get()
        if self._is_create:
            if password != self._pw2_var.get():
                messagebox.showwarning("提示", "两次输入的密码不一致", parent=self.root)
                return
            if len(password) < 8:
                messagebox.showwarning("提示", "主密码至少需要 8 个字符", parent=self.root)
                return
            try:
                self.vault = Vault.create(VAULT_DIR, password)
            except VaultError as exc:
                messagebox.showerror("创建失败", str(exc), parent=self.root)
                return
            self._pw_var.set("")
            self._pw2_var.set("")
            self._show_main()
            messagebox.showinfo("完成", "保险箱已创建，把文件或文件夹拖进窗口即可加密保存。", parent=self.root)
        else:
            if not password:
                return

            def work():
                return self.vault.unlock(password)

            def done(ok):
                self._pw_var.set("")
                if ok:
                    self._show_main()
                else:
                    messagebox.showerror("解锁失败", "密码错误，请重试。", parent=self.root)

            self._run_async(work, done, "正在校验密码…")

    def _on_lock_now(self) -> None:
        saved, failed = self._sync_open_files()
        self.vault.lock()
        if self._auto_lock_job:
            self.root.after_cancel(self._auto_lock_job)
            self._auto_lock_job = None
        self._cleanup_workspace()
        self._open_folders = set()
        self._lock_var.set("")
        self._show_lock(create=False)
        if failed:
            messagebox.showwarning(
                "部分改动未能回存",
                "以下文件正被其它程序占用，改动未写回保险箱：\n\n" + "\n".join(failed[:10]),
                parent=self.root,
            )
        self._set_status(f"已锁定（回存 {saved} 个改动文件）" if saved else "已锁定")

    # ================= 选择辅助 =================
    def _selected_file_ids(self) -> list[str]:
        return [iid[len(FILE_PREFIX):] for iid in self._tree.selection() if iid.startswith(FILE_PREFIX)]

    def _selected_folder_paths(self) -> list[str]:
        return [iid[len(FOLDER_PREFIX):] for iid in self._tree.selection() if iid.startswith(FOLDER_PREFIX)]

    def _current_folder(self) -> str:
        """当前上下文文件夹：选中文件夹时为其本身，否则为根目录。"""
        folders = self._selected_folder_paths()
        return folders[0] if folders else ""

    # ================= 导入（保留目录结构）=================
    def _on_new_folder(self) -> None:
        name = simpledialog.askstring("新建文件夹", "文件夹名：", parent=self.root)
        if not name:
            return
        parent = self._current_folder()
        target = f"{parent}/{name}" if parent else name

        def work():
            return self.vault.create_folder(target)

        def done(rel):
            if parent:
                self._open_folders.add(parent)
            self._open_folders |= set(ancestors_of(rel))
            self._refresh()
            self._set_status(f"已创建文件夹：{rel}")

        self._run_async(work, done, "正在创建文件夹…")

    def _on_add_files(self) -> None:
        paths = filedialog.askopenfilenames(parent=self.root, title="选择要加密保存的文件")
        if paths:
            self._import_paths(list(paths), self._current_folder())

    def _collect_items(self, paths: list[str], dest: str) -> list[tuple[Path, str]]:
        """把待导入的路径整理成 (源文件, 保险箱内相对路径) 列表，目录层级原样保留。"""
        base = f"{dest}/" if dest else ""
        items: list[tuple[Path, str]] = []
        for raw in paths:
            path = Path(raw)
            if path.is_file():
                items.append((path, base + path.name))
            elif path.is_dir():
                prefix = base + path.name
                for sub in sorted(p for p in path.rglob("*") if p.is_file()):
                    rel = sub.relative_to(path).as_posix()
                    items.append((sub, f"{prefix}/{rel}"))
        return items

    def _import_paths(self, paths: list[str], dest: str) -> None:
        items = self._collect_items(paths, dest)
        if not items:
            return
        if dest:
            self._open_folders.add(dest)

        def work():
            return self.vault.add_files(items)

        def done(result):
            added, failed = result
            self._refresh()
            self._set_status(f"已加密保存 {added} 个文件")
            if failed:
                lines = [f"{name}：{reason}" for name, reason in failed[:10]]
                messagebox.showwarning(
                    "部分文件未能保存", "以下文件保存失败：\n" + "\n".join(lines), parent=self.root,
                )

        self._run_async(work, done, f"正在加密 {len(items)} 个文件…")

    # ================= 导出（保留目录结构）=================
    def _selected_export_items(self) -> list[tuple[str, str]]:
        """返回 (fid, 保险箱内相对路径) 列表，选中文件夹时包含其全部后代文件。"""
        entries = {item["fid"]: item for item in self.vault.list_files()}
        out: list[tuple[str, str]] = []
        seen: set[str] = set()
        for iid in self._tree.selection():
            if iid.startswith(FILE_PREFIX):
                fid = iid[len(FILE_PREFIX):]
                if fid in entries and fid not in seen:
                    seen.add(fid)
                    out.append((fid, entries[fid]["path"]))
            else:
                prefix = iid[len(FOLDER_PREFIX):] + "/"
                for fid, info in entries.items():
                    if info["path"].startswith(prefix) and fid not in seen:
                        seen.add(fid)
                        out.append((fid, info["path"]))
        return out

    def _on_export_selected(self) -> None:
        items = self._selected_export_items()
        if not items:
            messagebox.showinfo("提示", "请先选择要导出的文件或文件夹", parent=self.root)
            return
        folder = filedialog.askdirectory(parent=self.root, title="选择导出目录")
        if not folder:
            return
        out_dir = Path(folder)

        def work():
            exported, failed = 0, []
            for fid, rel in items:
                target = unique_target(out_dir / PurePosixPath(rel))
                try:
                    self.vault.extract_file(fid, target)
                    exported += 1
                except VaultError as exc:
                    failed.append(f"{rel}：{exc}")
            return exported, failed

        def done(result):
            exported, failed = result
            self._set_status(f"已导出 {exported} 个文件（保留目录结构）到 {out_dir}")
            if failed:
                messagebox.showwarning("部分文件导出失败", "\n".join(failed[:10]), parent=self.root)

        self._run_async(work, done, f"正在解密导出 {len(items)} 个文件…")

    def _on_tree_double_click(self, event) -> str:
        iid = self._tree.identify_row(event.y)
        if not iid:
            return "break"
        if iid.startswith(FOLDER_PREFIX):
            self._tree.item(iid, open=not self._tree.item(iid, "open"))
            self._remember_explicit(iid, self._tree.item(iid, "open"))
            return "break"

        fid = iid[len(FILE_PREFIX):]
        self._open_file(fid)
        return "break"

    # ================= 双击打开（临时解密 + 系统默认程序）=================
    def _purge_stale_workspaces(self) -> None:
        """启动时清理上次运行遗留的临时明文目录。"""
        try:
            for path in Path(tempfile.gettempdir()).glob(WORKSPACE_PREFIX + "*"):
                shutil.rmtree(path, ignore_errors=True)
        except OSError:
            pass

    def _workspace(self) -> Path:
        if self._workspace_dir is None:
            self._workspace_dir = Path(tempfile.mkdtemp(prefix=WORKSPACE_PREFIX))
        return self._workspace_dir

    def _open_file(self, fid: str) -> None:
        """像资源管理器那样双击打开：解密到临时目录后交给系统默认程序。"""
        info = next((item for item in self.vault.list_files() if item["fid"] == fid), None)
        if info is None:
            return

        record = self._opened.get(fid)
        if record is not None and record["path"].exists():
            self._launch(record["path"], record["rel"])
            return

        target = self._workspace() / PurePosixPath(info["path"])

        def work():
            self.vault.extract_file(fid, target)
            return target

        def done(path):
            stat = Path(path).stat()
            self._opened[fid] = {
                "path": Path(path), "rel": info["path"],
                "size": stat.st_size, "mtime": stat.st_mtime,
            }
            self._launch(Path(path), info["path"])

        self._run_async(work, done, f"正在解密打开 {info['path']}…")

    def _launch(self, path: Path, rel: str) -> None:
        try:
            os.startfile(str(path))
        except OSError as exc:
            messagebox.showerror(
                "无法打开",
                f"未能用默认程序打开 {rel}：\n{exc}\n\n可改用“导出到本地…”手动保存。",
                parent=self.root,
            )
            return
        self._set_status(f"已打开：{rel}（改动将在锁定或退出时自动回存）")

    def _sync_open_files(self) -> tuple[int, list[str]]:
        """把外部程序修改过的临时文件重新加密回存到保险箱。"""
        if not self.vault.is_unlocked or not self._opened:
            return 0, []
        saved, failed = 0, []
        for fid, record in list(self._opened.items()):
            path = record["path"]
            try:
                stat = path.stat()
            except OSError:
                continue
            if stat.st_size == record["size"] and stat.st_mtime == record["mtime"]:
                continue
            try:
                self.vault.replace_file(fid, path)
                record["size"] = stat.st_size
                record["mtime"] = stat.st_mtime
                saved += 1
            except VaultError as exc:
                failed.append(f"{record['rel']}：{exc}")
        return saved, failed

    def _cleanup_workspace(self) -> None:
        self._opened.clear()
        if self._workspace_dir is not None:
            shutil.rmtree(self._workspace_dir, ignore_errors=True)
            self._workspace_dir = None

    def _on_open_selected(self) -> None:
        fids = self._selected_file_ids()
        if not fids:
            messagebox.showinfo("提示", "请先选择要打开的文件（文件夹无法直接打开）", parent=self.root)
            return
        for fid in fids:
            self._open_file(fid)

    # ================= 删除 / 重命名 / 移动 =================
    def _on_delete(self) -> None:
        fids = self._selected_file_ids()
        folders = self._selected_folder_paths()
        if not fids and not folders:
            messagebox.showinfo("提示", "请先选择要删除的文件或文件夹", parent=self.root)
            return
        labels = [self._tree.item(iid, "text") for iid in self._tree.selection()]
        preview = "\n".join(labels[:8]) + ("\n…" if len(labels) > 8 else "")
        extra = "（文件夹会连同其中所有文件一起删除）" if folders else ""
        if not messagebox.askyesno(
            "确认删除",
            f"将从保险箱中永久删除以下 {len(labels)} 项{extra}，且不可恢复：\n\n{preview}",
            parent=self.root,
        ):
            return

        def work():
            removed = 0
            for rel in folders:
                try:
                    removed += self.vault.remove_folder(rel, secure=True)
                except VaultError:
                    pass
            for fid in fids:
                try:
                    self.vault.remove_file(fid, secure=True)
                    removed += 1
                except VaultError:
                    pass
            return removed

        def done(removed):
            self._refresh()
            self._set_status(f"已删除 {removed} 个文件")

        self._run_async(work, done, "正在删除…")

    def _on_rename(self) -> None:
        fids = self._selected_file_ids()
        folders = self._selected_folder_paths()
        if len(fids) + len(folders) != 1:
            messagebox.showinfo("提示", "请选择单个文件或文件夹后再重命名", parent=self.root)
            return
        if folders:
            rel = folders[0]
            new_name = simpledialog.askstring(
                "重命名文件夹", "新的文件夹名：", initialvalue=name_of(rel), parent=self.root,
            )
            if not new_name:
                return

            def work():
                return self.vault.rename_folder(rel, new_name)

            def done(new_rel):
                self._open_folders.discard(rel)
                self._open_folders.add(new_rel)
                self._refresh()
                self._set_status(f"文件夹已重命名为 {new_rel}")

            self._run_async(work, done, "正在重命名…")
        else:
            fid = fids[0]
            iid = FILE_PREFIX + fid
            new_name = simpledialog.askstring(
                "重命名文件", "新的文件名：", initialvalue=self._tree.item(iid, "text"),
                parent=self.root,
            )
            if not new_name:
                return

            def work():
                return self.vault.rename_file(fid, new_name)

            def done(new_rel):
                self._refresh()
                self._set_status(f"文件已重命名为 {new_rel}")

            self._run_async(work, done, "正在重命名…")

    def _on_move(self) -> None:
        fids = self._selected_file_ids()
        folders = self._selected_folder_paths()
        if not fids and not folders:
            messagebox.showinfo("提示", "请先选择要移动的文件或文件夹", parent=self.root)
            return

        dialog = FolderPickerDialog(self.root, self.vault.list_folders())
        self.root.wait_window(dialog)
        dest = dialog.result
        if dest is None:
            return

        def work():
            moved = self.vault.move_files(fids, dest) if fids else 0
            for rel in folders:
                try:
                    self.vault.move_folder(rel, dest)
                    moved += 1
                except VaultError:
                    pass
            return moved

        def done(moved):
            for rel in folders:
                self._open_folders.discard(rel)
            if dest:
                self._open_folders.add(dest)
            self._refresh()
            self._set_status(f"已移动 {moved} 项到 {dest or '根目录'}")

        self._run_async(work, done, "正在移动…")

    def _on_change_password(self) -> None:
        dialog = PasswordDialog(
            self.root, "修改主密码",
            [("原密码", "old"), ("新密码", "new"), ("确认新密码", "confirm")],
        )
        self.root.wait_window(dialog)
        data = dialog.result
        if not data:
            return
        if data["new"] != data["confirm"]:
            messagebox.showwarning("提示", "两次输入的新密码不一致", parent=self.root)
            return
        if len(data["new"]) < 8:
            messagebox.showwarning("提示", "新密码至少需要 8 个字符", parent=self.root)
            return

        def work():
            return self.vault.change_password(data["old"], data["new"])

        def done(ok):
            if ok:
                self._set_status("主密码已更新")
                messagebox.showinfo("完成", "主密码已更新。", parent=self.root)
            else:
                messagebox.showerror("失败", "原密码不正确。", parent=self.root)

        self._run_async(work, done, "正在更新主密码…")

    def _on_tree_right_click(self, event) -> None:
        row = self._tree.identify_row(event.y)
        if row and row not in self._tree.selection():
            self._tree.selection_set(row)
        if row:
            self._menu.tk_popup(event.x_root, event.y_root)

    # ================= 树构建 / 状态 =================
    def _remember_open(self, opened: bool) -> None:
        iid = self._tree.focus()
        self._remember_explicit(iid, opened)

    def _remember_explicit(self, iid: str, opened: bool) -> None:
        if not iid.startswith(FOLDER_PREFIX):
            return
        rel = iid[len(FOLDER_PREFIX):]
        if opened:
            self._open_folders.add(rel)
        else:
            self._open_folders.discard(rel)

    def _refresh(self) -> None:
        if not self.vault.is_unlocked:
            return
        selection = set(self._tree.selection())
        self._tree.delete(*self._tree.get_children(""))

        files = self.vault.list_files()
        folders = set(self.vault.list_folders())
        for info in files:
            folders |= set(ancestors_of(info["path"]))
        self._open_folders &= folders

        nodes = {"": ""}
        # 先插文件夹（按深度排序，保证父节点先于子节点）
        for rel in sorted(folders, key=lambda r: (r.count("/"), r.lower())):
            parent = nodes.get(parent_of(rel), "")
            iid = FOLDER_PREFIX + rel
            self._tree.insert(
                parent, "end", iid=iid, text=name_of(rel), values=("", ""),
                open=rel in self._open_folders,
            )
            nodes[rel] = iid
        # 再插文件
        for info in sorted(files, key=lambda i: i["path"].lower()):
            parent = nodes.get(parent_of(info["path"]), "")
            self._tree.insert(
                parent, "end", iid=FILE_PREFIX + info["fid"], text=name_of(info["path"]),
                values=(human_size(info["size"]), info["mtime"]),
            )

        for iid in selection:
            if self._tree.exists(iid):
                self._tree.selection_add(iid)
        self._set_status(f"保险箱内共 {len(files)} 个文件 · {len(folders)} 个文件夹")

    def _set_status(self, text: str) -> None:
        self._status_var.set(text)

    # ================= 自动锁定 =================
    def _bind_activity(self) -> None:
        for sequence in ("<Motion>", "<KeyPress>", "<ButtonPress>", "<MouseWheel>"):
            self.root.bind_all(sequence, self._touch, add="+")

    def _touch(self, _event=None) -> None:
        self._last_activity = time.monotonic()

    def _schedule_tick(self) -> None:
        if self._auto_lock_job:
            self.root.after_cancel(self._auto_lock_job)
        self._auto_lock_job = self.root.after(1000, self._tick)

    def _tick(self) -> None:
        self._auto_lock_job = None
        if not self.vault.is_unlocked:
            return
        limit = self.vault.auto_lock_seconds or DEFAULT_AUTO_LOCK
        remaining = max(0, int(limit - (time.monotonic() - self._last_activity)))
        self._lock_var.set(f"自动锁定：{remaining // 60:02d}:{remaining % 60:02d}")
        if remaining <= 0:
            self._on_lock_now()
            return
        self._schedule_tick()

    # ================= 异步任务 =================
    def _run_async(self, work, on_done, status: str) -> None:
        if self._busy:
            return
        self._set_busy(True, status)
        result_queue: queue.Queue = queue.Queue()

        def runner():
            try:
                result_queue.put(("ok", work()))
            except Exception as exc:  # noqa: BLE001 - 统一兜底反馈到界面
                result_queue.put(("err", exc))

        threading.Thread(target=runner, daemon=True).start()

        def poll():
            try:
                kind, payload = result_queue.get_nowait()
            except queue.Empty:
                self.root.after(80, poll)
                return
            if not self._busy:   # 期间已被锁定
                return
            self._set_busy(False, "")
            if kind == "err":
                messagebox.showerror("操作失败", str(payload), parent=self.root)
                self._set_status("操作失败")
            else:
                on_done(payload)

        self.root.after(80, poll)

    def _set_busy(self, busy: bool, status: str) -> None:
        self._busy = busy
        state = "disabled" if busy else "normal"
        for btn in [*getattr(self, "_buttons", []), self._lock_btn]:
            btn.configure(state=state)
        if busy:
            if status:
                self._set_status(status)
            self._progress.pack(side="left", padx=(10, 0))
            self._progress.start(12)
        else:
            self._progress.stop()
            self._progress.pack_forget()

    # ================= 收尾 =================
    def _on_close(self) -> None:
        if self.vault.is_unlocked:
            self._sync_open_files()
            self.vault.lock()
        self._cleanup_workspace()
        self.root.destroy()

    def run(self) -> None:
        self.root.mainloop()


def main() -> None:
    app = VaultApp()
    app.run()


if __name__ == "__main__":
    main()
