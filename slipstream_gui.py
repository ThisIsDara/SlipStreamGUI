import atexit
import ctypes
import json
import os
import queue
import signal
import subprocess
import sys
import threading
import time
from dataclasses import dataclass

import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import webbrowser
import winreg

BINARY_NAME = "slipstream-client-windows-amd64.exe"
LOCK_FILE = "slipstream-gui.lock"

PROCESS_QUERY_INFORMATION = 0x0400
INTERNET_OPTION_SETTINGS_CHANGED = 39
INTERNET_OPTION_REFRESH = 37


@dataclass
class ManagedSession:
    id: int
    proc: subprocess.Popen
    start_time: float
    resolver: str
    resolver_port: str
    tcp_port: str
    args: list[str]

    @property
    def description(self) -> str:
        tcp_info = self.tcp_port or "auto"
        return f"{self.resolver}:{self.resolver_port} (TCP {tcp_info})"


def is_process_running(pid: int) -> bool:
    if pid <= 0:
        return False
    handle = ctypes.windll.kernel32.OpenProcess(PROCESS_QUERY_INFORMATION, 0, pid)
    if not handle:
        return False
    ctypes.windll.kernel32.CloseHandle(handle)
    return True


def acquire_lock(lock_path: str) -> None:
    if os.path.exists(lock_path):
        try:
            with open(lock_path, "r", encoding="utf-8") as f:
                pid_str = f.read().strip()
            pid = int(pid_str) if pid_str else -1
        except Exception:
            pid = -1

        if pid > 0 and is_process_running(pid):
            raise RuntimeError("another instance is already running")
        try:
            os.remove(lock_path)
        except OSError:
            pass

    with open(lock_path, "x", encoding="utf-8") as f:
        f.write(str(os.getpid()))


def release_lock(lock_path: str) -> None:
    try:
        os.remove(lock_path)
    except OSError:
        pass


def find_binary() -> str:
    bundle_dir = getattr(sys, "_MEIPASS", None)
    if bundle_dir:
        candidate = os.path.join(bundle_dir, BINARY_NAME)
        if os.path.exists(candidate):
            return candidate

    exe_dir = os.path.dirname(os.path.abspath(sys.argv[0]))
    candidate = os.path.join(exe_dir, BINARY_NAME)
    if os.path.exists(candidate):
        return candidate
    cwd_candidate = os.path.join(os.getcwd(), BINARY_NAME)
    if os.path.exists(cwd_candidate):
        return cwd_candidate
    return BINARY_NAME


def format_duration(seconds: int) -> str:
    if seconds < 0:
        seconds = 0
    h = seconds // 3600
    m = (seconds % 3600) // 60
    s = seconds % 60
    if h > 0:
        return f"{h}h {m}m {s}s"
    if m > 0:
        return f"{m}m {s}s"
    return f"{s}s"


class SlipstreamGUI:
    def __init__(self) -> None:
        self.root = tk.Tk()
        self.root.title("SlipStream GUI Client")
        self.root.geometry("940x780")
        self.root.minsize(840, 840)
        self.root.resizable(False, False)

        self._set_window_icon()

        self.binary_path = find_binary()
        self.log_queue = queue.Queue()
        self.imported_dns_entries: list[tuple[str, str | None]] = []
        self.dns_listbox: tk.Listbox | None = None
        self.sessions: list[ManagedSession] = []
        self.sessions_listbox: tk.Listbox | None = None
        self.session_counter = 0
        self.stop_event = threading.Event()
        self.proxy_active = False

        self._setup_theme()
        self._build_ui()
        self._setup_timers()

        self.root.protocol("WM_DELETE_WINDOW", self.on_close)

    def _setup_theme(self) -> None:
        style = ttk.Style(self.root)
        style.theme_use("clam")

        bg = "#0b0d12"
        panel = "#121722"
        fg = "#f0f4f8"
        muted = "#9aa7b2"
        accent = "#7cc4ff"
        accent_soft = "#b3ddff"
        danger = "#ff6b6b"

        self.root.configure(bg=bg)
        style.configure("TFrame", background=bg)
        style.configure("Panel.TFrame", background=panel)
        style.configure("TLabel", background=bg, foreground=fg, font=("Segoe UI Variable", 10))
        style.configure("Muted.TLabel", background=bg, foreground=muted, font=("Segoe UI Variable", 9))
        style.configure("Header.TLabel", background=bg, foreground=accent, font=("Segoe UI Variable", 16, "bold"))
        style.configure("TButton", font=("Segoe UI Variable", 10), padding=(12, 7))
        style.configure("Accent.TButton", foreground="#0a0f14", background=accent)
        style.map("Accent.TButton", background=[("active", accent_soft)])
        style.configure("TEntry", fieldbackground=panel, foreground=fg, insertcolor=accent)
        style.configure("TLabelframe", background=bg, foreground=accent)
        style.configure("TLabelframe.Label", background=bg, foreground=accent, font=("Segoe UI Variable", 10, "bold"))
        style.configure("TRadiobutton", background=bg, foreground=fg, font=("Segoe UI Variable", 9))
        style.configure("TCheckbutton", background=bg, foreground=fg, font=("Segoe UI Variable", 9))

        self._theme = {
            "bg": bg,
            "panel": panel,
            "fg": fg,
            "muted": muted,
            "accent": accent,
            "accent_soft": accent_soft,
            "danger": danger,
        }

    def _set_window_icon(self) -> None:
        self._set_appusermodel_id()
        icon_path = None

        bundle_dir = getattr(sys, "_MEIPASS", None)
        if bundle_dir:
            candidate = os.path.join(bundle_dir, "stream.ico")
            if os.path.exists(candidate):
                icon_path = candidate

        if not icon_path:
            candidate = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), "stream.ico")
            if os.path.exists(candidate):
                icon_path = candidate

        if icon_path:
            try:
                self.root.iconbitmap(icon_path)
                self.root.wm_iconbitmap(icon_path)
                self.root.iconbitmap(default=icon_path)
            except Exception:
                pass

    def _set_appusermodel_id(self) -> None:
        try:
            app_id = "ThisIsDara.SlipstreamGUI"
            ctypes.windll.shell32.SetCurrentProcessExplicitAppUserModelID(app_id)
        except Exception:
            pass

    def _build_ui(self) -> None:
        main = ttk.Frame(self.root, padding=8)
        main.pack(fill=tk.BOTH, expand=True)

        header = ttk.Label(main, text="SlipStream GUI Client", style="Header.TLabel")
        header.pack(anchor="w", pady=(0, 10))

        content = ttk.Frame(main)
        content.pack(fill=tk.BOTH, expand=True)
        content.columnconfigure(0, weight=1)
        content.columnconfigure(1, weight=9)

        # Left: Config
        left = ttk.Frame(content, padding=10, style="Panel.TFrame")
        left.grid(row=0, column=0, sticky="nsew", padx=(0, 10))

        form = ttk.Frame(left)
        form.pack(fill=tk.X)

        self.resolver_var = tk.StringVar()
        self.resolver_port_var = tk.StringVar(value="53")
        self.domain_var = tk.StringVar()
        self.tcp_port_var = tk.StringVar(value="5201")
        self.cert_var = tk.StringVar()
        self.cc_var = tk.StringVar(value="dcubic")
        self.keepalive_var = tk.StringVar(value="400")
        self.authoritative_var = tk.BooleanVar(value=False)
        self.gso_var = tk.BooleanVar(value=False)

        self._add_field(form, 0, "Resolver Host *", self.resolver_var, "e.g. 8.8.8.8")
        self._add_field(form, 1, "Resolver Port", self.resolver_port_var, "Default 53")
        self._add_field(form, 2, "Domain *", self.domain_var, "e.g. tunnel.example.com")
        self._add_field(form, 3, "TCP Listen Port", self.tcp_port_var, "Default 5201")
        self._add_field(form, 4, "Certificate", self.cert_var, "Optional")
        cc_row = 5
        ttk.Label(form, text="Congestion Control").grid(row=cc_row, column=0, sticky="w", pady=4, padx=(0, 10))
        cc_box = ttk.Frame(form)
        cc_box.grid(row=cc_row, column=1, sticky="w", pady=4)
        ttk.Radiobutton(cc_box, text="dcubic", variable=self.cc_var, value="dcubic").pack(side=tk.LEFT, padx=(0, 10))
        ttk.Radiobutton(cc_box, text="bbr", variable=self.cc_var, value="bbr").pack(side=tk.LEFT)
        ttk.Label(form, text="Default: dcubic", style="Muted.TLabel").grid(row=cc_row, column=2, sticky="w", padx=(10, 0))

        self._add_field(form, 6, "Keep-Alive (ms)", self.keepalive_var, "Default 400")

        checks = ttk.Frame(form)
        checks.grid(row=7, column=1, sticky="w", pady=(8, 6))
        ttk.Checkbutton(checks, text="Authoritative", variable=self.authoritative_var).pack(anchor="w")
        ttk.Checkbutton(checks, text="UDP GSO", variable=self.gso_var).pack(anchor="w")
        # Proxy controls
        proxy_row = ttk.Frame(left)
        proxy_row.pack(fill=tk.X, pady=(4, 6))
        self.start_proxy_btn = ttk.Button(proxy_row, text="Start Proxy", command=self.on_start_proxy)
        self.stop_proxy_btn = ttk.Button(proxy_row, text="Stop Proxy", command=self.on_stop_proxy)
        self.start_proxy_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.stop_proxy_btn.pack(side=tk.LEFT)
        self.stop_proxy_btn.state(["disabled"])

        self.error_label = ttk.Label(left, text="", foreground=self._theme["danger"], background=self._theme["bg"])
        self.error_label.pack(anchor="w", pady=(8, 4))

        buttons = ttk.Frame(left)
        buttons.pack(fill=tk.X, pady=(10, 6))
        self.connect_btn = ttk.Button(buttons, text="Connect", command=self.on_connect, style="Accent.TButton")
        self.disconnect_btn = ttk.Button(buttons, text="Disconnect", command=self.on_disconnect)
        self.restart_btn = ttk.Button(buttons, text="Restart", command=self.on_restart)
        self.connect_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.disconnect_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.restart_btn.pack(side=tk.LEFT)
        exit_btn = ttk.Button(buttons, text="Exit", command=self.on_close)
        exit_btn.pack(side=tk.RIGHT)
        self.disconnect_btn.state(["disabled"])
        self.restart_btn.state(["disabled"])

        io_bar = ttk.Frame(left)
        io_bar.pack(fill=tk.X, pady=(0, 6))
        ttk.Button(io_bar, text="Import Config", command=self.on_import).pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(io_bar, text="Export Config", command=self.on_export).pack(side=tk.LEFT)

        self._build_dns_list_section(left)

        # Right: Status + Logs
        right = ttk.Frame(content, padding=10, style="Panel.TFrame")
        right.grid(row=0, column=1, sticky="nsew")

        status_box = ttk.LabelFrame(right, text="Connection Status", padding=8)
        status_box.pack(fill=tk.X, pady=(0, 10))
        self.status_var = tk.StringVar(value="Stopped")
        self.protocol_var = tk.StringVar(value="SOCKS")
        self.pid_var = tk.StringVar(value="-")
        self.uptime_var = tk.StringVar(value="0s")
        ttk.Label(status_box, text="Status:").grid(row=0, column=0, sticky="w")
        ttk.Label(status_box, textvariable=self.status_var).grid(row=0, column=1, sticky="w")
        ttk.Label(status_box, text="Protocol:").grid(row=1, column=0, sticky="w")
        ttk.Label(status_box, textvariable=self.protocol_var).grid(row=1, column=1, sticky="w")
        ttk.Label(status_box, text="PID:").grid(row=2, column=0, sticky="w")
        ttk.Label(status_box, textvariable=self.pid_var).grid(row=2, column=1, sticky="w")
        ttk.Label(status_box, text="Uptime:").grid(row=3, column=0, sticky="w")
        ttk.Label(status_box, textvariable=self.uptime_var).grid(row=3, column=1, sticky="w")

        sessions_box = ttk.LabelFrame(right, text="Active Sessions", padding=8)
        sessions_box.pack(fill=tk.BOTH, expand=False, pady=(0, 10))
        self.sessions_listbox = tk.Listbox(
            sessions_box,
            activestyle="none",
            selectmode=tk.SINGLE,
            background=self._theme["panel"],
            foreground=self._theme["fg"],
            highlightthickness=0,
            relief=tk.FLAT,
            height=6,
        )
        self.sessions_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sessions_scroll = ttk.Scrollbar(sessions_box, command=self.sessions_listbox.yview)
        sessions_scroll.pack(side=tk.RIGHT, fill=tk.Y)
        self.sessions_listbox.configure(yscrollcommand=sessions_scroll.set)
        self.sessions_listbox.bind("<<ListboxSelect>>", self._on_session_select)
        ttk.Label(
            sessions_box,
            text="select a session to manage.",
            style="Muted.TLabel",
        ).pack(fill=tk.X, pady=(4, 0))

        logs_box = ttk.LabelFrame(right, text="Live Logs", padding=8)
        logs_box.pack(fill=tk.BOTH, expand=True)

        self.log_text = tk.Text(
            logs_box,
            wrap=tk.WORD,
            state=tk.DISABLED,
            height=16,
            bg=self._theme["panel"],
            fg=self._theme["fg"],
            insertbackground=self._theme["accent"],
            relief=tk.FLAT,
            highlightthickness=0,
        )
        self.log_text.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        scrollbar = ttk.Scrollbar(logs_box, command=self.log_text.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.log_text["yscrollcommand"] = scrollbar.set

        self.log_text.tag_configure("stdout", foreground="#7ed4a7")
        self.log_text.tag_configure("stderr", foreground="#ff8a8a")
        self.log_text.tag_configure("system", foreground="#ffd18c")

        self._refresh_sessions_list()

        footer = tk.Label(
            main,
            text="ThisIsDara",
            fg=self._theme["accent"],
            bg=self._theme["bg"],
            cursor="hand2",
            font=("Segoe UI Variable", 9, "underline"),
        )
        footer.pack(anchor="w", pady=(0, 6))
        footer.bind("<Button-1>", lambda _e: webbrowser.open("https://github.com/ThisIsDara"))

    def _add_field(self, parent, row, label, var, placeholder=None):
        ttk.Label(parent, text=label).grid(row=row, column=0, sticky="w", pady=4, padx=(0, 10))
        entry = ttk.Entry(parent, textvariable=var, width=32)
        entry.grid(row=row, column=1, sticky="we", pady=4)
        if placeholder:
            ttk.Label(parent, text=placeholder, style="Muted.TLabel").grid(row=row, column=2, sticky="w", padx=(10, 0))
        parent.columnconfigure(1, weight=1)

    def _build_dns_list_section(self, parent):
        frame = ttk.LabelFrame(parent, text="Imported DNS", padding=8)
        frame.pack(fill=tk.BOTH, expand=True, pady=(0, 6))

        header_row = ttk.Frame(frame)
        header_row.pack(fill=tk.X)
        ttk.Label(header_row, text="Imported DNS entries", style="Header.TLabel").pack(side=tk.LEFT, anchor="w")
        ttk.Button(header_row, text="Import DNS List", command=self.on_import_dns_list).pack(side=tk.RIGHT)

        ttk.Label(
            frame,
            text="Double-click or select + Use Entry to set resolver fields.",
            style="Muted.TLabel",
        ).pack(fill=tk.X, pady=(4, 6))

        list_frame = ttk.Frame(frame)
        list_frame.pack(fill=tk.BOTH, expand=True)

        self.dns_listbox = tk.Listbox(
            list_frame,
            activestyle="none",
            selectmode=tk.SINGLE,
            background=self._theme["panel"],
            foreground=self._theme["fg"],
            highlightthickness=0,
            relief=tk.FLAT,
            height=8,
        )
        self.dns_listbox.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.dns_listbox.bind("<Double-Button-1>", self._apply_selected_dns)

        scrollbar = ttk.Scrollbar(list_frame, command=self.dns_listbox.yview)
        scrollbar.pack(side=tk.RIGHT, fill=tk.Y)
        self.dns_listbox.configure(yscrollcommand=scrollbar.set)

        actions = ttk.Frame(frame)
        actions.pack(fill=tk.X, pady=(6, 0))
        ttk.Button(actions, text="Use Selected", command=self._apply_selected_dns).pack(side=tk.LEFT)

        self._refresh_dns_list()

    def _refresh_dns_list(self):
        if not self.dns_listbox:
            return
        self.dns_listbox.delete(0, tk.END)
        for resolver, port in self.imported_dns_entries:
            label = f"{resolver}:{port}" if port else resolver
            self.dns_listbox.insert(tk.END, label)

    def _get_selected_session(self) -> ManagedSession | None:
        if not self.sessions_listbox:
            return None
        selection = self.sessions_listbox.curselection()
        if not selection:
            return None
        idx = selection[0]
        if idx >= len(self.sessions):
            return None
        return self.sessions[idx]

    def _on_session_select(self, event=None):
        session = self._get_selected_session()
        if session:
            self.disconnect_btn.state(["!disabled"])
            self.restart_btn.state(["!disabled"])
        else:
            self.disconnect_btn.state(["disabled"])
            self.restart_btn.state(["disabled"])
        self._apply_selected_session_status(session)

    def _refresh_sessions_list(self):
        if not self.sessions_listbox:
            return
        previous = self._get_selected_session()
        self.sessions_listbox.delete(0, tk.END)
        for session in self.sessions:
            tcp_display = session.tcp_port or "auto"
            label = f"{session.resolver}:{session.resolver_port} ({tcp_display})"
            self.sessions_listbox.insert(tk.END, label)
        if previous and previous in self.sessions:
            self.sessions_listbox.select_set(self.sessions.index(previous))
        elif self.sessions:
            self.sessions_listbox.select_set(len(self.sessions) - 1)
        else:
            self.sessions_listbox.selection_clear(0, tk.END)
        self._on_session_select()

    def _prune_finished_sessions(self):
        removed_any = False
        to_remove = []
        for session in self.sessions:
            if session.proc.poll() is not None:
                self.log_queue.put(("system", f"[session {session.description}] Process exited"))
                to_remove.append(session)
        for session in to_remove:
            self.sessions.remove(session)
            removed_any = True
        if removed_any:
            self._refresh_sessions_list()

    def _apply_selected_session_status(self, session: ManagedSession | None):
        if session and session.proc.poll() is None:
            self.pid_var.set(str(session.proc.pid))
            uptime = int(time.time() - session.start_time)
            self.uptime_var.set(format_duration(uptime))
        else:
            self.pid_var.set("-")
            self.uptime_var.set("0s")

    def _is_tcp_port_in_use(self, port: str) -> bool:
        if not port:
            return False
        for session in self.sessions:
            if session.tcp_port == port and session.proc.poll() is None:
                return True
        return False

    def _start_session(self, resolver: str, resolver_port: str, tcp_port: str, args: list[str]) -> ManagedSession | None:
        creationflags = subprocess.CREATE_NEW_PROCESS_GROUP
        try:
            proc = subprocess.Popen(
                [self.binary_path] + args,
                cwd=os.path.dirname(self.binary_path) or None,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                text=True,
                bufsize=1,
                creationflags=creationflags,
            )
        except Exception as e:
            messagebox.showerror("Error", f"Failed to start process: {e}")
            return None

        self.session_counter += 1
        session = ManagedSession(
            id=self.session_counter,
            proc=proc,
            start_time=time.time(),
            resolver=resolver,
            resolver_port=resolver_port,
            tcp_port=tcp_port,
            args=list(args),
        )
        self.sessions.append(session)
        self._start_reader_threads(session)
        self.log_queue.put(("system", f"[session {session.description}] Process started (PID {proc.pid})"))
        self._refresh_sessions_list()
        return session

    def _stop_session(self, session: ManagedSession, reason: str):
        if session.proc.poll() is None:
            try:
                session.proc.send_signal(signal.CTRL_BREAK_EVENT)
            except Exception:
                try:
                    session.proc.terminate()
                except Exception:
                    pass
            time.sleep(0.1)
            if session.proc.poll() is None:
                try:
                    session.proc.kill()
                except Exception:
                    pass

        self.log_queue.put(("system", f"[session {session.description}] {reason}"))
        self._remove_session(session)
        if self.proxy_active and not self.sessions:
            self.apply_system_proxy(False)

    def _remove_session(self, session: ManagedSession):
        if session in self.sessions:
            self.sessions.remove(session)
            self._refresh_sessions_list()

    def _apply_selected_dns(self, event=None):
        if not self.dns_listbox:
            return
        selection = self.dns_listbox.curselection()
        if not selection:
            return
        resolver, port = self.imported_dns_entries[selection[0]]
        if resolver:
            self.resolver_var.set(resolver)
        if port:
            self.resolver_port_var.set(port)

    def _parse_dns_entry(self, raw_line: str) -> tuple[str, str | None] | None:
        line = raw_line.strip()
        if not line:
            return None
        resolver, sep, port = line.rpartition(":")
        if sep and port.isdigit():
            resolver = resolver.strip()
            is_bracketed = resolver.startswith("[") and resolver.endswith("]")
            if is_bracketed:
                resolver = resolver[1:-1].strip()
            if resolver and (is_bracketed or ":" not in resolver):
                port_val = int(port)
                if 1 <= port_val <= 65535:
                    return resolver, str(port_val)
        return line, None

    def on_import_dns_list(self):
        path = filedialog.askopenfilename(
            title="Import DNS List",
            filetypes=[("Text Files", "*.txt")],
        )
        if not path:
            return
        try:
            entries = []
            with open(path, "r", encoding="utf-8") as f:
                for line in f:
                    parsed = self._parse_dns_entry(line)
                    if parsed:
                        entries.append(parsed)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import DNS list: {e}")
            return
        if not entries:
            messagebox.showinfo("Import DNS List", "No valid DNS entries were found in the file.")
            return
        seen = {entry for entry in self.imported_dns_entries}
        added = 0
        for entry in entries:
            if entry not in seen:
                self.imported_dns_entries.append(entry)
                seen.add(entry)
                added += 1
        if added == 0:
            messagebox.showinfo("Import DNS List", "All imported entries already exist.")
        self._refresh_dns_list()

    def _setup_timers(self):
        self.root.after(200, self._poll_logs)
        self.root.after(500, self._update_status)

    def _update_status(self):
        self._prune_finished_sessions()
        total = len(self.sessions)
        running = sum(1 for session in self.sessions if session.proc.poll() is None)
        if total == 0:
            self.status_var.set("Stopped")
        else:
            self.status_var.set(f"Running ({running}/{total})")
        self._apply_selected_session_status(self._get_selected_session())
        self.root.after(500, self._update_status)

    def _poll_logs(self):
        try:
            while True:
                stream, line = self.log_queue.get_nowait()
                self._append_log(line, stream)
        except queue.Empty:
            pass
        self.root.after(150, self._poll_logs)

    def _append_log(self, line: str, stream: str):
        self.log_text.configure(state=tk.NORMAL)
        self.log_text.insert(tk.END, line + "\n", stream)
        self.log_text.see(tk.END)
        self.log_text.configure(state=tk.DISABLED)

    def validate(self) -> bool:
        self.error_label.config(text="")
        resolver = self.resolver_var.get().strip()
        resolver_port = self.resolver_port_var.get().strip()
        domain = self.domain_var.get().strip()
        if not resolver:
            self.error_label.config(text="Resolver is required")
            return False
        if resolver_port:
            try:
                port = int(resolver_port)
                if port < 1 or port > 65535:
                    raise ValueError()
            except ValueError:
                self.error_label.config(text="Resolver Port must be 1-65535")
                return False
        if not domain:
            self.error_label.config(text="Domain is required")
            return False

        if self.tcp_port_var.get().strip():
            try:
                port = int(self.tcp_port_var.get().strip())
                if port < 1 or port > 65535:
                    raise ValueError()
            except ValueError:
                self.error_label.config(text="TCP Listen Port must be 1-65535")
                return False

        if self.keepalive_var.get().strip():
            try:
                val = int(self.keepalive_var.get().strip())
                if val < 0:
                    raise ValueError()
            except ValueError:
                self.error_label.config(text="Keep-Alive must be >= 0")
                return False

        cc = self.cc_var.get().strip()
        if cc and cc not in ("bbr", "dcubic"):
            self.error_label.config(text="Congestion Control must be bbr or dcubic")
            return False
        return True

    def build_args(self):
        resolver_host = self.resolver_var.get().strip()
        resolver_port = self.resolver_port_var.get().strip() or "53"
        args = ["-r", f"{resolver_host}:{resolver_port}", "-d", self.domain_var.get().strip()]

        if self.tcp_port_var.get().strip():
            args += ["-l", self.tcp_port_var.get().strip()]
        if self.cert_var.get().strip():
            args += ["--cert", self.cert_var.get().strip()]
        if self.cc_var.get().strip():
            args += ["-c", self.cc_var.get().strip()]
        if self.keepalive_var.get().strip():
            args += ["-t", self.keepalive_var.get().strip()]
        if self.authoritative_var.get():
            args += ["--authoritative", "true"]
        if self.gso_var.get():
            args.append("--gso")

        return args

    def on_connect(self):
        if not self.validate():
            return

        if not os.path.exists(self.binary_path):
            messagebox.showerror("Error", f"Binary not found: {self.binary_path}")
            return

        args = self.build_args()
        resolver = self.resolver_var.get().strip()
        resolver_port = self.resolver_port_var.get().strip() or "53"
        tcp_port = self.tcp_port_var.get().strip()
        if self.proxy_active:
            self.apply_system_proxy(True)
        if self._is_tcp_port_in_use(tcp_port):
            messagebox.showerror("TCP Port In Use", f"TCP listen port {tcp_port} is already in use by another session.")
            return
        self._start_session(resolver, resolver_port, tcp_port, args)

    def on_disconnect(self, *, suppress_warning: bool = False):
        session = self._get_selected_session()
        if not session:
            if not suppress_warning:
                messagebox.showinfo("No session selected", "Select a session to disconnect.")
            return
        self._stop_session(session, "Disconnect requested")

    def on_restart(self):
        session = self._get_selected_session()
        if not session:
            messagebox.showinfo("No session selected", "Select a session to restart.")
            return
        args = list(session.args)
        resolver = session.resolver
        resolver_port = session.resolver_port
        tcp_port = session.tcp_port
        self._stop_session(session, "Restart requested")
        time.sleep(0.2)
        if self.proxy_active:
            self.apply_system_proxy(True)
        self._start_session(resolver, resolver_port, tcp_port, args)

    def on_import(self):
        path = filedialog.askopenfilename(
            title="Import Configuration",
            filetypes=[("JSON Files", "*.json")],
        )
        if not path:
            return
        try:
            with open(path, "r", encoding="utf-8") as f:
                data = json.load(f)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to import config: {e}")
            return

        self.resolver_var.set(data.get("resolver", ""))
        self.domain_var.set(data.get("domain", ""))
        self.tcp_port_var.set(str(data.get("tcp_listen_port", "5201")))
        self.cert_var.set(data.get("cert", ""))
        self.cc_var.set(data.get("congestion_control", "dcubic"))
        self.keepalive_var.set(str(data.get("keep_alive_interval", "400")))
        self.authoritative_var.set(bool(data.get("authoritative", False)))
        self.gso_var.set(bool(data.get("gso", False)))

    def on_export(self):
        path = filedialog.asksaveasfilename(
            title="Export Configuration",
            defaultextension=".json",
            filetypes=[("JSON Files", "*.json")],
        )
        if not path:
            return

        data = {
            "resolver": self.resolver_var.get().strip(),
            "domain": self.domain_var.get().strip(),
            "tcp_listen_port": self.tcp_port_var.get().strip(),
            "cert": self.cert_var.get().strip(),
            "congestion_control": self.cc_var.get().strip(),
            "keep_alive_interval": self.keepalive_var.get().strip(),
            "authoritative": bool(self.authoritative_var.get()),
            "gso": bool(self.gso_var.get()),
        }
        try:
            with open(path, "w", encoding="utf-8") as f:
                json.dump(data, f, indent=2)
        except Exception as e:
            messagebox.showerror("Error", f"Failed to export config: {e}")

    def _start_reader_threads(self, session: ManagedSession):
        prefix = f"[{session.description}] "

        def reader(stream, tag):
            try:
                for line in iter(stream.readline, ""):
                    if self.stop_event.is_set():
                        break
                    if line:
                        self.log_queue.put((tag, prefix + line.rstrip("\n")))
            finally:
                try:
                    stream.close()
                except Exception:
                    pass

        if session.proc.stdout:
            threading.Thread(target=reader, args=(session.proc.stdout, "stdout"), daemon=True).start()
        if session.proc.stderr:
            threading.Thread(target=reader, args=(session.proc.stderr, "stderr"), daemon=True).start()

    def on_close(self):
        self.stop_event.set()
        self._stop_all_sessions()
        self.root.destroy()

    def _stop_all_sessions(self):
        while self.sessions:
            session = self.sessions[0]
            self._stop_session(session, "Shutdown requested")

    def on_start_proxy(self):
        try:
            self.apply_system_proxy(True)
            self.start_proxy_btn.state(["disabled"])
            self.stop_proxy_btn.state(["!disabled"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to enable system proxy: {e}")

    def on_stop_proxy(self):
        try:
            self.apply_system_proxy(False)
            self.start_proxy_btn.state(["!disabled"])
            self.stop_proxy_btn.state(["disabled"])
        except Exception as e:
            messagebox.showerror("Error", f"Failed to disable system proxy: {e}")

    def apply_system_proxy(self, enable: bool):
        port_text = self.tcp_port_var.get().strip()
        if not port_text:
            raise RuntimeError("TCP Listen Port is required for system proxy")
        try:
            port = int(port_text)
        except ValueError:
            raise RuntimeError("TCP Listen Port must be a number")
        if port < 1 or port > 65535:
            raise RuntimeError("TCP Listen Port must be 1-65535")

        key_path = r"Software\Microsoft\Windows\CurrentVersion\Internet Settings"
        with winreg.OpenKey(winreg.HKEY_CURRENT_USER, key_path, 0, winreg.KEY_SET_VALUE) as key:
            if enable:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 1)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, f"socks=127.0.0.1:{port}")
                winreg.SetValueEx(key, "ProxyOverride", 0, winreg.REG_SZ, "<local>")
                self.proxy_active = True
                self.log_queue.put(("system", f"[system] System proxy enabled (SOCKS 127.0.0.1:{port})"))
            else:
                winreg.SetValueEx(key, "ProxyEnable", 0, winreg.REG_DWORD, 0)
                winreg.SetValueEx(key, "ProxyServer", 0, winreg.REG_SZ, "")
                self.proxy_active = False
                self.log_queue.put(("system", "[system] System proxy disabled"))

        if not enable:
            self.start_proxy_btn.state(["!disabled"])
            self.stop_proxy_btn.state(["disabled"])

        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_SETTINGS_CHANGED, 0, 0)
        ctypes.windll.wininet.InternetSetOptionW(0, INTERNET_OPTION_REFRESH, 0, 0)


if __name__ == "__main__":
    lock_path = os.path.join(os.path.dirname(os.path.abspath(sys.argv[0])), LOCK_FILE)
    try:
        acquire_lock(lock_path)
    except Exception as e:
        force = messagebox.askyesno(
            "Another instance detected",
            f"{e}\n\nForce unlock and continue?",
        )
        if force:
            try:
                release_lock(lock_path)
                acquire_lock(lock_path)
            except Exception as e2:
                messagebox.showerror("Error", str(e2))
                sys.exit(1)
        else:
            sys.exit(1)

    atexit.register(release_lock, lock_path)

    gui = SlipstreamGUI()
    gui.root.mainloop()
