#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
N64 未使用メモリ検索ツール  v1.0

実行中の N64 エミュレータ (Project64 / mupen64plus 系 / RetroArch / ares など) の
プロセスにアタッチして RDRAM を繰り返し読み取り、「開始」から「停止」までの間に
一度も 0 以外の値にならなかったバイト範囲を列挙します。

  - 最小連続長 (バイト) 以上の 0 連続だけを結果にできます
  - 4 バイト境界に揃えるオプション、検索範囲の指定ができます
  - 結果はテキストファイルに保存でき、そのファイルを読み込めば続きから再開できます

必要なもの: Windows + Python 3.8 以降 (標準ライブラリのみ。tkinter 同梱版)
起動: python n64_unused_scan.py

注意:
  * サンプリングの合間に一瞬だけ 0 以外になって戻る値は検出できません。
    サンプル間隔は 0 (最速) を推奨します。
  * 再開用ファイルには「表示中の結果」だけが入ります。読み込むとそれ以外は
    すべて使用中扱いになるため、再開後に最小連続長を小さくしたり
    検索範囲を広げたりしても、失われた部分は戻りません。
"""

import sys
import re
import time
import threading
import ctypes
from array import array
from datetime import datetime

APP_TITLE = "N64 未使用メモリ検索"
FILE_MAGIC = "# N64UnusedScan v1"
KSEG0 = 0x80000000
SIZE_4MB = 0x400000
SIZE_8MB = 0x800000
MAX_TREE_ROWS = 3000
EMU_KEYWORDS = ("project64", "pj64", "ares", "mupen", "retroarch", "simple64",
                "rmg", "m64p", "1964", "gopher", "cen64", "parallel", "bizhawk",
                "emuhawk", "n64")

_U32 = "I" if array("I").itemsize == 4 else "L"


# ======================================================================
#  純粋な処理 (OS 非依存)
# ======================================================================
def swap32(b):
    """32bit 語ごとにバイト順を反転 (LE32 格納 <-> N64 順)。"""
    a = array(_U32)
    a.frombytes(b)
    a.byteswap()
    return a.tobytes()


def to_offset(addr):
    """KSEG0(8xxxxxxx)/KSEG1(Axxxxxxx)/物理アドレスを RDRAM オフセットへ。"""
    return addr & 0x1FFFFFFF


def fmt_addr(off):
    return f"{KSEG0 + off:08X}"


def parse_hex(text):
    t = text.strip().replace("_", "").replace(" ", "")
    if t.lower().startswith("0x"):
        t = t[2:]
    return int(t, 16)


def find_zero_runs(mask, min_len, align4, lo, hi):
    """N64 順のマスク(0=常に0だった)から 0 の連続範囲 [(start,end_exclusive)] を返す。"""
    min_len = max(1, int(min_len))
    lo = max(0, lo)
    hi = min(len(mask), hi)
    if hi <= lo:
        return []
    pat = re.compile(rb"\x00{%d,}" % min_len)
    out = []
    for m in pat.finditer(mask, lo, hi):
        s, e = m.start(), m.end()
        if align4:
            s = (s + 3) & ~3
            e &= ~3
        if e > s and e - s >= min_len:
            out.append((s, e))
    return out


def save_result(path, meta, ranges):
    lines = [FILE_MAGIC]
    for k, v in meta.items():
        lines.append(f"# {k}={v}")
    lines.append("# 書式: 開始-終了(終了アドレスを含む)  サイズ(16進)  (サイズ10進)")
    for s, e in ranges:
        lines.append(f"{fmt_addr(s)}-{fmt_addr(e - 1)}  0x{e - s:06X}  ({e - s})")
    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines) + "\n")


_META_RE = re.compile(r"^#\s*([A-Za-z_0-9]+)\s*=\s*(.*?)\s*$")
_RANGE_RE = re.compile(r"^\s*(?:0x)?([0-9A-Fa-f]{1,8})\s*-\s*(?:0x)?([0-9A-Fa-f]{1,8})")


def load_result(path):
    meta, ranges = {}, []
    with open(path, encoding="utf-8-sig") as f:
        for line in f:
            m = _META_RE.match(line)
            if m:
                meta[m.group(1)] = m.group(2)
                continue
            if line.lstrip().startswith("#"):
                continue
            m = _RANGE_RE.match(line)
            if m:
                s = to_offset(int(m.group(1), 16))
                e = to_offset(int(m.group(2), 16)) + 1
                if e > s:
                    ranges.append((s, e))
    return meta, ranges


def mask_from_ranges(size, ranges):
    """ファイルの範囲だけ 0、それ以外は使用中(0xFF)のマスクを作る。"""
    m = bytearray(b"\xff") * size
    for s, e in ranges:
        s, e = max(0, s), min(size, e)
        if e > s:
            m[s:e] = bytes(e - s)
    return bytes(m)


# ======================================================================
#  Win32 (プロセスメモリ読み取り)
# ======================================================================
PROCESS_VM_READ = 0x0010
PROCESS_QUERY_INFORMATION = 0x0400
MEM_COMMIT = 0x1000
PAGE_GUARD = 0x100
READABLE_PROTECT = {0x02, 0x04, 0x08, 0x20, 0x40, 0x80}
TH32CS_SNAPPROCESS = 0x2

DWORD = ctypes.c_ulong if sys.platform == "win32" else ctypes.c_uint32


class MBI(ctypes.Structure):
    _fields_ = [("BaseAddress", ctypes.c_void_p),
                ("AllocationBase", ctypes.c_void_p),
                ("AllocationProtect", DWORD),
                ("RegionSize", ctypes.c_size_t),
                ("State", DWORD),
                ("Protect", DWORD),
                ("Type", DWORD)]


class PROCESSENTRY32W(ctypes.Structure):
    _fields_ = [("dwSize", DWORD),
                ("cntUsage", DWORD),
                ("th32ProcessID", DWORD),
                ("th32DefaultHeapID", ctypes.c_size_t),
                ("th32ModuleID", DWORD),
                ("cntThreads", DWORD),
                ("th32ParentProcessID", DWORD),
                ("pcPriClassBase", ctypes.c_long),
                ("dwFlags", DWORD),
                ("szExeFile", ctypes.c_wchar * 260)]


k32 = None


def init_win32():
    global k32
    k32 = ctypes.WinDLL("kernel32", use_last_error=True)
    H = ctypes.c_void_p
    k32.OpenProcess.argtypes = [DWORD, ctypes.c_int, DWORD]
    k32.OpenProcess.restype = H
    k32.CloseHandle.argtypes = [H]
    k32.CloseHandle.restype = ctypes.c_int
    k32.ReadProcessMemory.argtypes = [H, ctypes.c_void_p, ctypes.c_void_p,
                                      ctypes.c_size_t, ctypes.POINTER(ctypes.c_size_t)]
    k32.ReadProcessMemory.restype = ctypes.c_int
    k32.VirtualQueryEx.argtypes = [H, ctypes.c_void_p, ctypes.POINTER(MBI), ctypes.c_size_t]
    k32.VirtualQueryEx.restype = ctypes.c_size_t
    k32.CreateToolhelp32Snapshot.argtypes = [DWORD, DWORD]
    k32.CreateToolhelp32Snapshot.restype = H
    k32.Process32FirstW.argtypes = [H, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32FirstW.restype = ctypes.c_int
    k32.Process32NextW.argtypes = [H, ctypes.POINTER(PROCESSENTRY32W)]
    k32.Process32NextW.restype = ctypes.c_int
    try:
        ctypes.windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass


def list_processes():
    snap = k32.CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0)
    if not snap or snap == ctypes.c_void_p(-1).value:
        return []
    out = []
    pe = PROCESSENTRY32W()
    pe.dwSize = ctypes.sizeof(pe)
    ok = k32.Process32FirstW(snap, ctypes.byref(pe))
    while ok:
        out.append((pe.th32ProcessID, pe.szExeFile))
        ok = k32.Process32NextW(snap, ctypes.byref(pe))
    k32.CloseHandle(snap)

    def key(p):
        n = p[1].lower()
        return (0 if any(k in n for k in EMU_KEYWORDS) else 1, n, p[0])
    return sorted(out, key=key)


class Proc:
    def __init__(self, pid, name):
        self.pid, self.name = pid, name
        self.h = k32.OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, 0, pid)
        if not self.h:
            raise OSError(f"プロセスを開けません (エラー {ctypes.get_last_error()})。"
                          "管理者として実行すると改善する場合があります。")

    def close(self):
        if self.h:
            k32.CloseHandle(self.h)
            self.h = None

    def read_into(self, addr, buf, size):
        n = ctypes.c_size_t(0)
        ok = k32.ReadProcessMemory(self.h, ctypes.c_void_p(addr), buf, size, ctypes.byref(n))
        return bool(ok) and n.value == size

    def read_bytes(self, addr, size):
        buf = ctypes.create_string_buffer(size)
        return buf.raw if self.read_into(addr, buf, size) else None

    def read_robust(self, addr, size, buf):
        """一括で読めなければ 64KB 単位で読む。読めない部分は 0 で埋める。全滅なら None。"""
        if self.read_into(addr, buf, size):
            return buf.raw
        out = bytearray(size)
        piece, got = 0x10000, False
        for off in range(0, size, piece):
            n = min(piece, size - off)
            b = self.read_bytes(addr + off, n)
            if b is not None:
                out[off:off + n] = b
                got = True
        return bytes(out) if got else None

    def readable_spans(self, min_size):
        """コミット済みかつ読み取り可能な連続領域 [(start,end)] (隣接領域は結合)。"""
        mbi = MBI()
        addr, spans, cur = 0, [], None
        limit = (1 << 47) if ctypes.sizeof(ctypes.c_void_p) == 8 else (1 << 32)
        while addr < limit:
            if not k32.VirtualQueryEx(self.h, ctypes.c_void_p(addr), ctypes.byref(mbi),
                                      ctypes.sizeof(mbi)):
                break
            base = mbi.BaseAddress or 0
            size = mbi.RegionSize
            if size == 0:
                break
            ok = (mbi.State == MEM_COMMIT and (mbi.Protect & 0xFF) in READABLE_PROTECT
                  and not (mbi.Protect & PAGE_GUARD))
            if ok:
                if cur and cur[1] == base:
                    cur[1] = base + size
                else:
                    if cur:
                        spans.append(tuple(cur))
                    cur = [base, base + size]
            elif cur:
                spans.append(tuple(cur))
                cur = None
            addr = base + size
        if cur:
            spans.append(tuple(cur))
        return [s for s in spans if s[1] - s[0] >= min_size]


# libultra の例外ベクタ (0x80000000/80/100/180 に置かれる)
#   lui k0,0x80xx / addiu k0,k0,xxxx / jr k0 / nop
SIG_LE = re.compile(rb".\x80\x1a\x3c..\x5a\x27\x08\x00\x40\x03", re.S)
SIG_BE = re.compile(rb"\x3c\x1a\x80.\x27\x5a..\x03\x40\x00\x08", re.S)


def detect_rdram(proc, progress=None):
    """RDRAM 先頭の候補 [(host_addr, swap, osMemSize)] を返す。"""
    spans = proc.readable_spans(SIZE_4MB)
    total = sum(e - s for s, e in spans) or 1
    done = 0
    CH, OV = 0x1000000, 0x200
    cands = []
    for sb, se in spans:
        pos = sb
        while pos < se:
            n = min(CH + OV, se - pos)
            data = proc.read_bytes(pos, n)
            if data is not None:
                for swap, pat in ((True, SIG_LE), (False, SIG_BE)):
                    for m in pat.finditer(data):
                        i = m.start()
                        if i >= CH:
                            break
                        addr = pos + i
                        if addr & 3 or se - addr < SIZE_4MB:
                            continue
                        if not pat.match(data, i + 0x180):
                            continue
                        ms = proc.read_bytes(addr + 0x318, 4)
                        msz = int.from_bytes(ms, "little" if swap else "big") if ms else 0
                        if msz == SIZE_8MB and se - addr < SIZE_8MB:
                            msz = SIZE_4MB
                        cands.append((addr, swap, msz))
            done += min(CH, se - pos)
            pos += CH
            if progress:
                progress(done / total)
    cands = list(dict.fromkeys(cands))
    cands.sort(key=lambda c: 0 if c[2] in (SIZE_4MB, SIZE_8MB) else 1)
    return cands


# ======================================================================
#  スキャナ本体
# ======================================================================
class Scanner:
    """accum: ホスト側バイト順のまま全サンプルを OR した巨大整数 (0 のビット=常に0)。"""

    def __init__(self):
        self.lock = threading.Lock()
        self.proc = None
        self.base = None
        self.size = SIZE_8MB
        self.swap = True
        self.accum = 0
        self.samples = 0
        self.elapsed = 0.0
        self.has_data = False
        self.interval = 0.0
        self.error = None
        self.thread = None
        self.stop_ev = threading.Event()
        self._t0 = None

    @property
    def configured(self):
        return self.proc is not None and self.base is not None

    @property
    def running(self):
        return self.thread is not None and self.thread.is_alive()

    def elapsed_now(self):
        with self.lock:
            return self.elapsed + ((time.perf_counter() - self._t0) if self._t0 else 0.0)

    def get_n64_mask(self):
        with self.lock:
            a = self.accum
        b = a.to_bytes(self.size, "little")
        return swap32(b) if self.swap else b

    def _set_n64_mask(self, mask):
        b = swap32(mask) if self.swap else mask
        with self.lock:
            self.accum = int.from_bytes(b, "little")

    def reconfigure(self, proc, base, size, swap):
        if self.has_data and size != self.size:
            raise ValueError("検索データのRDRAMサイズと違います。リセットしてから変更してください。")
        mask = self.get_n64_mask() if self.has_data else None
        self.proc, self.base, self.size, self.swap = proc, base, size, swap
        if mask is not None:
            self._set_n64_mask(mask)

    def load(self, size, mask, samples, elapsed):
        self.size = size
        self._set_n64_mask(mask)
        with self.lock:
            self.samples, self.elapsed, self.has_data = samples, elapsed, True

    def reset(self):
        with self.lock:
            self.accum, self.samples, self.elapsed, self.has_data = 0, 0, 0.0, False
        self.error = None

    def start(self, interval):
        if self.running or not self.configured:
            return
        self.interval = interval
        self.error = None
        self.stop_ev.clear()
        self.thread = threading.Thread(target=self._run, daemon=True)
        self.thread.start()

    def stop(self):
        self.stop_ev.set()
        if self.thread:
            self.thread.join(timeout=3)
        self.thread = None

    def _run(self):
        size = self.size
        buf = ctypes.create_string_buffer(size)
        with self.lock:
            self._t0 = time.perf_counter()
        try:
            while not self.stop_ev.is_set():
                data = self.proc.read_robust(self.base, size, buf)
                if data is None:
                    self.error = "RDRAM を読み取れません。エミュレータが終了したか、アドレスが変わった可能性があります。"
                    break
                v = int.from_bytes(data, "little")
                with self.lock:
                    self.accum |= v
                    self.samples += 1
                    self.has_data = True
                if self.interval > 0:
                    self.stop_ev.wait(self.interval)
        finally:
            with self.lock:
                self.elapsed += time.perf_counter() - self._t0
                self._t0 = None


# ======================================================================
#  GUI
# ======================================================================
def run_gui():
    import tkinter as tk
    from tkinter import ttk, filedialog, messagebox

    ORDERS = ["LE32 (Project64/mupen系)", "BE (そのまま)"]
    SIZES = ["4MB", "8MB"]

    class App:
        def __init__(self, root):
            self.root = root
            root.title(APP_TITLE)
            root.geometry("820x720")
            root.minsize(700, 560)
            self.sc = Scanner()
            self.proc = None
            self.procs = []
            self.cands = []
            self.detect_thread = None
            self.detect_result = None
            self.detect_progress = 0.0
            self.last_ranges = []
            self.last_tree_key = None
            self.last_refresh = 0.0
            self.error_shown = None
            self.prev_samples = (0, time.perf_counter())
            self.rate = 0.0

            self.v_proc = tk.StringVar()
            self.v_cand = tk.StringVar()
            self.v_base = tk.StringVar()
            self.v_order = tk.StringVar(value=ORDERS[0])
            self.v_size = tk.StringVar(value=SIZES[1])
            self.v_minlen = tk.StringVar(value="16")
            self.v_align = tk.BooleanVar(value=False)
            self.v_lo = tk.StringVar(value="80000000")
            self.v_hi = tk.StringVar(value="80800000")
            self.v_interval = tk.StringVar(value="0")
            self.v_status = tk.StringVar(value="エミュレータを選んで「アタッチ」してください。")
            self.v_stats = tk.StringVar(value="")
            self.v_summary = tk.StringVar(value="")

            self.build()
            self.refresh_procs()
            root.protocol("WM_DELETE_WINDOW", self.on_close)
            root.after(300, self.tick)

        # ---------- UI ----------
        def build(self):
            r = self.root
            pad = dict(padx=4, pady=3)

            f1 = ttk.LabelFrame(r, text="エミュレータ")
            f1.pack(fill="x", padx=8, pady=4)
            self.cb_proc = ttk.Combobox(f1, textvariable=self.v_proc, state="readonly", width=48)
            self.cb_proc.grid(row=0, column=0, sticky="we", **pad)
            ttk.Button(f1, text="一覧更新", command=self.refresh_procs).grid(row=0, column=1, **pad)
            self.btn_attach = ttk.Button(f1, text="アタッチ", command=self.on_attach)
            self.btn_attach.grid(row=0, column=2, **pad)
            f1.columnconfigure(0, weight=1)

            f2 = ttk.LabelFrame(r, text="RDRAM (自動検出 / 手動指定)")
            f2.pack(fill="x", padx=8, pady=4)
            ttk.Label(f2, text="候補").grid(row=0, column=0, sticky="e", **pad)
            self.cb_cand = ttk.Combobox(f2, textvariable=self.v_cand, state="readonly", width=60)
            self.cb_cand.grid(row=0, column=1, columnspan=5, sticky="we", **pad)
            self.cb_cand.bind("<<ComboboxSelected>>", lambda e: self.apply_cand())
            ttk.Label(f2, text="ホスト先頭アドレス").grid(row=1, column=0, sticky="e", **pad)
            ttk.Entry(f2, textvariable=self.v_base, width=20).grid(row=1, column=1, sticky="w", **pad)
            ttk.Label(f2, text="格納順").grid(row=1, column=2, sticky="e", **pad)
            ttk.Combobox(f2, textvariable=self.v_order, values=ORDERS, state="readonly",
                         width=22).grid(row=1, column=3, **pad)
            ttk.Label(f2, text="サイズ").grid(row=1, column=4, sticky="e", **pad)
            ttk.Combobox(f2, textvariable=self.v_size, values=SIZES, state="readonly",
                         width=6).grid(row=1, column=5, **pad)
            ttk.Button(f2, text="適用", command=self.apply_config).grid(row=1, column=6, **pad)
            f2.columnconfigure(1, weight=1)

            f3 = ttk.LabelFrame(r, text="検索設定")
            f3.pack(fill="x", padx=8, pady=4)
            ttk.Label(f3, text="最小連続長(バイト)").grid(row=0, column=0, sticky="e", **pad)
            ttk.Spinbox(f3, textvariable=self.v_minlen, from_=1, to=SIZE_8MB,
                        width=10).grid(row=0, column=1, sticky="w", **pad)
            ttk.Checkbutton(f3, text="4バイト境界に揃える", variable=self.v_align
                            ).grid(row=0, column=2, sticky="w", **pad)
            ttk.Label(f3, text="サンプル間隔(ms, 0=最速)").grid(row=0, column=3, sticky="e", **pad)
            ttk.Spinbox(f3, textvariable=self.v_interval, from_=0, to=10000,
                        width=8).grid(row=0, column=4, sticky="w", **pad)
            ttk.Label(f3, text="範囲 開始").grid(row=1, column=0, sticky="e", **pad)
            ttk.Entry(f3, textvariable=self.v_lo, width=12).grid(row=1, column=1, sticky="w", **pad)
            ttk.Label(f3, text="終了(この直前まで)").grid(row=1, column=2, sticky="e", **pad)
            ttk.Entry(f3, textvariable=self.v_hi, width=12).grid(row=1, column=3, sticky="w", **pad)

            f4 = ttk.Frame(r)
            f4.pack(fill="x", padx=8, pady=4)
            self.btn_start = ttk.Button(f4, text="▶ 開始", command=self.on_start)
            self.btn_start.pack(side="left", padx=3)
            self.btn_stop = ttk.Button(f4, text="■ 停止", command=self.on_stop)
            self.btn_stop.pack(side="left", padx=3)
            ttk.Button(f4, text="リセット", command=self.on_reset).pack(side="left", padx=3)
            ttk.Separator(f4, orient="vertical").pack(side="left", fill="y", padx=6)
            ttk.Button(f4, text="保存…", command=self.on_save).pack(side="left", padx=3)
            ttk.Button(f4, text="読込(再開)…", command=self.on_load).pack(side="left", padx=3)
            ttk.Separator(f4, orient="vertical").pack(side="left", fill="y", padx=6)
            ttk.Button(f4, text="結果を再計算", command=lambda: self.refresh_list(True)
                       ).pack(side="left", padx=3)
            ttk.Button(f4, text="一覧をコピー", command=self.copy_all).pack(side="left", padx=3)

            ttk.Label(r, textvariable=self.v_stats).pack(fill="x", padx=12)
            ttk.Label(r, textvariable=self.v_summary, font=("", 10, "bold")).pack(fill="x", padx=12)

            f5 = ttk.Frame(r)
            f5.pack(fill="both", expand=True, padx=8, pady=4)
            cols = ("start", "end", "size", "dec")
            self.tree = ttk.Treeview(f5, columns=cols, show="headings")
            for c, t, w in zip(cols, ("開始", "終了(含む)", "サイズ(16進)", "サイズ(10進)"),
                               (140, 140, 140, 140)):
                self.tree.heading(c, text=t)
                self.tree.column(c, width=w, anchor="center")
            sb = ttk.Scrollbar(f5, orient="vertical", command=self.tree.yview)
            self.tree.configure(yscrollcommand=sb.set)
            self.tree.pack(side="left", fill="both", expand=True)
            sb.pack(side="right", fill="y")
            self.tree.bind("<Double-1>", self.copy_row)

            ttk.Label(r, textvariable=self.v_status, relief="sunken", anchor="w"
                      ).pack(fill="x", side="bottom")

        # ---------- エミュ / RDRAM ----------
        def refresh_procs(self):
            self.procs = list_processes()
            self.cb_proc["values"] = [f"{n}  (PID {p})" for p, n in self.procs]
            if self.procs and not self.v_proc.get():
                self.cb_proc.current(0)

        def on_attach(self):
            i = self.cb_proc.current()
            if i < 0:
                messagebox.showwarning(APP_TITLE, "プロセスを選んでください。")
                return
            if self.sc.running:
                self.on_stop()
            pid, name = self.procs[i]
            try:
                proc = Proc(pid, name)
            except OSError as e:
                messagebox.showerror(APP_TITLE, str(e))
                return
            if self.proc:
                self.proc.close()
            self.proc = proc
            self.btn_attach.state(["disabled"])
            self.v_status.set(f"{name} の RDRAM を探しています…")
            self.detect_result = None
            self.detect_progress = 0.0

            def work():
                try:
                    res = detect_rdram(proc, lambda p: setattr(self, "detect_progress", p))
                except Exception as e:  # noqa
                    res = e
                self.detect_result = res
            self.detect_thread = threading.Thread(target=work, daemon=True)
            self.detect_thread.start()
            self.root.after(150, self.poll_detect)

        def poll_detect(self):
            if self.detect_thread and self.detect_thread.is_alive():
                self.v_status.set(f"{self.proc.name} の RDRAM を探しています… "
                                  f"{self.detect_progress * 100:.0f}%")
                self.root.after(150, self.poll_detect)
                return
            self.btn_attach.state(["!disabled"])
            res = self.detect_result
            if isinstance(res, Exception):
                messagebox.showerror(APP_TITLE, f"検出中にエラー: {res}")
                return
            self.cands = res or []
            self.cb_cand["values"] = [
                f"{a:X}  {'LE32' if s else 'BE'}  osMemSize="
                + (f"{m // 0x100000}MB" if m in (SIZE_4MB, SIZE_8MB) else f"0x{m:X}?")
                for a, s, m in self.cands]
            if not self.cands:
                self.v_cand.set("")
                self.v_status.set("自動検出できませんでした。ゲームを起動してから再度アタッチするか、手動で指定してください。")
                messagebox.showinfo(APP_TITLE, "RDRAM を自動検出できませんでした。\n"
                                    "ゲーム起動後に再アタッチするか、ホスト先頭アドレスを手動入力して「適用」してください。")
                return
            self.cb_cand.current(0)
            self.apply_cand()

        def apply_cand(self):
            i = self.cb_cand.current()
            if i < 0:
                return
            a, s, m = self.cands[i]
            self.v_base.set(f"{a:X}")
            self.v_order.set(ORDERS[0] if s else ORDERS[1])
            if m in (SIZE_4MB, SIZE_8MB):
                self.v_size.set(SIZES[0] if m == SIZE_4MB else SIZES[1])
            self.apply_config()

        def apply_config(self):
            if not self.proc:
                messagebox.showwarning(APP_TITLE, "先にアタッチしてください。")
                return False
            try:
                base = parse_hex(self.v_base.get())
            except ValueError:
                messagebox.showerror(APP_TITLE, "ホスト先頭アドレスが不正です(16進)。")
                return False
            size = SIZE_4MB if self.v_size.get() == "4MB" else SIZE_8MB
            swap = self.v_order.get() == ORDERS[0]
            if self.proc.read_bytes(base, size) is None:
                if not messagebox.askyesno(APP_TITLE, "指定範囲を一括で読み取れません。このまま使いますか？"):
                    return False
            was_running = self.sc.running
            if was_running:
                self.sc.stop()
            try:
                self.sc.reconfigure(self.proc, base, size, swap)
            except ValueError as e:
                messagebox.showerror(APP_TITLE, str(e))
                return False
            self.v_status.set(f"{self.proc.name}: RDRAM={base:X} "
                              f"{'LE32' if swap else 'BE'} {size // 0x100000}MB を使用")
            if was_running:
                self.on_start()
            return True

        # ---------- 検索 ----------
        def on_start(self):
            if not self.sc.configured:
                messagebox.showwarning(APP_TITLE, "先にアタッチして RDRAM を設定してください。")
                return
            if self.sc.running:
                return
            try:
                iv = max(0.0, float(self.v_interval.get()) / 1000.0)
            except ValueError:
                iv = 0.0
            self.error_shown = None
            self.sc.start(iv)
            self.v_status.set("検索中… ゲームを色々操作してから「停止」してください。")

        def on_stop(self):
            if self.sc.running:
                self.sc.stop()
                self.v_status.set("停止しました。")
            self.refresh_list(True)

        def on_reset(self):
            if self.sc.has_data and not messagebox.askyesno(APP_TITLE, "検索結果を消去しますか？"):
                return
            running = self.sc.running
            if running:
                self.sc.stop()
            self.sc.reset()
            self.refresh_list(True)
            if running:
                self.on_start()

        # ---------- 結果 ----------
        def get_params(self):
            minlen = max(1, int(self.v_minlen.get()))
            lo = to_offset(parse_hex(self.v_lo.get()))
            hi_raw = parse_hex(self.v_hi.get())
            hi = to_offset(hi_raw)
            if hi == 0 and hi_raw != 0:   # 例: A0000000 のように一周した場合
                hi = self.sc.size
            return minlen, bool(self.v_align.get()), lo, min(hi, self.sc.size)

        def refresh_list(self, force=False):
            self.last_refresh = time.perf_counter()
            if not self.sc.has_data:
                self.last_ranges = []
                self.v_summary.set("")
                self.update_tree([])
                return
            try:
                minlen, align, lo, hi = self.get_params()
            except ValueError:
                if force:
                    messagebox.showerror(APP_TITLE, "検索設定(最小連続長/範囲)が不正です。")
                return
            mask = self.sc.get_n64_mask()
            rng = find_zero_runs(mask, minlen, align, lo, hi)
            self.last_ranges = rng
            total = sum(e - s for s, e in rng)
            self.v_summary.set(f"未使用ブロック {len(rng)} 個 / 合計 {total:,} バイト (0x{total:X})")
            self.update_tree(rng)

        def update_tree(self, rng):
            key = (len(rng), rng[:1], rng[-1:], sum(e - s for s, e in rng))
            if key == self.last_tree_key:
                return
            self.last_tree_key = key
            self.tree.delete(*self.tree.get_children())
            for s, e in rng[:MAX_TREE_ROWS]:
                self.tree.insert("", "end", values=(fmt_addr(s), fmt_addr(e - 1),
                                                     f"0x{e - s:X}", f"{e - s:,}"))
            if len(rng) > MAX_TREE_ROWS:
                self.tree.insert("", "end", values=("…", f"他 {len(rng) - MAX_TREE_ROWS} 件",
                                                     "(保存で全件)", ""))

        def copy_row(self, _e):
            sel = self.tree.selection()
            if sel:
                v = self.tree.item(sel[0], "values")
                self.root.clipboard_clear()
                self.root.clipboard_append(f"{v[0]}-{v[1]}  {v[2]}")
                self.v_status.set(f"コピーしました: {v[0]}-{v[1]}")

        def copy_all(self):
            txt = "\n".join(f"{fmt_addr(s)}-{fmt_addr(e - 1)}  0x{e - s:X}" for s, e in self.last_ranges)
            self.root.clipboard_clear()
            self.root.clipboard_append(txt)
            self.v_status.set(f"{len(self.last_ranges)} 件をコピーしました。")

        # ---------- 保存 / 読込 ----------
        def on_save(self):
            if not self.sc.has_data:
                messagebox.showinfo(APP_TITLE, "保存する検索データがありません。")
                return
            self.refresh_list(True)
            try:
                minlen, align, lo, hi = self.get_params()
            except ValueError:
                return
            path = filedialog.asksaveasfilename(
                title="結果を保存", defaultextension=".txt",
                initialfile=f"n64_unused_{datetime.now():%Y%m%d_%H%M%S}.txt",
                filetypes=[("テキスト", "*.txt"), ("すべて", "*.*")])
            if not path:
                return
            meta = {
                "saved": f"{datetime.now():%Y-%m-%d %H:%M:%S}",
                "process": self.proc.name if self.proc else "",
                "rdram_size": f"0x{self.sc.size:X}",
                "min_len": minlen,
                "align4": int(align),
                "range": f"{fmt_addr(lo)}-{fmt_addr(hi)}",
                "samples": self.sc.samples,
                "elapsed_sec": f"{self.sc.elapsed_now():.1f}",
                "blocks": len(self.last_ranges),
                "total_bytes": sum(e - s for s, e in self.last_ranges),
            }
            try:
                save_result(path, meta, self.last_ranges)
            except OSError as e:
                messagebox.showerror(APP_TITLE, f"保存できません: {e}")
                return
            self.v_status.set(f"保存しました: {path}")

        def on_load(self):
            path = filedialog.askopenfilename(title="再開ファイルを開く",
                                              filetypes=[("テキスト", "*.txt"), ("すべて", "*.*")])
            if not path:
                return
            try:
                meta, ranges = load_result(path)
            except (OSError, UnicodeDecodeError) as e:
                messagebox.showerror(APP_TITLE, f"読み込めません: {e}")
                return
            if self.sc.has_data and not messagebox.askyesno(
                    APP_TITLE, "現在の検索データを破棄して、ファイルの内容で置き換えますか？"):
                return
            try:
                size = int(meta.get("rdram_size", "0"), 0)
            except ValueError:
                size = 0
            if size not in (SIZE_4MB, SIZE_8MB):
                size = SIZE_8MB if any(e > SIZE_4MB for _, e in ranges) else SIZE_4MB
            running = self.sc.running
            if running:
                self.sc.stop()
            try:
                samples = int(meta.get("samples", "0"))
                elapsed = float(meta.get("elapsed_sec", "0"))
            except ValueError:
                samples, elapsed = 0, 0.0
            self.sc.load(size, mask_from_ranges(size, ranges), samples, elapsed)
            self.v_size.set(SIZES[0] if size == SIZE_4MB else SIZES[1])
            if "min_len" in meta:
                self.v_minlen.set(meta["min_len"])
            if "align4" in meta:
                self.v_align.set(meta["align4"] == "1")
            if "range" in meta and "-" in meta["range"]:
                lo, hi = meta["range"].split("-", 1)
                self.v_lo.set(lo.strip())
                self.v_hi.set(hi.strip())
            self.refresh_list(True)
            msg = f"{len(ranges)} 件を読み込みました。"
            if self.sc.configured:
                msg += "「開始」で続きから検索します。"
            else:
                msg += "アタッチ後に「開始」で続きから検索します。"
            self.v_status.set(msg)
            if running:
                self.on_start()

        # ---------- 定期更新 ----------
        def tick(self):
            now = time.perf_counter()
            ps, pt = self.prev_samples
            if now - pt >= 1.0:
                self.rate = (self.sc.samples - ps) / (now - pt)
                self.prev_samples = (self.sc.samples, now)
            el = self.sc.elapsed_now()
            state = "検索中" if self.sc.running else "停止中"
            self.v_stats.set(f"[{state}]  サンプル数 {self.sc.samples:,}   "
                             f"経過 {int(el // 3600)}:{int(el % 3600 // 60):02d}:{int(el % 60):02d}   "
                             f"速度 {self.rate:.1f} 回/秒")
            if self.sc.running and now - self.last_refresh > 1.0:
                self.refresh_list()
            if self.sc.error and not self.sc.running and self.error_shown != self.sc.error:
                self.error_shown = self.sc.error
                self.refresh_list()
                self.v_status.set(self.sc.error)
                messagebox.showerror(APP_TITLE, self.sc.error + "\n検索結果は保持しています。保存しておくと再開できます。")
            self.root.after(300, self.tick)

        def on_close(self):
            self.sc.stop()
            if self.proc:
                self.proc.close()
            self.root.destroy()

    root = tk.Tk()
    try:
        ttk.Style().theme_use("vista")
    except Exception:
        pass
    App(root)
    root.mainloop()


def main():
    if sys.platform != "win32":
        print("このツールは Windows 専用です。")
        sys.exit(1)
    init_win32()
    run_gui()


if __name__ == "__main__":
    main()
