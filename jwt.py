#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
JWT 弱密钥爆破工具 - GUI 版（慢速演示 + 固定字典）
仅限授权测试环境使用，该工具只能用于合法授权测试，禁止非法测试

字典文件: 脚本同目录下的 jwt.txt
"""

import tkinter as tk
from tkinter import ttk, messagebox, scrolledtext
import threading
import queue
import json
import base64
import time
import os
import sys
import random

try:
    import jwt
except ImportError:
    import tkinter.messagebox as mb
    mb.showerror("缺少依赖", "请先安装 pyjwt:\n\npip install pyjwt")
    sys.exit(1)


# ============================================================
# 固定字典路径（脚本同目录下的 jwt.txt）
# ============================================================
SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
WORDLIST_PATH = os.path.join(SCRIPT_DIR, "jwt.txt")


# ============================================================
# 核心逻辑
# ============================================================
def b64url_decode(s):
    s += '=' * (-len(s) % 4)
    return base64.urlsafe_b64decode(s)


def decode_jwt_parts(token):
    parts = token.strip().split('.')
    if len(parts) != 3:
        raise ValueError("JWT 格式不正确（应包含两个点）")
    header = json.loads(b64url_decode(parts[0]))
    payload = json.loads(b64url_decode(parts[1]))
    return header, payload


def try_secret(token, secret, alg):
    try:
        return jwt.decode(
            token, secret, algorithms=[alg],
            options={"verify_exp": False, "verify_aud": False, "verify_nbf": False}
        )
    except jwt.InvalidSignatureError:
        return None
    except Exception:
        return None


# ============================================================
# 慢速爆破（单线程，逐条上报）
# ============================================================
def crack_slow_worker(token, wordlist_path, alg, out_queue, stop_event,
                      target_seconds):
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            secrets = [l.rstrip('\n') for l in f if l.strip()]
    except Exception as e:
        out_queue.put(('error', f"读取字典失败: {e}"))
        return

    total = len(secrets)
    if total == 0:
        out_queue.put(('error', "字典为空"))
        return

    per_item_base = target_seconds / total

    out_queue.put(('log', f"[*] 算法: {alg}"))
    out_queue.put(('log', f"[*] 模式: 慢速演示"))
    out_queue.put(('log', f"[*] 字典: {wordlist_path}"))
    out_queue.put(('log', f"[*] 候选密钥: {total}"))
    out_queue.put(('log', f"[*] 目标时长: {target_seconds:.2f}s (随机 2-6s)"))
    out_queue.put(('log', "-" * 50))

    start = time.time()
    found = None
    tested = 0

    for idx, secret in enumerate(secrets, 1):
        if stop_event.is_set():
            out_queue.put(('log', "[!] 用户停止"))
            out_queue.put(('done', None))
            return

        jitter = random.uniform(0.6, 1.4)
        time.sleep(per_item_base * jitter)

        tested = idx
        percent = idx / total * 100
        elapsed = time.time() - start
        rate = idx / elapsed if elapsed > 0 else 0

        r = try_secret(token, secret, alg)

        if r is not None:
            out_queue.put(('progress', (idx, total, rate, percent)))
            out_queue.put(('log', f"[+] 命中！密钥: {secret}"))
            out_queue.put(('log', f"[+] Payload: {json.dumps(r, ensure_ascii=False)}"))
            out_queue.put(('log', f"[+] 尝试次数: {idx} / {total}"))
            out_queue.put(('log', f"[+] 耗时: {elapsed:.2f}s"))
            found = (secret, r)
            out_queue.put(('found', found))
            break

        out_queue.put(('attempt', (idx, total, secret, False)))
        out_queue.put(('progress', (idx, total, rate, percent)))

    if found is None:
        elapsed = time.time() - start
        out_queue.put(('log', "-" * 50))
        out_queue.put(('log', f"[-] 未找到密钥（已测试 {tested} 条，耗时 {elapsed:.2f}s）"))
        out_queue.put(('done', None))


# ============================================================
# 极速爆破（多线程）
# ============================================================
def crack_fast_worker(token, wordlist_path, alg, threads, out_queue, stop_event):
    try:
        with open(wordlist_path, 'r', encoding='utf-8', errors='ignore') as f:
            secrets = [l.rstrip('\n') for l in f if l.strip()]
    except Exception as e:
        out_queue.put(('error', f"读取字典失败: {e}"))
        return

    total = len(secrets)
    out_queue.put(('log', f"[*] 算法: {alg}"))
    out_queue.put(('log', f"[*] 模式: 极速"))
    out_queue.put(('log', f"[*] 字典: {wordlist_path}"))
    out_queue.put(('log', f"[*] 候选密钥: {total}"))
    out_queue.put(('log', f"[*] 线程数: {threads}"))
    out_queue.put(('log', "-" * 50))

    from concurrent.futures import ThreadPoolExecutor, as_completed

    start = time.time()
    tested = 0
    found = None

    with ThreadPoolExecutor(max_workers=threads) as ex:
        futures = {ex.submit(try_secret, token, s, alg): s for s in secrets}
        for fut in as_completed(futures):
            if stop_event.is_set():
                for f in futures:
                    f.cancel()
                out_queue.put(('log', "[!] 用户停止"))
                out_queue.put(('done', None))
                return

            tested += 1
            if tested % 200 == 0 or tested == total:
                elapsed = time.time() - start
                rate = tested / elapsed if elapsed > 0 else 0
                percent = tested / total * 100
                out_queue.put(('progress', (tested, total, rate, percent)))

            r = fut.result()
            if r is not None:
                found = (futures[fut], r)
                for f in futures:
                    f.cancel()
                break

    elapsed = time.time() - start
    out_queue.put(('log', "-" * 50))

    if found:
        secret, payload = found
        out_queue.put(('log', f"[+] 爆破成功！耗时 {elapsed:.2f}s，测试 {tested} 次"))
        out_queue.put(('log', f"[+] 密钥: {secret}"))
        out_queue.put(('log', f"[+] Payload: {json.dumps(payload, ensure_ascii=False)}"))
        out_queue.put(('found', (secret, payload)))
    else:
        out_queue.put(('log', f"[-] 未找到密钥（已测试 {tested} 条，耗时 {elapsed:.2f}s）"))
        out_queue.put(('done', None))


# ============================================================
# GUI
# ============================================================
class JWTCrackerGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("JWT 弱密钥爆破工具 - 授权测试专用")
        self.root.geometry("880x720")
        self.root.minsize(750, 640)

        self.queue = queue.Queue()
        self.stop_event = threading.Event()
        self.worker_thread = None
        self.last_result = None

        self._build_ui()
        self._check_wordlist()
        self._poll_queue()

    def _build_ui(self):
        top = tk.Frame(self.root, bg="#2c3e50", height=48)
        top.pack(fill=tk.X)
        tk.Label(
            top, text="  JWT 弱密钥爆破工具",
            bg="#2c3e50", fg="white",
            font=("Microsoft YaHei", 14, "bold")
        ).pack(side=tk.LEFT, pady=10)
        tk.Label(
            top, text="",
            bg="#2c3e50", fg="#e74c3c",
            font=("Microsoft YaHei", 9)
        ).pack(side=tk.RIGHT, pady=10)

        main = ttk.Frame(self.root, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        # JWT 输入
        jwt_frame = ttk.LabelFrame(main, text=" JWT Token ", padding=8)
        jwt_frame.pack(fill=tk.X, pady=(0, 8))

        self.jwt_text = scrolledtext.ScrolledText(
            jwt_frame, height=4, wrap=tk.WORD,
            font=("Consolas", 9)
        )
        self.jwt_text.pack(fill=tk.X, side=tk.LEFT, expand=True)

        btn_jwt = ttk.Frame(jwt_frame)
        btn_jwt.pack(side=tk.RIGHT, fill=tk.Y, padx=(6, 0))
        ttk.Button(btn_jwt, text="粘贴", width=8,
                   command=self.paste_jwt).pack(pady=1)
        ttk.Button(btn_jwt, text="解析", width=8,
                   command=self.parse_jwt).pack(pady=1)
        ttk.Button(btn_jwt, text="清空", width=8,
                   command=lambda: self.jwt_text.delete("1.0", tk.END)).pack(pady=1)

        # 配置
        cfg = ttk.LabelFrame(main, text=" 配置 ", padding=8)
        cfg.pack(fill=tk.X, pady=(0, 8))

        # ★ 字典固定显示
        ttk.Label(cfg, text="字典文件:").grid(row=0, column=0, sticky=tk.W, pady=3)
        self.wordlist_label = ttk.Label(
            cfg, text=WORDLIST_PATH, foreground="#2c3e50"
        )
        self.wordlist_label.grid(row=0, column=1, sticky=tk.W, padx=5, pady=3)

        self.wordlist_status = ttk.Label(cfg, text="")
        self.wordlist_status.grid(row=0, column=2, columnspan=2,
                                  sticky=tk.W, padx=5, pady=3)

        ttk.Label(cfg, text="算法:").grid(row=1, column=0, sticky=tk.W, pady=3)
        self.alg_var = tk.StringVar(value="HS256")
        alg_box = ttk.Combobox(
            cfg, textvariable=self.alg_var, state="readonly",
            values=["HS256", "HS384", "HS512"], width=12
        )
        alg_box.grid(row=1, column=1, sticky=tk.W, padx=5, pady=3)

        ttk.Label(cfg, text="线程数:").grid(row=1, column=2, sticky=tk.E, pady=3)
        self.threads_var = tk.IntVar(value=8)
        ttk.Spinbox(cfg, from_=1, to=64, textvariable=self.threads_var,
                    width=8).grid(row=1, column=3, sticky=tk.W, padx=5, pady=3)

        # 慢速模式
        speed_frame = ttk.Frame(cfg)
        speed_frame.grid(row=2, column=0, columnspan=4, sticky=tk.W, pady=(5, 0))

        self.slow_mode_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(
            speed_frame, text="慢速演示模式（单线程，逐条显示，2-6秒随机结束）",
            variable=self.slow_mode_var
        ).pack(side=tk.LEFT)

        cfg.columnconfigure(1, weight=1)

        # 操作按钮
        btn_frame = ttk.Frame(main)
        btn_frame.pack(fill=tk.X, pady=(0, 8))

        self.start_btn = ttk.Button(
            btn_frame, text="▶  开始爆破", command=self.start_crack
        )
        self.start_btn.pack(side=tk.LEFT, padx=(0, 5))

        self.stop_btn = ttk.Button(
            btn_frame, text="■  停止", command=self.stop_crack,
            state=tk.DISABLED
        )
        self.stop_btn.pack(side=tk.LEFT, padx=5)

        ttk.Button(btn_frame, text="复制结果",
                   command=self.copy_result).pack(side=tk.LEFT, padx=5)
        ttk.Button(btn_frame, text="保存日志",
                   command=self.save_log).pack(side=tk.LEFT, padx=5)

        # 进度
        prog_frame = ttk.Frame(main)
        prog_frame.pack(fill=tk.X, pady=(0, 8))

        self.progress = ttk.Progressbar(
            prog_frame, mode='determinate', maximum=100
        )
        self.progress.pack(fill=tk.X, side=tk.LEFT, expand=True)

        self.progress_label = ttk.Label(prog_frame, text="0 / 0  (0 h/s)")
        self.progress_label.pack(side=tk.RIGHT, padx=(8, 0))

        # 日志
        log_frame = ttk.LabelFrame(main, text=" 日志 ", padding=4)
        log_frame.pack(fill=tk.BOTH, expand=True)

        self.log_text = scrolledtext.ScrolledText(
            log_frame, wrap=tk.WORD, font=("Consolas", 9),
            bg="#1e1e1e", fg="#d4d4d4", insertbackground="white"
        )
        self.log_text.pack(fill=tk.BOTH, expand=True)

        self.log_text.tag_config("ok", foreground="#4ec9b0")
        self.log_text.tag_config("err", foreground="#f44747")
        self.log_text.tag_config("warn", foreground="#dcdcaa")
        self.log_text.tag_config("info", foreground="#569cd6")
        self.log_text.tag_config("attempt", foreground="#808080")

        # 状态栏
        self.status = tk.StringVar(value="就绪")
        status_bar = tk.Label(
            self.root, textvariable=self.status, anchor=tk.W,
            bg="#ecf0f1", fg="#2c3e50", padx=8, pady=3
        )
        status_bar.pack(fill=tk.X, side=tk.BOTTOM)

    # ---------- 字典检查 ----------
    def _check_wordlist(self):
        """启动时检查字典文件"""
        if os.path.isfile(WORDLIST_PATH):
            try:
                with open(WORDLIST_PATH, 'r', encoding='utf-8', errors='ignore') as f:
                    count = sum(1 for l in f if l.strip())
                self.wordlist_status.config(
                    text=f"✓ 存在 ({count} 条)",
                    foreground="#27ae60"
                )
                self.status.set(f"就绪 | 字典已加载 {count} 条")
            except Exception as e:
                self.wordlist_status.config(
                    text=f"✗ 读取失败: {e}", foreground="#e74c3c"
                )
        else:
            self.wordlist_status.config(
                text="✗ 未找到 jwt.txt", foreground="#e74c3c"
            )
            self.status.set("警告：脚本同目录下缺少 jwt.txt")

    # ---------- 辅助 ----------
    def log(self, msg, tag=None):
        self.log_text.insert(tk.END, msg + "\n", tag)
        self.log_text.see(tk.END)

    def paste_jwt(self):
        try:
            content = self.root.clipboard_get()
            self.jwt_text.delete("1.0", tk.END)
            self.jwt_text.insert("1.0", content.strip())
            self.status.set("已粘贴")
        except Exception as e:
            messagebox.showwarning("粘贴失败", str(e))

    def parse_jwt(self):
        token = self.jwt_text.get("1.0", tk.END).strip()
        if not token:
            messagebox.showwarning("提示", "请先输入 JWT")
            return
        try:
            header, payload = decode_jwt_parts(token)
            self.log("[*] Header:", "info")
            self.log(json.dumps(header, indent=2, ensure_ascii=False))
            self.log("[*] Payload:", "info")
            self.log(json.dumps(payload, indent=2, ensure_ascii=False))
            self.log("-" * 50)

            alg = header.get('alg', '')
            if alg in ('HS256', 'HS384', 'HS512'):
                self.alg_var.set(alg)
            else:
                self.log(f"[!] 当前算法 {alg} 非 HMAC，无法用本工具爆破", "warn")

            self.status.set(f"解析成功 | alg={alg}")
        except Exception as e:
            messagebox.showerror("解析失败", str(e))

    # ---------- 爆破 ----------
    def start_crack(self):
        token = self.jwt_text.get("1.0", tk.END).strip()
        if not token:
            messagebox.showwarning("提示", "请先输入 JWT")
            return

        # ★ 使用固定字典路径
        wordlist = WORDLIST_PATH
        if not os.path.isfile(wordlist):
            messagebox.showerror(
                "字典缺失",
                f"未找到字典文件:\n{wordlist}\n\n"
                f"请将 jwt.txt 放到脚本同目录下。"
            )
            return

        try:
            decode_jwt_parts(token)
        except Exception as e:
            messagebox.showerror("JWT 无效", str(e))
            return

        alg = self.alg_var.get()
        threads = self.threads_var.get()
        slow_mode = self.slow_mode_var.get()

        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self.progress['value'] = 0
        self.progress_label.config(text="0 / 0  (0 h/s)")
        self.status.set("爆破中...")
        self.last_result = None

        self.log("=" * 50)
        self.log(f"[*] 开始爆破 | {time.strftime('%H:%M:%S')} | "
                 f"模式: {'慢速演示' if slow_mode else '极速'}", "info")

        self.stop_event.clear()

        if slow_mode:
            target = random.uniform(2.0, 6.0)
            self.worker_thread = threading.Thread(
                target=crack_slow_worker,
                args=(token, wordlist, alg, self.queue,
                      self.stop_event, target),
                daemon=True
            )
        else:
            self.worker_thread = threading.Thread(
                target=crack_fast_worker,
                args=(token, wordlist, alg, threads, self.queue,
                      self.stop_event),
                daemon=True
            )
        self.worker_thread.start()

    def stop_crack(self):
        self.stop_event.set()
        self.status.set("正在停止...")

    def copy_result(self):
        if self.last_result:
            secret, payload = self.last_result
            text = f"SECRET: {secret}\nPAYLOAD: {json.dumps(payload, ensure_ascii=False)}"
            self.root.clipboard_clear()
            self.root.clipboard_append(text)
            self.status.set("结果已复制到剪贴板")
            messagebox.showinfo("已复制", "密钥和 Payload 已复制")
        else:
            messagebox.showinfo("提示", "还没有成功的结果")

    def save_log(self):
        from tkinter import filedialog
        path = filedialog.asksaveasfilename(
            title="保存日志",
            defaultextension=".txt",
            filetypes=[("文本文件", "*.txt")]
        )
        if path:
            with open(path, 'w', encoding='utf-8') as f:
                f.write(self.log_text.get("1.0", tk.END))
            self.status.set(f"日志已保存: {path}")

    # ---------- 队列轮询 ----------
    def _poll_queue(self):
        try:
            while True:
                msg_type, data = self.queue.get_nowait()

                if msg_type == 'log':
                    tag = None
                    if data.startswith('[+]'):
                        tag = 'ok'
                    elif data.startswith('[-]'):
                        tag = 'err'
                    elif data.startswith('[!]'):
                        tag = 'warn'
                    elif data.startswith('[*]'):
                        tag = 'info'
                    self.log(data, tag)

                elif msg_type == 'attempt':
                    idx, total, secret, hit = data
                    if hit:
                        self.log(f"  [{idx:>5}/{total}]  ✓  {secret}", 'ok')
                    else:
                        self.log(f"  [{idx:>5}/{total}]  ✗  {secret}", 'attempt')

                elif msg_type == 'progress':
                    tested, total, rate, percent = data
                    self.progress['value'] = percent
                    self.progress_label.config(
                        text=f"{tested} / {total}  ({rate:.0f} h/s)"
                    )
                    self.status.set(f"爆破中... {percent:.1f}%")

                elif msg_type == 'found':
                    self.last_result = data
                    self.progress['value'] = 100
                    self.status.set(f"✓ 成功！密钥: {data[0]}")
                    self.start_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)

                elif msg_type == 'done':
                    self.start_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)
                    if self.last_result is None:
                        self.status.set("完成，未找到密钥")

                elif msg_type == 'error':
                    self.log(f"[!] {data}", 'warn')
                    self.start_btn.config(state=tk.NORMAL)
                    self.stop_btn.config(state=tk.DISABLED)
                    self.status.set("出错")

        except queue.Empty:
            pass

        self.root.after(50, self._poll_queue)


# ============================================================
def main():
    root = tk.Tk()
    try:
        from ctypes import windll
        windll.shcore.SetProcessDpiAwareness(1)
    except Exception:
        pass
    app = JWTCrackerGUI(root)
    root.mainloop()


if __name__ == '__main__':
    main()