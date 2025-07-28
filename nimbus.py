 (cd "$(git rev-parse --show-toplevel)" && git apply --3way <<'EOF' 
diff --git a/nimbus.py b/nimbus.py
index b0c8550ee27bd893708b10970e27efd642a0b796..9e6bc8b55dad1d05297ec10557477e61a7ceb2da 100644
--- a/nimbus.py
+++ b/nimbus.py
@@ -1,40 +1,45 @@
 from __future__ import annotations
-import sys, asyncio, time, json, re
+import sys, asyncio, time, json, re, random
 from dataclasses import dataclass
 from pathlib import Path
 from typing import Optional, List, Dict, Any, Tuple, Callable
 import httpx
 from httpx_socks import SyncProxyTransport
 import socketio
 import aiohttp
 from aiohttp_socks import ProxyConnector
-from PySide6.QtWidgets import (
-    QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
-    QFileDialog, QSpinBox, QLineEdit
-)
-from PySide6.QtCore import QThread, Signal
+
+try:
+    from PySide6.QtWidgets import (
+        QApplication, QWidget, QVBoxLayout, QHBoxLayout, QLabel, QPushButton, QTextEdit,
+        QFileDialog, QSpinBox, QLineEdit, QCheckBox
+    )
+    from PySide6.QtCore import QThread, Signal, QTimer
+    GUI_AVAILABLE = True
+except Exception:
+    GUI_AVAILABLE = False
 
 USER_AGENT = "Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/126.0.0.0 Safari/537.36"
 DEFAULT_PROXY_SCHEME = "socks5"
 HEADERS_POOL = {
     "User-Agent": USER_AGENT,
     "Accept": "text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,*/*;q=0.8",
     "Accept-Language": "en-US,en;q=0.5",
     "Accept-Encoding": "gzip, deflate, br",
     "Connection": "keep-alive",
     "Upgrade-Insecure-Requests": "1",
     "Sec-Fetch-Dest": "document",
     "Sec-Fetch-Mode": "navigate",
     "Sec-Fetch-Site": "none",
     "Sec-Fetch-User": "?1",
 }
 
 class BadCredentials(Exception):
     pass
 class TwoFARequired(Exception):
     pass
 
 @dataclass
 class User:
     session_id: str
     domain: str
@@ -204,83 +209,89 @@ def load_proxies_from_text(text: str, default_scheme: str = DEFAULT_PROXY_SCHEME
     items: List[str] = []
     for ln in text.splitlines():
         ln = ln.strip()
         if not ln or ln.startswith('#'):
             continue
         items.append(normalize_proxy(ln, default_scheme))
     return items
 
 def fetch_pool(url: str) -> str:
     headers = dict(HEADERS_POOL)
     try:
         with httpx.Client(headers=headers, timeout=30.0, follow_redirects=True, http2=True) as c:
             r = c.get(url)
             r.raise_for_status()
             return r.text or ""
     except httpx.HTTPStatusError as e:
         raise Exception(f"HTTP error fetching pool: {e.response.status_code} {e.response.reason_phrase} - {e.response.text[:200]}")
     except httpx.TimeoutException:
         raise Exception("Timeout while fetching proxy pool")
     except httpx.ProxyError:
         raise Exception("Proxy error while fetching pool")
     except Exception as e:
         raise Exception(f"Unexpected error fetching pool: {str(e)}")
 
 class ProxyRotator:
-    def __init__(self, proxies: List[str], ttl_minutes: int, fetch_url: Optional[str] = None):
+    def __init__(self, proxies: List[str], ttl_minutes: int, fetch_url: Optional[str] = None, enabled: bool = True):
         self.proxies = [normalize_proxy(p) for p in (proxies or [])]
         self.fetch_url = fetch_url
         self.ttl_ms = ttl_minutes * 60_000
-        self._idx = 0
         self._cur: Optional[str] = None
         self._until = 0
+        self.enabled = enabled
+
+    def set_enabled(self, val: bool) -> None:
+        self.enabled = val
+
     async def current(self) -> Optional[str]:
+        if not self.enabled:
+            return None
         now = int(time.time() * 1000)
         if self.fetch_url and (not self._cur or now >= self._until):
             try:
                 text = fetch_pool(self.fetch_url)
                 lines = load_proxies_from_text(text)
                 self.proxies = lines
-                self._idx = 0
                 self._cur = None
                 self._until = now + self.ttl_ms
             except Exception as e:
                 raise e  # Let the caller handle
         if not self.proxies:
             return None
         if not self._cur or now >= self._until:
-            self._cur = self.proxies[self._idx % len(self.proxies)]
-            self._idx += 1
+            self._cur = random.choice(self.proxies)
             self._until = now + self.ttl_ms
         return self._cur
+
     def invalidate(self):
         self._until = 0
+
     def set_list(self, proxies: List[str]):
         self.proxies = [normalize_proxy(p) for p in proxies]
-        self._idx = 0
         self._cur = None
         self._until = 0
+
     def count(self) -> int:
         return len(self.proxies)
 
 # io helpers
 
 def read_lines(path: Optional[Path]) -> List[str]:
     if not path or not path.exists():
         return []
     return [ln.strip() for ln in path.read_text(encoding="utf-8", errors="ignore").splitlines() if ln.strip() and not ln.strip().startswith('#')]
 
 def read_accounts(path: Path) -> List[Tuple[str,str]]:
     items: List[Tuple[str,str]] = []
     for ln in read_lines(path):
         if ':' not in ln:
             raise ValueError(f"bad accounts line: {ln}")
         email, pwd = ln.split(':',1)
         items.append((email.strip(), pwd.strip()))
     return items
 
 # core batch
 
 async def export_one_account(email: str, password: str, out_root: Path, rot: ProxyRotator, retries_account: int, note_conc: int, download_timeout: float, log: Callable[[str], None]|None) -> Tuple[str,bool,int,str]:
     attempts = 0
     last_err = ''
     while attempts < retries_account:
@@ -381,197 +392,281 @@ async def run_batch(accounts_file: Path, out_root: Path, rot: ProxyRotator, acc_
     sem = asyncio.Semaphore(acc_conc)
     results: List[Tuple[str,bool,int,str]] = []
     async def worker(email, pwd):
         nonlocal in_work, good, bad, error
         async with sem:
             in_work += 1
             if stats_cb: stats_cb(in_work, good, bad, error)
             em, ok, cnt, err = await export_one_account(email, pwd, out_root, rot, retries_account, note_conc, download_timeout, log_fn)
             results.append((em, ok, cnt, err))
             in_work -= 1
             if ok:
                 good += 1
             else:
                 if err == 'BAD':
                     bad += 1
                     append_line(out_root / 'BAD.txt', f"{em}:{pwd}")
                 elif err == '2FA':
                     error += 1
                     append_line(out_root / '2fa.txt', f"{em}:{pwd}")
                 else:
                     error += 1
                     append_line(out_root / 'ERROR.txt', f"{em}:{pwd} - {err}")
             if stats_cb: stats_cb(in_work, good, bad, error)
     await asyncio.gather(*(worker(e,p) for e,p in accounts))
 
-class Worker(QThread):
-    logsig = Signal(str)
-    finsig = Signal()
-    proxysig = Signal(int)
-    statssig = Signal(str)
-    def __init__(self, accounts_file: Path, proxies_file: Optional[Path], out_root: Path, proxy_url: Optional[str], proxy_ttl_min: int, acc_conc: int, retries_account: int, note_conc: int, download_timeout: float):
-        super().__init__()
-        self.accounts_file = accounts_file
-        self.proxies_file = proxies_file
-        self.out_root = out_root
-        self.proxy_url = proxy_url
-        self.proxy_ttl_min = proxy_ttl_min
-        self.acc_conc = acc_conc
-        self.retries_account = retries_account
-        self.note_conc = note_conc
-        self.download_timeout = download_timeout
-        self.rot = ProxyRotator(read_lines(proxies_file) if proxies_file else [], proxy_ttl_min, proxy_url)
-    def set_proxy_url(self, url: Optional[str]):
-        self.proxy_url = url
-        self.rot.fetch_url = url
-    def reload_proxies(self):
-        raw_file_list = read_lines(self.proxies_file) if self.proxies_file else []
-        lst = [normalize_proxy(x) for x in raw_file_list]
-        pool_loaded = 0
-        if self.proxy_url:
-            try:
-                text = fetch_pool(self.proxy_url)
-                lines = load_proxies_from_text(text)
-                pool_loaded = len(lines)
-                lst.extend(lines)
-                self.logsig.emit(f"Proxy pool loaded successfully: {pool_loaded} proxies")
-            except Exception as e:
-                self.logsig.emit(f"Proxy pool fetch error: {str(e)}")
-        self.rot.set_list(lst)
-        total = self.rot.count()
-        self.logsig.emit(f"Proxy refresh: file={len(raw_file_list)} pool={pool_loaded} total={total}")
-        self.proxysig.emit(total)
-    def run(self):
-        if sys.platform.startswith('win'):
-            try:
-                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
-            except Exception:
-                pass
-        async def _run():
-            def log_cb(msg: str):
-                self.logsig.emit(msg)
-            def stats_cb(inwork: int, good: int, bad: int, err: int):
-                self.statssig.emit(f"In work: {inwork} | Good: {good} | Bad: {bad} | Error: {err}")
-            self.proxysig.emit(self.rot.count())
-            try:
-                await run_batch(self.accounts_file, self.out_root, self.rot, self.acc_conc, self.retries_account, self.note_conc, self.download_timeout, log_cb, stats_cb)
-            except Exception as e:
-                self.logsig.emit(f"ERROR: {e}")
-        asyncio.run(_run())
-        self.finsig.emit()
-
-class App(QWidget):
-    def __init__(self):
-        super().__init__()
-        self.setWindowTitle("Nimbus HTTP Exporter")
-        lay = QVBoxLayout(self)
-        self.btnAcc = QPushButton("accounts.txt")
-        self.lblAcc = QLabel("—")
-        self.btnAcc.clicked.connect(self.pickAcc)
-        row = QHBoxLayout(); row.addWidget(self.btnAcc); row.addWidget(self.lblAcc); lay.addLayout(row)
-        self.btnProx = QPushButton("proxies.txt (optional)")
-        self.lblProx = QLabel("—")
-        self.btnProx.clicked.connect(self.pickProx)
-        row = QHBoxLayout(); row.addWidget(self.btnProx); row.addWidget(self.lblProx); lay.addLayout(row)
-        self.poolEdit = QLineEdit(); self.poolEdit.setPlaceholderText("Proxy pool URL (optional)")
-        lay.addWidget(self.poolEdit)
-        self.proxyCountLbl = QLabel("Proxies: 0")
-        self.refreshBtn = QPushButton("Refresh proxies")
-        prow = QHBoxLayout(); prow.addWidget(self.proxyCountLbl); prow.addWidget(self.refreshBtn); lay.addLayout(prow)
-        self.btnOut = QPushButton("Папка выгрузки")
-        self.lblOut = QLabel(str(Path("exports").absolute()))
-        self.outPath = Path("exports").absolute()
-        self.btnOut.clicked.connect(self.pickOut)
-        row = QHBoxLayout(); row.addWidget(self.btnOut); row.addWidget(self.lblOut); lay.addLayout(row)
-        self.spinAcc = QSpinBox(); self.spinAcc.setRange(1, 50); self.spinAcc.setValue(2)
-        self.spinNote = QSpinBox(); self.spinNote.setRange(1, 64); self.spinNote.setValue(8)
-        self.spinRet = QSpinBox(); self.spinRet.setRange(1, 10); self.spinRet.setValue(3)
-        self.spinTTL = QSpinBox(); self.spinTTL.setRange(1, 240); self.spinTTL.setValue(10)
-        row = QHBoxLayout();
-        row.addWidget(QLabel("Потоки аккаунтов:")); row.addWidget(self.spinAcc)
-        row.addWidget(QLabel("Потоки заметок:")); row.addWidget(self.spinNote)
-        row.addWidget(QLabel("Повторы/акк:")); row.addWidget(self.spinRet)
-        row.addWidget(QLabel("TTL прокси (мин):")); row.addWidget(self.spinTTL)
-        lay.addLayout(row)
-        self.statsLbl = QLabel("In work: 0 | Good: 0 | Bad: 0 | Error: 0")
-        lay.addWidget(self.statsLbl)
-        self.log = QTextEdit(); self.log.setReadOnly(True); lay.addWidget(self.log)
-        self.btnStart = QPushButton("Старт")
-        self.btnStart.clicked.connect(self.start)
-        lay.addWidget(self.btnStart)
-        self.accounts: Optional[Path] = None
-        self.proxies: Optional[Path] = None
-        self.worker: Optional[Worker] = None
-        self.refreshBtn.clicked.connect(self.onRefreshProxies)
-    def pickAcc(self):
-        p, _ = QFileDialog.getOpenFileName(self, "accounts.txt", "", "Text (*.txt)")
-        if p:
-            self.accounts = Path(p); self.lblAcc.setText(p)
-    def pickProx(self):
-        p, _ = QFileDialog.getOpenFileName(self, "proxies.txt", "", "Text (*.txt)")
-        if p:
-            self.proxies = Path(p); self.lblProx.setText(p)
-    def pickOut(self):
-        p = QFileDialog.getExistingDirectory(self, "Папка выгрузки")
-        if p:
-            self.outPath = Path(p); self.lblOut.setText(p)
-    def start(self):
-        if not self.accounts:
-            self.log.append("Укажи accounts.txt")
-            return
-        self.worker = Worker(
-            accounts_file=self.accounts,
-            proxies_file=self.proxies,
-            out_root=self.outPath,
-            proxy_url=self.poolEdit.text().strip() or None,
-            proxy_ttl_min=self.spinTTL.value(),
-            acc_conc=self.spinAcc.value(),
-            retries_account=self.spinRet.value(),
-            note_conc=self.spinNote.value(),
-            download_timeout=180.0,
-        )
-        self.worker.logsig.connect(self.onLog)
-        self.worker.finsig.connect(self.onFin)
-        self.worker.proxysig.connect(self.onProxyCount)
-        self.worker.statssig.connect(self.onStats)
-        self.worker.start()
-        self.btnStart.setEnabled(False)
-        self.log.append("Старт...")
-    def onRefreshProxies(self):
-        if self.worker:
-            self.worker.set_proxy_url(self.poolEdit.text().strip() or None)
-            self.worker.reload_proxies()
-        else:
-            raw_file_list = read_lines(self.proxies) if self.proxies else []
+if GUI_AVAILABLE:
+    class Worker(QThread):
+        logsig = Signal(str)
+        finsig = Signal()
+        proxysig = Signal(int)
+        statssig = Signal(str)
+
+        def __init__(self, accounts_file: Path, proxies_file: Optional[Path], out_root: Path, proxy_url: Optional[str], proxy_ttl_min: int, acc_conc: int, retries_account: int, note_conc: int, download_timeout: float, no_proxy: bool = False):
+            super().__init__()
+            self.accounts_file = accounts_file
+            self.proxies_file = proxies_file
+            self.out_root = out_root
+            self.proxy_url = proxy_url
+            self.proxy_ttl_min = proxy_ttl_min
+            self.acc_conc = acc_conc
+            self.retries_account = retries_account
+            self.note_conc = note_conc
+            self.download_timeout = download_timeout
+            self.no_proxy = no_proxy
+            self.rot = ProxyRotator(read_lines(proxies_file) if proxies_file else [], proxy_ttl_min, proxy_url, not no_proxy)
+            
+        def set_proxy_url(self, url: Optional[str]):
+            self.proxy_url = url
+            self.rot.fetch_url = url
+
+        def set_no_proxy(self, val: bool):
+            self.no_proxy = val
+            self.rot.set_enabled(not val)
+
+        def reload_proxies(self):
+            if self.no_proxy:
+                self.rot.set_list([])
+                self.proxysig.emit(0)
+                return
+
+            raw_file_list = read_lines(self.proxies_file) if self.proxies_file else []
             lst = [normalize_proxy(x) for x in raw_file_list]
-            pool = self.poolEdit.text().strip()
             pool_loaded = 0
-            if pool:
+            if self.proxy_url:
                 try:
-                    text = fetch_pool(pool)
+                    text = fetch_pool(self.proxy_url)
                     lines = load_proxies_from_text(text)
                     pool_loaded = len(lines)
                     lst.extend(lines)
-                    self.log.append(f"Proxy pool loaded successfully: {pool_loaded} proxies")
+                    self.logsig.emit(f"Proxy pool loaded successfully: {pool_loaded} proxies")
                 except Exception as e:
-                    self.log.append(f"Proxy pool fetch error: {str(e)}")
-            self.proxyCountLbl.setText(f"Proxies: {len(lst)}")
-            self.log.append(f"Proxy preview: file={len(raw_file_list)} pool={pool_loaded} total={len(lst)}")
-    def onProxyCount(self, n: int):
-        self.proxyCountLbl.setText(f"Proxies: {n}")
-    def onStats(self, s: str):
-        self.statsLbl.setText(s)
-    def onLog(self, msg: str):
-        self.log.append(msg)
-    def onFin(self):
-        self.log.append("Готово")
-        self.btnStart.setEnabled(True)
+                    self.logsig.emit(f"Proxy pool fetch error: {str(e)}")
+            self.rot.set_list(lst)
+            total = self.rot.count()
+            self.logsig.emit(f"Proxy refresh: file={len(raw_file_list)} pool={pool_loaded} total={total}")
+            self.proxysig.emit(total)
+
+        def run(self):
+            if sys.platform.startswith('win'):
+                try:
+                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
+                except Exception:
+                    pass
+
+            async def _run():
+                def log_cb(msg: str):
+                    self.logsig.emit(msg)
+
+                def stats_cb(inwork: int, good: int, bad: int, err: int):
+                    self.statssig.emit(f"In work: {inwork} | Good: {good} | Bad: {bad} | Error: {err}")
+
+                self.proxysig.emit(self.rot.count())
+                try:
+                    await run_batch(self.accounts_file, self.out_root, self.rot, self.acc_conc, self.retries_account, self.note_conc, self.download_timeout, log_cb, stats_cb)
+                except Exception as e:
+                    self.logsig.emit(f"ERROR: {e}")
+
+            asyncio.run(_run())
+            self.finsig.emit()
+
+    class App(QWidget):
+        def __init__(self):
+            super().__init__()
+            self.setWindowTitle("Nimbus HTTP Exporter")
+            lay = QVBoxLayout(self)
+            self.btnAcc = QPushButton("accounts.txt")
+            self.lblAcc = QLabel("—")
+            self.btnAcc.clicked.connect(self.pickAcc)
+            row = QHBoxLayout(); row.addWidget(self.btnAcc); row.addWidget(self.lblAcc); lay.addLayout(row)
+            self.btnProx = QPushButton("proxies.txt (optional)")
+            self.lblProx = QLabel("—")
+            self.btnProx.clicked.connect(self.pickProx)
+            row = QHBoxLayout(); row.addWidget(self.btnProx); row.addWidget(self.lblProx); lay.addLayout(row)
+            self.poolEdit = QLineEdit(); self.poolEdit.setPlaceholderText("Proxy pool URL (optional)")
+            lay.addWidget(self.poolEdit)
+            self.noProxyChk = QCheckBox("Без прокси")
+            lay.addWidget(self.noProxyChk)
+            self.proxyCountLbl = QLabel("Proxies: 0")
+            self.refreshBtn = QPushButton("Refresh proxies")
+            prow = QHBoxLayout(); prow.addWidget(self.proxyCountLbl); prow.addWidget(self.refreshBtn); lay.addLayout(prow)
+            self.btnOut = QPushButton("Папка выгрузки")
+            self.lblOut = QLabel(str(Path("exports").absolute()))
+            self.outPath = Path("exports").absolute()
+            self.btnOut.clicked.connect(self.pickOut)
+            row = QHBoxLayout(); row.addWidget(self.btnOut); row.addWidget(self.lblOut); lay.addLayout(row)
+            self.spinAcc = QSpinBox(); self.spinAcc.setRange(1, 50); self.spinAcc.setValue(2)
+            self.spinNote = QSpinBox(); self.spinNote.setRange(1, 64); self.spinNote.setValue(8)
+            self.spinRet = QSpinBox(); self.spinRet.setRange(1, 10); self.spinRet.setValue(3)
+            self.spinTTL = QSpinBox(); self.spinTTL.setRange(1, 240); self.spinTTL.setValue(10)
+            row = QHBoxLayout();
+            row.addWidget(QLabel("Потоки аккаунтов:")); row.addWidget(self.spinAcc)
+            row.addWidget(QLabel("Потоки заметок:")); row.addWidget(self.spinNote)
+            row.addWidget(QLabel("Повторы/акк:")); row.addWidget(self.spinRet)
+            row.addWidget(QLabel("TTL прокси (мин):")); row.addWidget(self.spinTTL)
+            lay.addLayout(row)
+            self.statsLbl = QLabel("In work: 0 | Good: 0 | Bad: 0 | Error: 0")
+            lay.addWidget(self.statsLbl)
+            self.log = QTextEdit(); self.log.setReadOnly(True); lay.addWidget(self.log)
+            self.btnStart = QPushButton("Старт")
+            self.btnStart.clicked.connect(self.start)
+            lay.addWidget(self.btnStart)
+            self.accounts: Optional[Path] = None
+            self.proxies: Optional[Path] = None
+            self.worker: Optional[Worker] = None
+            self.refreshTimer = QTimer(self)
+            self.refreshTimer.timeout.connect(self.onRefreshProxies)
+            self.poolEdit.editingFinished.connect(self.onRefreshProxies)
+            self.refreshBtn.clicked.connect(self.onRefreshProxies)
+
+        def pickAcc(self):
+            p, _ = QFileDialog.getOpenFileName(self, "accounts.txt", "", "Text (*.txt)")
+            if p:
+                self.accounts = Path(p); self.lblAcc.setText(p)
+
+        def pickProx(self):
+            p, _ = QFileDialog.getOpenFileName(self, "proxies.txt", "", "Text (*.txt)")
+            if p:
+                self.proxies = Path(p); self.lblProx.setText(p)
+
+        def pickOut(self):
+            p = QFileDialog.getExistingDirectory(self, "Папка выгрузки")
+            if p:
+                self.outPath = Path(p); self.lblOut.setText(p)
+
+        def start(self):
+            if not self.accounts:
+                self.log.append("Укажи accounts.txt")
+                return
+            self.worker = Worker(
+                accounts_file=self.accounts,
+                proxies_file=self.proxies,
+                out_root=self.outPath,
+                proxy_url=self.poolEdit.text().strip() or None,
+                proxy_ttl_min=self.spinTTL.value(),
+                acc_conc=self.spinAcc.value(),
+                retries_account=self.spinRet.value(),
+                note_conc=self.spinNote.value(),
+                download_timeout=180.0,
+                no_proxy=self.noProxyChk.isChecked(),
+            )
+            self.worker.logsig.connect(self.onLog)
+            self.worker.finsig.connect(self.onFin)
+            self.worker.proxysig.connect(self.onProxyCount)
+            self.worker.statssig.connect(self.onStats)
+            self.worker.start()
+            if not self.noProxyChk.isChecked():
+                self.refreshTimer.start(self.spinTTL.value() * 60_000)
+            self.btnStart.setEnabled(False)
+            self.log.append("Старт...")
+
+        def onRefreshProxies(self):
+            if self.worker:
+                self.worker.set_no_proxy(self.noProxyChk.isChecked())
+                self.worker.set_proxy_url(self.poolEdit.text().strip() or None)
+                self.worker.reload_proxies()
+            else:
+                if self.noProxyChk.isChecked():
+                    self.proxyCountLbl.setText("Proxies: 0")
+                    self.log.append("Proxy preview: disabled")
+                else:
+                    raw_file_list = read_lines(self.proxies) if self.proxies else []
+                    lst = [normalize_proxy(x) for x in raw_file_list]
+                    pool = self.poolEdit.text().strip()
+                    pool_loaded = 0
+                    if pool:
+                        try:
+                            text = fetch_pool(pool)
+                            lines = load_proxies_from_text(text)
+                            pool_loaded = len(lines)
+                            lst.extend(lines)
+                            self.log.append(f"Proxy pool loaded successfully: {pool_loaded} proxies")
+                        except Exception as e:
+                            self.log.append(f"Proxy pool fetch error: {str(e)}")
+                    self.proxyCountLbl.setText(f"Proxies: {len(lst)}")
+                    self.log.append(f"Proxy preview: file={len(raw_file_list)} pool={pool_loaded} total={len(lst)}")
+
+        def onProxyCount(self, n: int):
+            self.proxyCountLbl.setText(f"Proxies: {n}")
+
+        def onStats(self, s: str):
+            self.statsLbl.setText(s)
+
+        def onLog(self, msg: str):
+            self.log.append(msg)
+
+        def onFin(self):
+            self.log.append("Готово")
+            self.refreshTimer.stop()
+            self.btnStart.setEnabled(True)
+
+def main_cli() -> None:
+    import argparse
+    parser = argparse.ArgumentParser(description="Nimbus HTTP Exporter CLI")
+    parser.add_argument("--accounts", required=True, help="Path to accounts.txt")
+    parser.add_argument("--proxies", help="Path to proxies.txt")
+    parser.add_argument("--proxy-url", help="Proxy pool URL")
+    parser.add_argument("--out", default="exports", help="Output directory")
+    parser.add_argument("--threads-acc", type=int, default=2, help="Account threads")
+    parser.add_argument("--threads-note", type=int, default=8, help="Note threads")
+    parser.add_argument("--retries", type=int, default=3, help="Retries per account")
+    parser.add_argument("--proxy-ttl", type=int, default=10, help="Proxy TTL minutes")
+    parser.add_argument("--timeout", type=float, default=180.0, help="Download timeout")
+    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy usage")
+    args = parser.parse_args()
+
+    rot = ProxyRotator(
+        read_lines(Path(args.proxies)) if args.proxies else [],
+        args.proxy_ttl,
+        args.proxy_url,
+        not args.no_proxy,
+    )
+
+    async def _run():
+        def log_cb(msg: str):
+            print(msg)
+        def stats_cb(i: int, g: int, b: int, e: int):
+            print(f"In work: {i} | Good: {g} | Bad: {b} | Error: {e}")
+        await run_batch(Path(args.accounts), Path(args.out), rot, args.threads_acc, args.retries, args.threads_note, args.timeout, log_cb, stats_cb)
 
-if __name__ == "__main__":
-    app = QApplication(sys.argv)
     if sys.platform.startswith('win'):
         try:
             asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
         except Exception:
             pass
-    w = App(); w.resize(1000, 720); w.show()
-    sys.exit(app.exec())
+    asyncio.run(_run())
+
+
+if __name__ == "__main__":
+    if not GUI_AVAILABLE or "--cli" in sys.argv:
+        if "--cli" in sys.argv:
+            sys.argv.remove("--cli")
+        main_cli()
+    else:
+        app = QApplication(sys.argv)
+        if sys.platform.startswith('win'):
+            try:
+                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
+            except Exception:
+                pass
+        w = App(); w.resize(1000, 720); w.show()
+        sys.exit(app.exec())
 
EOF
)
