#!/usr/bin/env python3
"""Singlite Single: one panel, this VPS, a local sing-box core."""
from __future__ import annotations
import argparse,base64,hashlib,hmac,http.cookies,ipaddress,json,mimetypes,os,re,secrets,signal,socket,subprocess,sys,tempfile,threading,time
from pathlib import Path
from http.server import BaseHTTPRequestHandler,ThreadingHTTPServer
from urllib.parse import quote,unquote,urlsplit
sys.path.insert(0,str(Path(__file__).resolve().parent))
from control import Controller,ControlError,SUBSCRIPTION_TITLE
from converter import Converter
from core import Runtime
COOKIE_NAME='singlite_session'
SESSION_TTL=12*60*60
MAX_BODY=2*1024*1024

class ApiError(Exception):
    def __init__(self, status: int, message: str):
        super().__init__(message)
        self.status = status
        self.message = message

def atomic_write(path: Path, value: bytes) -> None:
    """Replace a file without leaving a partially-written config or secret."""
    path.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
    fd, temporary = tempfile.mkstemp(prefix="." + path.name + ".", dir=path.parent)
    try:
        os.fchmod(fd, 0o600)
        with os.fdopen(fd, "wb") as output:
            output.write(value)
            output.flush()
            os.fsync(output.fileno())
        os.replace(temporary, path)
        directory = os.open(path.parent, os.O_RDONLY | os.O_DIRECTORY)
        try:
            os.fsync(directory)
        finally:
            os.close(directory)
    finally:
        if os.path.exists(temporary):
            os.unlink(temporary)

def json_bytes(value: object) -> bytes:
    return (json.dumps(value, ensure_ascii=False, indent=2) + "\n").encode("utf-8")

def subscription_headers():
    # Keep all client display names fixed; accounting remains private to the panel.
    return {
        'Profile-Title': 'base64:' + base64.b64encode(SUBSCRIPTION_TITLE.encode('utf-8')).decode('ascii'),
        'Profile-Update-Interval': '6',
        'Content-Disposition': 'attachment; filename="Singlite Proxy.yaml"; filename*=UTF-8\'\'' + quote(SUBSCRIPTION_TITLE + '.yaml', safe=''),
    }

def hostname(value: object, field: str, *, optional: bool = False,
             allow_ip: bool = False) -> str:
    if not isinstance(value, str):
        raise ApiError(400, f"{field} 必须是字符串")
    value = value.strip().rstrip(".")
    if not value and optional:
        return ""
    if allow_ip:
        try:
            return str(ipaddress.ip_address(value))
        except ValueError:
            pass
    try:
        value = value.encode("idna").decode("ascii").lower()
    except UnicodeError:
        raise ApiError(400, f"{field} 格式无效") from None
    if len(value) > 253 or not re.fullmatch(
        r"(?=.{1,253}$)(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)*"
        r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?", value
    ):
        raise ApiError(400, f"{field} 请填写域名，不含协议、路径或端口")
    if not allow_ip:
        try:
            ipaddress.ip_address(value)
        except ValueError:
            pass
        else:
            raise ApiError(400, f"{field} 请填写域名")
    return value

class Panel:
    def __init__(self,data_dir=None,runner=None):
        self.data_dir=Path(data_dir or os.environ.get('SINGLITE_DATA_DIR','/var/lib/singlite'))
        self.data_dir.mkdir(mode=0o700,parents=True,exist_ok=True);os.chmod(self.data_dir,0o700)
        if (self.data_dir/'control.sqlite').exists():raise ValueError('此目录包含旧多 VPS 版数据，请保留备份并在全新环境部署单机版')
        self.admin_path=self.data_dir/'admin.json';self.port=int(os.environ.get('SINGLITE_PORT','8787'))
        self.static_dir=Path(__file__).resolve().parent.parent/'dist'
        self.lock=threading.RLock();self.sessions={};self.attempts={};self.cpu_previous=None
        self.control=Controller(self.data_dir,hostname,os.environ.get('SINGLITE_PUBLIC_HOST',os.environ.get('SINGLITE_PANEL_DOMAIN','')))
        self.conversions=Converter(self.control)
        self.runtime=Runtime(self.control,binary=os.environ.get('SINGLITE_SING_BOX','/opt/singlite/bin/sing-box'),stats_binary=os.environ.get('SINGLITE_STATS','/opt/singlite/bin/singbox-stats'),runner=runner)

    def init_admin(self, username: object, password: object) -> None:
        if not isinstance(username, str) or not re.fullmatch(r"[A-Za-z0-9_.-]{3,64}", username):
            raise ValueError("Username must be 3–64 ASCII letters, digits, dots, underscores or hyphens")
        if not isinstance(password, str) or not 6 <= len(password) <= 1024:
            raise ValueError("Password must contain 6–1024 characters")
        with self.lock:
            if self.admin_path.exists():
                raise ValueError("Administrator already exists; refusing to replace credentials")
            salt = secrets.token_bytes(16)
            key = hashlib.scrypt(password.encode(), salt=salt, n=16384, r=8, p=1)
            atomic_write(self.admin_path, json_bytes({"username": username,
                         "salt": salt.hex(), "hash": key.hex(), "algorithm": "scrypt-v1"}))

    def authenticate(self, username: object, password: object, client: str) -> tuple[str, str]:
        with self.lock:
            now = time.monotonic()
            # Limit both one source address and the whole panel to cap distributed guessing.
            for key, limit in ((client, 8), ("*", 40)):
                attempts = [item for item in self.attempts.get(key, []) if now - item < 300]
                self.attempts[key] = attempts
                if len(attempts) >= limit:
                    raise ApiError(429, "登录尝试过多，请 5 分钟后重试")
            self.attempts[client].append(now)
            self.attempts["*"].append(now)
            if not self.admin_path.exists():
                raise ApiError(409, "管理员尚未初始化，请在服务器上运行初始化命令")
            if not isinstance(username, str) or not isinstance(password, str) or len(password) > 1024:
                raise ApiError(401, "用户名或密码不正确")
            admin = json.loads(self.admin_path.read_text("utf-8"))
            computed = hashlib.scrypt(password.encode(), salt=bytes.fromhex(admin["salt"]),
                                      n=16384, r=8, p=1).hex()
            if not (hmac.compare_digest(computed, admin["hash"]) and
                    hmac.compare_digest(username.encode(), admin["username"].encode())):
                raise ApiError(401, "用户名或密码不正确")
            self.attempts.pop(client, None)
            self.clean_sessions()
            token, csrf = secrets.token_urlsafe(32), secrets.token_urlsafe(32)
            self.sessions[token] = {"csrf": csrf, "created": now}
            return token, csrf

    def clean_sessions(self) -> None:
        now = time.monotonic()
        self.sessions = {key: session for key, session in self.sessions.items()
                         if now - session["created"] < SESSION_TTL}
        # Bound memory for many unique remote sources.
        self.attempts = {key: [item for item in entries if now - item < 300]
                         for key, entries in self.attempts.items()
                         if entries and now - entries[-1] < 300}

    def session(self, token: str) -> dict | None:
        with self.lock:
            self.clean_sessions()
            return self.sessions.get(token)

    def state(self):
        memory=None;cpu=None
        try:
            values=dict(re.findall(r'^(\w+):\s+(\d+)',Path('/proc/meminfo').read_text(),re.M))
            total=int(values['MemTotal'])*1024;memory={'used':total-int(values['MemAvailable'])*1024,'total':total}
            parts=list(map(int,Path('/proc/stat').read_text().splitlines()[0].split()[1:9]));total_ticks=sum(parts);idle=parts[3]+parts[4]
            if self.cpu_previous and total_ticks>self.cpu_previous[0]:cpu=round(100*(1-(idle-self.cpu_previous[1])/(total_ticks-self.cpu_previous[0])),1)
            self.cpu_previous=(total_ticks,idle)
        except (OSError,ValueError,KeyError,IndexError):pass
        return {'mode':'live',**self.control.state(),'conversions':self.conversions.summaries(),'core':self.runtime.status(),'machine':{'hostname':socket.gethostname(),'cpu':cpu,'memory':memory}}

    def mutate(self,method,path,payload):
        if path=='/api/conversions' or path.startswith('/api/conversions/'):
            return self.conversions.api(method,path,payload)
        if path.endswith('/reset-traffic'):
            if not self.runtime.lock.acquire(timeout=1):raise ApiError(409,'正在采样，请稍后重置流量')
            try:
                try:self.runtime.collect()
                except (OSError,ValueError,RuntimeError,subprocess.SubprocessError):raise ApiError(409,'统计暂不可用，恢复后再重置流量') from None
                data=self.control.api(method,path,payload)
            finally:self.runtime.lock.release()
        elif path=='/api/core' and method=='POST':
            if set(payload)!={'action'} or payload['action'] not in ('restart','stop'):raise ApiError(400,'请选择重启或停止')
            self.control.running(payload['action']=='restart');self.runtime.force=True;data={'ok':True}
        else:
            if path.startswith('/api/nodes') and isinstance(payload.get('port'),int) and payload['port'] in {w['port'] for w in list(self.runtime.workers.values())}:
                raise ApiError(409,'该端口正在用于本机节点统计，请选择另一个监听端口')
            data=self.control.api(method,path,payload)
        self.runtime.wake.set();return data

    def close(self):
        self.runtime.close();self.control.db.close()


class Handler(BaseHTTPRequestHandler):
    server_version='Singlite'
    sys_version=''
    protocol_version='HTTP/1.1'
    @property
    def app(self):return self.server.app

    def log_message(self, format: str, *args) -> None:
        # Avoid recording raw request paths or request bodies in the panel journal.
        sys.stderr.write(f"{self.address_string()} {self.command} {getattr(self, 'response_code', '-')}\n")

    def send_response(self, code, message=None):
        self.response_code = code
        super().send_response(code, message)

    def cookie_token(self) -> str:
        try:
            cookie = http.cookies.SimpleCookie(self.headers.get("Cookie", ""))
            return cookie[COOKIE_NAME].value if COOKIE_NAME in cookie else ""
        except http.cookies.CookieError:
            return ""

    def secure_request(self) -> bool:
        forced = os.environ.get("SINGLITE_COOKIE_SECURE", "auto").lower()
        if forced in ("1", "true", "yes"):
            return True
        if forced in ("0", "false", "no"):
            return False
        try:
            loopback = ipaddress.ip_address(self.client_address[0]).is_loopback
        except ValueError:
            loopback = False
        return loopback and self.headers.get("X-Forwarded-Proto", "").lower() == "https"

    def session_cookie(self, token: str, *, expire: bool = False) -> str:
        value = f"{COOKIE_NAME}={token}; Path=/; HttpOnly; SameSite=Strict; Max-Age={0 if expire else SESSION_TTL}"
        return value + ("; Secure" if self.secure_request() else "")

    def json_response(self, status: int, data: object, *, cookie: str | None = None) -> None:
        body = json_bytes(data)
        self.send_response(status)
        self.send_header("Content-Type", "application/json; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.security_headers()
        if cookie:
            self.send_header("Set-Cookie", cookie)
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def raw_response(self, status, body, mime, headers=None):
        self.send_response(status)
        self.send_header('Content-Type', mime)
        self.send_header('Content-Length', str(len(body)))
        self.send_header('Cache-Control', 'no-store')
        self.security_headers()
        for key, value in (headers or {}).items(): self.send_header(key, value)
        self.end_headers()
        if self.command != 'HEAD': self.wfile.write(body)

    def security_headers(self) -> None:
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("X-Frame-Options", "DENY")
        self.send_header("Referrer-Policy", "same-origin")

    def read_json(self) -> dict:
        if self.headers.get("Transfer-Encoding"):
            self.close_connection = True
            raise ApiError(400, "不支持分块请求体")
        try:
            length = int(self.headers.get("Content-Length", "0"))
        except ValueError:
            self.close_connection = True
            raise ApiError(400, "请求长度无效") from None
        if not 0 <= length <= MAX_BODY:
            self.close_connection = True
            raise ApiError(413, "请求内容过大")
        if length == 0:
            return {}
        if self.headers.get_content_type() != "application/json":
            self.close_connection = True
            raise ApiError(415, "请使用 application/json")
        try:
            raw = self.rfile.read(length)
            if len(raw) != length:
                raise ValueError
            data = json.loads(raw)
            if not isinstance(data, dict):
                raise ValueError
            return data
        except (ValueError, UnicodeError):
            raise ApiError(400, "请求必须为有效的 JSON 对象") from None

    def dispatch(self):
        path=urlsplit(self.path).path
        if path.startswith('/convert/') and self.command in ('GET','HEAD'):
            match=re.fullmatch(r'/convert/([A-Za-z0-9_-]{43})/clash\.yaml',path)
            if not match:raise ApiError(404,'订阅不存在')
            content=self.app.conversions.subscription(match[1],'clash.yaml')
            self.raw_response(200,content.encode(),'text/yaml; charset=utf-8',subscription_headers())
            return
        if path.startswith('/sub/') and self.command in ('GET','HEAD'):
            match=re.fullmatch(r'/sub/([A-Za-z0-9_-]{43})/clash\.yaml',path)
            if not match:raise ApiError(404,'订阅不存在')
            content,_=self.app.control.subscription(match[1])
            self.raw_response(200,content.encode(),'text/yaml; charset=utf-8',subscription_headers())
            return
        if not path.startswith('/api/'):
            if self.command not in ('GET','HEAD'):raise ApiError(405,'请求方法不支持')
            self.static(path);return
        if self.command in ('POST','PUT','DELETE','PATCH') and self.headers.get('Origin'):
            try:
                origin=urlsplit(self.headers['Origin']);valid=origin.scheme in ('http','https') and not origin.username and origin.netloc.lower()==self.headers.get('Host','').lower()
            except ValueError:valid=False
            if not valid:self.close_connection=True;raise ApiError(403,'不允许来自其他站点的请求')
        token=self.cookie_token();session=self.app.session(token)
        if self.command=='GET' and path=='/api/bootstrap':
            self.json_response(200,{'mode':'live','edition':'single','authenticated':session is not None,'setupRequired':not self.app.admin_path.exists(),**({'csrf':session['csrf']} if session else {})});return
        if self.command=='GET' and path=='/api/health':
            ready=not self.app.control.running() or self.app.runtime.status()['accounting']=='ok'
            self.json_response(200 if ready else 503,{'ok':ready,'edition':'single'});return
        if self.command=='POST' and path=='/api/login':
            p=self.read_json();token,csrf=self.app.authenticate(p.get('username'),p.get('password'),self.client_address[0])
            self.json_response(200,{'csrf':csrf},cookie=self.session_cookie(token));return
        if session is None:self.close_connection=True;raise ApiError(401,'请先登录')
        if self.command in ('POST','PUT','DELETE','PATCH'):
            if not hmac.compare_digest(self.headers.get('X-CSRF-Token','').encode(),session['csrf'].encode()):self.close_connection=True;raise ApiError(403,'会话校验失败，请刷新页面后重试')
            payload=self.read_json()
        else:payload={}
        if self.command=='POST' and path=='/api/logout':
            with self.app.lock:self.app.sessions.pop(token,None)
            self.json_response(200,{'ok':True},cookie=self.session_cookie('',expire=True));return
        if self.command=='GET' and path=='/api/state':data=self.app.state()
        elif self.command=='GET' and path=='/api/logs':data=self.app.runtime.logs()
        elif self.command=='GET' and (path=='/api/conversions' or path.startswith('/api/conversions/')):data=self.app.conversions.api(self.command,path,payload)
        elif self.command in ('POST','PUT','DELETE'):data=self.app.mutate(self.command,path,payload)
        else:
            data=self.app.control.api(self.command,path,payload)
            if path.endswith('/links'):
                status=self.app.runtime.status();data['warning']='' if status['ready'] else status['error'] or ('核心已暂停' if not self.app.control.running() else '本机核心正在应用或统计暂不可用，请稍后确认')
        self.json_response(200,data)

    def static(self, path: str) -> None:
        path = unquote(path)
        if "\x00" in path or "\\" in path or any(part.startswith(".") for part in path.split("/") if part):
            raise ApiError(404, "页面不存在")
        root = self.app.static_dir.resolve()
        candidate = (root / path.lstrip("/")).resolve()
        if not candidate.is_relative_to(root):
            raise ApiError(404, "页面不存在")
        if not candidate.is_file():
            if Path(path).suffix:
                raise ApiError(404, "文件不存在")
            candidate = root / "index.html"
        if not candidate.is_file():
            raise ApiError(503, "前端文件缺失，请重新安装 dist 静态文件")
        body = candidate.read_bytes()
        self.send_response(200)
        mime = mimetypes.guess_type(str(candidate))[0] or "application/octet-stream"
        self.send_header("Content-Type", mime + ("; charset=utf-8" if mime.startswith("text/") else ""))
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-cache" if candidate.name == "index.html" else "public, max-age=3600")
        self.security_headers()
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(body)

    def handle_request(self) -> None:
        try:
            self.dispatch()
        except (ApiError, ControlError) as error:
            try: self.json_response(error.status, {"error": error.message})
            except (BrokenPipeError, ConnectionResetError): self.close_connection = True
        except (BrokenPipeError, ConnectionResetError, TimeoutError):
            self.close_connection = True
        except Exception as error:
            # Do not put configs, tokens or request bodies into logs or error responses.
            sys.stderr.write(f"Singlite internal error: {type(error).__name__}\n")
            self.close_connection = True
            self.json_response(500, {"error": "服务器内部错误，请检查数据文件和服务权限"})

    def setup(self) -> None:
        super().setup()
        self.connection.settimeout(20)

    do_GET=do_POST=do_PUT=do_DELETE=do_PATCH=do_HEAD=handle_request

class PanelServer(ThreadingHTTPServer):
    daemon_threads=True
    allow_reuse_address=True
    def __init__(self,address,app):
        self.app=app;super().__init__(address,Handler)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--init-admin',action='store_true')
    args=parser.parse_args();app=None;server=None
    try:
        app=Panel()
        if args.init_admin:
            raw=sys.stdin.read(MAX_BODY+1)
            if len(raw)>MAX_BODY:raise ValueError('Input too large')
            p=json.loads(raw)
            if not isinstance(p,dict):raise ValueError('Input must be an object')
            app.init_admin(p.get('username'),p.get('password'));print('Administrator initialized.');return 0
        server=PanelServer((os.environ.get('SINGLITE_BIND','127.0.0.1'),app.port),app)
        def stop(*_):threading.Thread(target=server.shutdown,daemon=True).start()
        signal.signal(signal.SIGTERM,stop);signal.signal(signal.SIGINT,stop)
        app.runtime.start();print(f'Singlite Single listening on 127.0.0.1:{app.port}',flush=True)
        server.serve_forever(poll_interval=.3);return 0
    except (ValueError,OSError,ApiError,ControlError) as error:
        print('Singlite startup failed: '+str(error),file=sys.stderr);return 1
    finally:
        if server:server.server_close()
        if app:app.close()

if __name__=='__main__':raise SystemExit(main())
