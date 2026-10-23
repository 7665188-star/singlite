#!/usr/bin/env bash
# Single-machine panel, core and accounting in one installation.
set -Eeuo pipefail
umask 077
SOURCE_DIR="$(cd -- "$(dirname -- "${BASH_SOURCE[0]}")" && pwd -P)"
MODE="${1:---with-caddy}"
FRESH=1
WORK_DIR=""
PANEL_STOPPED=0
PANEL_WAS_ACTIVE=0
cleanup(){
 rc=$?;trap - EXIT;set +e
 if [[ "$rc" != 0 && "$PANEL_STOPPED" == 1 && "$PANEL_WAS_ACTIVE" == 1 ]];then systemctl start singlite-panel;fi
 [[ -z "$WORK_DIR" ]] || rm -rf -- "$WORK_DIR"
 exit "$rc"
}
trap cleanup EXIT
fail(){ printf '\n错误：%s\n' "$*" >&2;exit 1; }
check_ports(){
 python3 - "$@" <<'PYPORTS'
import errno,socket,subprocess,sys
purpose=sys.argv[1]
ports=[int(value) for value in sys.argv[2:]]
conflicts={}
for port in ports:
 addresses=[(socket.AF_INET,'127.0.0.1')] if purpose=='panel' else [(socket.AF_INET,'0.0.0.0'),(socket.AF_INET6,'::')]
 for family,address in addresses:
  try:
   with socket.socket(family,socket.SOCK_STREAM) as listener:
    listener.setsockopt(socket.SOL_SOCKET,socket.SO_REUSEADDR,1)
    if family==socket.AF_INET6:listener.setsockopt(socket.IPPROTO_IPV6,socket.IPV6_V6ONLY,1)
    listener.bind((address,port))
  except OSError as error:
   if family==socket.AF_INET6 and error.errno in (errno.EAFNOSUPPORT,errno.EPROTONOSUPPORT,errno.EADDRNOTAVAIL):continue
   if error.errno==errno.EADDRINUSE:
    conflicts.setdefault(port,[]).append('IPv6' if family==socket.AF_INET6 else 'IPv4')
   else:raise SystemExit(f'无法检测 TCP {port}（{address}）：{error.strerror}。请检查权限和本机网络配置。')
if conflicts:
 print('\n错误：安装所需端口已被占用：',file=sys.stderr)
 for port,families in conflicts.items():print(f'  TCP {port}（'+', '.join(families)+'）',file=sys.stderr)
 query='( '+' or '.join('sport = :'+str(port) for port in conflicts)+' )'
 try:
  result=subprocess.run(['ss','-H','-ltnp',query],capture_output=True,text=True,timeout=5)
  if result.returncode==0 and result.stdout.strip():print('当前监听进程：\n'+result.stdout.strip(),file=sys.stderr)
 except (OSError,subprocess.SubprocessError):pass
 print('查看命令：ss -ltnp '+repr(query),file=sys.stderr)
 if purpose=='web':
  print('自带 Caddy 需要 TCP 80、443。已有网站请使用 bash install.sh --existing-proxy，并按教程配置 HTTPS 反代；需要自带 HTTPS 时，请确认占用服务用途后释放端口，再重新运行 --with-caddy。',file=sys.stderr)
 else:print('127.0.0.1:8787 是面板后端端口，请确认占用程序用途后处理冲突；--existing-proxy 同样需要这个端口。',file=sys.stderr)
 raise SystemExit(1)
PYPORTS
}
case "$MODE" in
 --with-caddy|--existing-proxy) HTTPS_MODE="$MODE";;
 --resume|--resume-existing-proxy|--upgrade) FRESH=0;;
 -h|--help) cat <<'EOF'
Singlite Single · 单机版（Debian12+/Ubuntu22.04+，amd64/arm64）
  bash install.sh --with-caddy       全新安装面板、sing-box 和自动 HTTPS
  bash install.sh --existing-proxy   全新安装，使用现有 HTTPS 反代
  bash install.sh --resume           继续中断的单机版安装
  bash install.sh --resume-existing-proxy 继续安装并使用已有反代
  bash install.sh --upgrade          升级已有单机版，保留用户与用量
登录网页直接创建节点与用户，不需要其他安装脚本或接入步骤。
EOF
 exit 0;;
 *)fail '参数无效，请运行 bash install.sh --help';;
esac
[[ "$EUID" == 0 && $# -le 1 ]]||fail '请使用 root 或 sudo 运行。'
[[ -d /run/systemd/system ]]||fail '需要正常运行 systemd 的 VPS。'
source /etc/os-release
case "${ID:-}" in debian)[[ "${VERSION_ID%%.*}" -ge 12 ]]||fail '需要 Debian12+';;ubuntu)[[ "${VERSION_ID%%.*}" -ge 22 ]]||fail '需要 Ubuntu22.04+';;*)fail '只支持 Debian/Ubuntu';;esac
[[ -r /dev/tty && -w /dev/tty ]]||fail '请在交互式 SSH 终端中运行。'
for name in server/panel.py server/control.py server/core.py server/converter.py dist/index.html dist/app.js dist/styles.css deploy/singlite-panel.service deploy/singlite-node@.service deploy/singlite-web.service deploy/Caddyfile scripts/build-singbox.sh scripts/singbox-stats.go scripts/render_guide.py scripts/package.py scripts/reset-admin.py README.md;do
 [[ -f "$SOURCE_DIR/$name" ]]||fail "源码包不完整：$name"
done
if command -v flock >/dev/null;then
 install -d -m 0755 /run/lock
 exec 9>/run/lock/singlite-install.lock
 flock -n 9||fail '另一个安装进程仍在运行，请先等待它结束或重新连接其 tmux 会话。'
fi
if [[ "$FRESH" == 1 ]];then
 for path in /opt/singlite /etc/singlite /var/lib/singlite;do [[ ! -e "$path" && ! -L "$path" ]]||fail "$path 已存在。中断的单机版请用 --resume；已有安装请先备份，不会自动覆盖。";done
 for path in /opt/singlite-agent /etc/singlite-agent /var/lib/singlite-agent;do [[ ! -e "$path" ]]||fail '检测到旧多 VPS 版节点，请保留数据并在全新环境部署单机版；安装器不会卸载旧服务。';done
 for unit in singlite-panel singlite-core singlite-web;do
  state="$(systemctl show "$unit" --property=LoadState --value 2>/dev/null||true)"
  [[ -z "$state" || "$state" == not-found ]]||fail "$unit 已存在，请确认安装状态。"
 done
 read -r -p '面板域名（例如 panel.example.com，不带 https://）：' PANEL_DOMAIN </dev/tty
else
 [[ -f /etc/singlite/edition && "$(cat /etc/singlite/edition)" == single && -f /etc/singlite/panel.env ]]||fail '未找到可恢复的单机版安装；旧多 VPS 版不使用此升级模式。'
 read -r HTTPS_MODE < /etc/singlite/install-mode
 case "$HTTPS_MODE" in --with-caddy|--existing-proxy);;*)fail '保存的 HTTPS 模式无效';;esac
 if [[ "$MODE" == --resume-existing-proxy ]];then HTTPS_MODE=--existing-proxy;fi
 if [[ "$MODE" == --upgrade && ! -s /var/lib/singlite/admin.json ]];then fail '管理员尚未初始化，请使用 --resume';fi
fi
check_install_ports(){
 if [[ "$FRESH" == 1 ]];then check_ports panel 8787;fi
 if [[ "$HTTPS_MODE" == --with-caddy ]] && ! systemctl is-active --quiet singlite-web;then check_ports web 80 443;fi
}
if command -v python3 >/dev/null;then check_install_ports;fi
apt-get update
DEBIAN_FRONTEND=noninteractive apt-get install -y --no-install-recommends python3 openssl ca-certificates curl tar tzdata
check_install_ports
if [[ "$FRESH" == 0 ]];then
 PANEL_DOMAIN="$(python3 - <<'PY'
from pathlib import Path
v=[s.split('=',1)[1] for s in Path('/etc/singlite/panel.env').read_text().splitlines() if s.startswith('SINGLITE_PANEL_DOMAIN=')]
if len(v)!=1:raise SystemExit('保存的域名无效')
print(v[0])
PY
)"
fi
PANEL_DOMAIN="$(python3 - "$PANEL_DOMAIN" <<'PY'
import ipaddress,re,sys
try:v=sys.argv[1].strip().rstrip('.').encode('idna').decode().lower()
except UnicodeError:raise SystemExit('域名格式无效')
if len(v)>253 or '.' not in v or any(not re.fullmatch(r'[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?',s) for s in v.split('.')):raise SystemExit('请填写域名，不含协议或路径')
try:ipaddress.ip_address(v)
except ValueError:pass
else:raise SystemExit('HTTPS 面板需要域名')
print(v)
PY
)"
WORK_DIR="$(mktemp -d /tmp/singlite-install.XXXXXXXX)"
# Stage and verify binaries before touching installed programs.
bash "$SOURCE_DIR/scripts/build-singbox.sh" "$WORK_DIR/core"
if [[ "$HTTPS_MODE" == --with-caddy ]];then
 if [[ "$FRESH" == 0 && -x /opt/singlite/bin/caddy ]];then CADDY_SOURCE=/opt/singlite/bin/caddy
 elif command -v caddy >/dev/null;then CADDY_SOURCE="$(command -v caddy)"
 else
  mkdir "$WORK_DIR/caddy";chmod 0755 "$WORK_DIR" "$WORK_DIR/caddy"
  (cd "$WORK_DIR/caddy" && apt-get download caddy)
  shopt -s nullglob;packages=("$WORK_DIR"/caddy/caddy_*.deb)
  [[ ${#packages[@]} == 1 ]]||fail '系统仓库没有 Caddy，可使用已有反代模式。'
  dpkg-deb -x "${packages[0]}" "$WORK_DIR/caddy/extracted"
  CADDY_SOURCE="$WORK_DIR/caddy/extracted/usr/bin/caddy"
 fi
 install -m 0755 "$CADDY_SOURCE" "$WORK_DIR/caddy-bin"
 SINGLITE_PANEL_DOMAIN="$PANEL_DOMAIN" XDG_DATA_HOME="$WORK_DIR/check" XDG_CONFIG_HOME="$WORK_DIR/check" "$WORK_DIR/caddy-bin" validate --config "$SOURCE_DIR/deploy/Caddyfile" --adapter caddyfile
fi
python3 "$SOURCE_DIR/scripts/package.py"
if [[ "$FRESH" == 0 ]];then
 printf '升级将短暂停止本机节点；SSH 请使用直连并在 tmux 内执行，避免通过正在升级的节点或 TUN。\n'
 if systemctl is-active --quiet singlite-panel;then PANEL_WAS_ACTIVE=1;fi
 if [[ -f /etc/systemd/system/singlite-panel.service ]];then PANEL_STOPPED=1;systemctl stop singlite-panel;fi
 backup="$(mktemp /root/singlite-backup-XXXXXXXX.tar.gz)"
 tar -czf "$backup" -C / opt/singlite etc/singlite var/lib/singlite
 printf '已备份：%s\n' "$backup"
fi
install -d -m 0755 /opt/singlite/server /opt/singlite/dist /opt/singlite/bin /etc/singlite
install -d -m 0700 /var/lib/singlite
if [[ "$FRESH" == 1 ]];then
 cat > /etc/singlite/panel.env <<EOF
SINGLITE_DATA_DIR=/var/lib/singlite
SINGLITE_BIND=127.0.0.1
SINGLITE_PORT=8787
SINGLITE_PANEL_DOMAIN=$PANEL_DOMAIN
SINGLITE_PUBLIC_HOST=$PANEL_DOMAIN
SINGLITE_COOKIE_SECURE=1
EOF
 chmod 0600 /etc/singlite/panel.env
 printf 'single\n' > /etc/singlite/edition
fi
printf '%s\n' "$HTTPS_MODE" > /etc/singlite/install-mode
install -m 0755 "$WORK_DIR/core/sing-box" "$WORK_DIR/core/singbox-stats" /opt/singlite/bin/
install -m 0644 "$WORK_DIR/core/core-build" /opt/singlite/core-build
[[ ! -f "$WORK_DIR/core/LICENSE" ]]||install -m 0644 "$WORK_DIR/core/LICENSE" /opt/singlite/CORE-LICENSE.txt
install -m 0644 "$SOURCE_DIR"/server/*.py /opt/singlite/server/
cp -R "$SOURCE_DIR/dist/." /opt/singlite/dist/
install -m 0644 "$SOURCE_DIR/README.md" /opt/singlite/README.md
chmod -R u+rwX,go+rX,go-w /opt/singlite
chown -R root:root /opt/singlite /etc/singlite /var/lib/singlite
if [[ ! -e /var/lib/singlite/admin.json ]];then
 SINGLITE_DATA_DIR=/var/lib/singlite SINGLITE_PUBLIC_HOST="$PANEL_DOMAIN" python3 - <<'PY'
import getpass,json,re,subprocess,sys
with open('/dev/tty','r') as tty_in,open('/dev/tty','w') as tty:
 while True:
  tty.write('管理员用户名（默认 admin）：');tty.flush();name=tty_in.readline().strip()or'admin'
  if re.fullmatch(r'[A-Za-z0-9_.-]{3,64}',name):break
  tty.write('用户名应为 3–64 位字母、数字或 _ . -。\n')
 while True:
  password=getpass.getpass('管理员密码（6–1024位）：',stream=tty)
  if 6<=len(password)<=1024 and password==getpass.getpass('再次输入密码：',stream=tty):break
  tty.write('密码长度或确认不匹配，请重试。\n')
subprocess.run([sys.executable,'/opt/singlite/server/panel.py','--init-admin'],input=json.dumps({'username':name,'password':password}),text=True,check=True)
PY
fi
install -m 0644 "$SOURCE_DIR/deploy/singlite-panel.service" "$SOURCE_DIR/deploy/singlite-node@.service" /etc/systemd/system/
# Only the panel starts at boot; it starts the core with current user permissions.
systemctl daemon-reload
systemctl disable --now singlite-core >/dev/null 2>&1||true
systemctl enable --now singlite-panel
READY=0
for attempt in {1..30};do
 if curl --fail --silent --max-time 2 --output /dev/null http://127.0.0.1:8787/api/health;then READY=1;break;fi
 sleep 1
done
[[ "$READY" == 1 ]]||fail '面板或节点统计接口启动失败。请查看 journalctl -u singlite-panel -n 60；修复后使用 --resume。'
if [[ "$HTTPS_MODE" == --with-caddy ]];then
 install -m 0755 "$WORK_DIR/caddy-bin" /opt/singlite/bin/caddy
 install -m 0644 "$SOURCE_DIR/deploy/Caddyfile" /etc/singlite/Caddyfile
 install -m 0644 "$SOURCE_DIR/deploy/singlite-web.service" /etc/systemd/system/singlite-web.service
 systemctl daemon-reload
 systemctl enable --now singlite-web
 if [[ "$FRESH" == 0 ]];then systemctl restart singlite-web;fi
fi
if [[ "$HTTPS_MODE" == --existing-proxy && -f /etc/systemd/system/singlite-web.service ]];then systemctl disable --now singlite-web;fi
PANEL_STOPPED=0
printf '\nSinglite 单机版安装完成：https://%s\n' "$PANEL_DOMAIN"
if [[ "$HTTPS_MODE" == --existing-proxy ]];then printf '请配置现有 HTTPS 站点反代到 http://127.0.0.1:8787，保留 Host、X-Forwarded-Proto 并关闭 /api/、/sub/ 与 /convert/ 缓存。\n';fi
printf '登录后直接创建节点与用户。节点公网地址可在“面板设置”修改。\n'
