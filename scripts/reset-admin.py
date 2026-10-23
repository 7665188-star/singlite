#!/usr/bin/env python3
"""Reset the controller admin through /dev/tty without putting credentials in argv."""
import getpass
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time
if os.geteuid()!=0:raise SystemExit('请使用 sudo python3 scripts/reset-admin.py')
os.umask(0o077)
path=Path('/var/lib/singlite/admin.json')
with open('/dev/tty','r') as tty_in, open('/dev/tty','w') as tty:
    while True:
        tty.write('管理员用户名（默认admin）：');tty.flush();name=tty_in.readline().strip()or'admin'
        if re.fullmatch(r'[A-Za-z0-9_.-]{3,64}',name):break
    while True:
        password=getpass.getpass('新密码（6–1024位）：',stream=tty)
        if 6<=len(password)<=1024 and password==getpass.getpass('再次输入密码：',stream=tty):break
        tty.write('长度或确认不匹配，请重试。\n')
backup=path.with_name('admin.backup.'+str(time.time_ns())+'.json')
subprocess.run(['systemctl','stop','singlite-panel'],check=True)
try:
    if path.exists():path.rename(backup)
    try:
        subprocess.run([sys.executable,'/opt/singlite/server/panel.py','--init-admin'],input=json.dumps({'username':name,'password':password}),text=True,check=True,env=dict(os.environ,SINGLITE_DATA_DIR='/var/lib/singlite'))
    except BaseException:
        if backup.exists():backup.replace(path)
        raise
finally:subprocess.run(['systemctl','start','singlite-panel'],check=True)
print('管理员已更新，原摘要已备份。')
