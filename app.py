import os, json, re, time, threading, subprocess, fnmatch, hmac, shutil, shlex, stat, zipfile
from pathlib import Path
from flask import Flask, jsonify, request, send_from_directory, Response

DATA = Path(os.environ.get("DATA_DIR", "/config"))
SETTINGS_FILE = DATA / "settings.json"
HIST = DATA / "history.json"
DEFAULTS = {
    "backup_dir": "/backups",
    "scan_dirs": [],                                  # 额外扫描 compose 文件的目录(可含未运行的项目)
    "store_paths": ["/1panel/apps/"],                 # 工作目录含这些片段 => 应用商店应用(不备份镜像)
    "compose_paths": ["/1panel/docker/compose/"],     # 含这些片段 => 编排应用(不备份镜像)
    "excludes": [],                                   # 全局排除路径/通配符,如 /data/sync*
    "mount_rules": ["syncthing:/data*", "syncthing:/sync*"],  # 镜像关键字:容器内路径通配符
    "overrides": {},
    "full_every": 7,                                  # 每隔几次增量做一次完整备份(0=每次都完整)
    "keep_full": 3,                                   # 保留最近几组(完整+其增量),0=不清理
    "schedule_enabled": False,
    "schedule_time": "03:00",
    "schedule_days": [1, 2, 3, 4, 5, 6, 7],           # 1=周一
    "schedule_apps": [],                              # 留空=全部应用
    "schedule_stop": False,
    "log_keep": 30,                                   # 日志最多保留几条,0=不清理
    "notify_enabled": False,                          # ntfy 通知
    "notify_url": os.environ.get("NOTIFY_URL", ""),   # 如 https://ntfy.example.com/topic
    "notify_on": "all",                               # all=成功失败都通知 / fail=只通知失败
    "notify_name": "",                                # 通知标题里的服务器名,留空=容器主机名
    "notify_token": "",                               # 可选: ntfy 访问令牌(Bearer)
    "scope": {},                                      # 应用名 => all(完整)|app(只备份应用,不含数据)|data(只备份数据)
    "servers": [],                                    # 其它服务器: {id,name,url,user,pass}                                  # 应用名 => store|compose|personal
}
COMPOSE_NAMES = {"docker-compose.yml", "docker-compose.yaml", "compose.yml", "compose.yaml"}
DANGEROUS_ROOTS = {"/", "/opt", "/etc", "/root", "/home", "/usr", "/bin", "/var", "/var/lib",
                    "/var/lib/docker", "/var/lib/docker/volumes", "/mnt", "/srv", "/data"}
app = Flask(__name__, static_folder="static")
JOB = {"running": False, "log": []}
LOCK = threading.Lock()


def settings():
    s = dict(DEFAULTS)
    try:
        s.update(json.loads(SETTINGS_FILE.read_text()))
    except Exception:
        pass
    return s


def log(m):
    JOB["log"].append(time.strftime("%H:%M:%S ") + m)


def run(cmd, cwd=None, ok=(0,)):
    log("$ " + " ".join(cmd)[:180])
    r = subprocess.run(cmd, cwd=cwd, capture_output=True, text=True)
    if r.returncode not in ok:
        raise RuntimeError((r.stderr or r.stdout).strip()[-400:])
    return r.stdout


@app.before_request
def auth():
    u, p = os.environ.get("AUTH_USER"), os.environ.get("AUTH_PASS")
    if not u:
        return
    a = request.authorization
    if not (a and hmac.compare_digest((a.username or "").encode(), u.encode())
            and hmac.compare_digest((a.password or "").encode(), (p or "").encode())):
        return Response("需要登录", 401, {"WWW-Authenticate": 'Basic realm="docker-backup"'})


# ---------- 扫描 ----------
def scan():
    S, apps = settings(), {}
    ids = subprocess.run(["docker", "ps", "-aq"], capture_output=True, text=True).stdout.split()
    if ids:
        for c in json.loads(subprocess.run(["docker", "inspect"] + ids, capture_output=True, text=True).stdout):
            L = c["Config"].get("Labels") or {}
            proj = L.get("com.docker.compose.project")
            name = proj or c["Name"].lstrip("/")
            a = apps.setdefault(("c:" if proj else "r:") + name, {
                "name": name, "compose": bool(proj),
                "workdir": L.get("com.docker.compose.project.working_dir", ""),
                "files": [f for f in L.get("com.docker.compose.project.config_files", "").split(",") if f],
                "store": False, "_c": []})
            a["store"] = a["store"] or L.get("createdBy") == "Apps"
            a["_c"].append(c)
    for base in S["scan_dirs"]:
        for root, dirs, files in os.walk(base):
            if root[len(base):].count("/") >= 3:
                dirs[:] = []
                continue
            hit = [f for f in files if f in COMPOSE_NAMES]
            if hit:
                n = re.sub(r"[^a-z0-9_-]", "", os.path.basename(root).lower())
                apps.setdefault("c:" + n, {"name": n, "compose": True, "workdir": root,
                                           "files": [os.path.join(root, hit[0])], "store": False, "_c": []})
                dirs[:] = []
    for a in apps.values():
        p = a["workdir"] + "/"
        a["kind"] = S["overrides"].get(a["name"]) or (
            "store" if a["store"] or any(x in p for x in S["store_paths"]) else
            "compose" if any(x in p for x in S["compose_paths"]) else "personal")
    return sorted(apps.values(), key=lambda a: a["name"])


def find_app(name):
    return next((a for a in scan() if a["name"] == name), None)


def self_stats():
    """本程序自己容器里 /backups 和 /config 这两个挂载点的 (设备号,inode)。
    用来判断某个候选路径是不是"其实就是备份目录本身"(哪怕是通过 /opt 等别的挂载绕道看到的),
    不依赖执行 docker 命令是否成功,不受容器网络模式/hostname 影响,每次都重新判断不会被一次性失败锁死。"""
    out = []
    for p in ("/backups", str(DATA)):
        try:
            st = os.stat(p)
            out.append((st.st_dev, st.st_ino))
        except OSError:
            pass
    return out


def under(p, bases):
    return any(p == b or p.startswith(b.rstrip("/") + "/") for b in bases)


def find_self(root, stats, max_depth=3):
    """在 root 底下最多找 max_depth 层,看有没有子目录其实就是备份目录本身(设备号+inode 相同)。
    命中就返回该子目录的绝对路径列表,不再往里递归(避免扫描备份目录自己的海量文件)。"""
    hits, root = [], root.rstrip("/") or "/"
    if not stats:
        return hits

    def walk(p, depth):
        try:
            st = os.stat(p)
        except OSError:
            return
        if (st.st_dev, st.st_ino) in stats:
            hits.append(p)
            return
        if depth >= max_depth:
            return
        try:
            entries = list(os.scandir(p))
        except OSError:
            return
        for e in entries:
            try:
                if e.is_dir(follow_symlinks=False):
                    walk(e.path, depth + 1)
            except OSError:
                pass
    walk(root, 0)
    return hits


def plan_paths(a, S):
    paths, excl = [], list(S["excludes"])
    rules = [r.split(":", 1) for r in S["mount_rules"] if ":" in r]
    if a["workdir"]:
        if a["workdir"].rstrip("/") in DANGEROUS_ROOTS:
            log(f"[{a['name']}] 工作目录是 {a['workdir']},范围过大(可能是 compose 文件没放在专属子文件夹里),已跳过,不会整个打包。建议把该应用的 compose 文件移到自己的子文件夹后重新部署。")
        else:
            paths.append(a["workdir"])
    for c in a["_c"]:
        img = c["Config"]["Image"].lower()
        for m in c.get("Mounts", []):
            src, dst = m.get("Source", ""), m.get("Destination", "")
            if not src or m["Type"] not in ("bind", "volume"):
                continue
            if src.startswith(("/var/run", "/run", "/proc", "/sys", "/dev")) or src in ("/etc/localtime", "/etc/timezone"):
                continue
            if src.rstrip("/") in DANGEROUS_ROOTS:
                log(f"[{a['name']}] 挂载源 {src} 范围过大,已跳过,不会整个打包")
                continue
            if any(k.lower() in img and fnmatch.fnmatch(dst, g) for k, g in rules):
                excl.append(src)
                continue
            paths.append(src)
    out = []
    for p in sorted(set(paths)):
        if not any(p == q or p.startswith(q.rstrip("/") + "/") for q in out):
            out.append(p)
    out = [p for p in out if os.path.exists(p)]
    stats = self_stats()
    for p in out:
        for hit in find_self(p, stats):
            log(f"检测到 {hit} 就是本程序自己的备份/设置目录,已自动跳过")
            excl.append(hit)
    return out, excl


# ---------- 备份 ----------
def chain_info(appdir):
    out = []
    for m in sorted(appdir.glob("*/meta.json")):
        try:
            out.append(json.loads(m.read_text()))
        except Exception:
            pass
    return out


def image_ids(images):
    r = subprocess.run(["docker", "image", "inspect", "-f", "{{.Id}}"] + images, capture_output=True, text=True)
    return dict(zip(images, r.stdout.split()))


def prune(appdir, keep, state):
    if keep < 1:
        return
    metas = chain_info(appdir)
    fulls = [m["time"] for m in metas if m.get("type", "full") == "full"]
    for old in fulls[:-keep]:
        for m in metas:
            if m["time"] == old or m.get("base") == old:
                shutil.rmtree(appdir / m["time"], ignore_errors=True)
                log("清理旧备份 " + m["time"])
        (state / f"{old}.snar").unlink(missing_ok=True)


def do_backup(name, stop, mode="auto"):
    S = settings()
    a = find_app(name)
    if not a:
        raise RuntimeError("找不到应用 " + name)
    appdir = Path(S["backup_dir"]) / re.sub(r"[^\w.-]", "_", name)
    state = appdir / ".state"
    state.mkdir(parents=True, exist_ok=True)
    metas = chain_info(appdir)
    fulls = [m for m in metas if m.get("type", "full") == "full"]
    base = fulls[-1] if fulls else None
    incs = [m for m in metas if base and m.get("type") == "inc" and m.get("base") == base["time"]]
    scope = (S.get("scope") or {}).get(name, "all")
    if scope not in ("all", "app", "data"):
        scope = "all"
    images = []
    if a["kind"] == "personal" and scope != "data":
        images = sorted({c["Config"]["Image"] for c in a["_c"]})
        if not images and a["files"]:
            images = run(["docker", "compose", "-f", a["files"][0], "config", "--images"], cwd=a["workdir"]).split()
        images = [i for i in images if subprocess.run(["docker", "image", "inspect", i], capture_output=True).returncode == 0]
    ids = image_ids(images) if images else {}
    inc = bool(mode == "auto" and base and S["full_every"] > 0 and len(incs) < S["full_every"]
               and (state / f"{base['time']}.snar").exists() and ids == base.get("image_ids", {})
               and base.get("scope", "all") == scope)
    ts = time.strftime("%Y%m%d-%H%M%S")
    d = appdir / ts
    d.mkdir(parents=True)
    bts = base["time"] if inc else ts
    snar, tmp = state / f"{bts}.snar", state / f"{bts}.tmp"
    tmp.unlink(missing_ok=True)
    if inc:
        shutil.copy(snar, tmp)
    running = [c["Name"].lstrip("/") for c in a["_c"] if c["State"]["Running"]]
    if stop and running:
        run(["docker", "stop"] + running)
    try:
        paths, excl = plan_paths(a, S)
        if scope != "all":
            dp, de, dn = plan_data(a, S)
            for x in dn:
                log(f"[{name}] {x}")
            if scope == "data":
                if not dp:
                    raise RuntimeError(f"{name} 没有可备份的数据(没有挂载目录/命名卷,或路径没挂载进本程序容器)")
                paths, excl = dp, de
            else:  # 只备份应用: 去掉数据目录/卷(工作目录里嵌套的数据目录用排除规则去掉)
                excl += dp
                paths = [p for p in paths if not any(p == q or p.startswith(q.rstrip("/") + "/") for q in dp)]
        log(f"[{name}] {'增量' if inc else '完整'}备份, 范围={ {'all': '应用+数据', 'app': '只应用(不含数据)', 'data': '只数据'}[scope] }, 类型={a['kind']}, 路径: {', '.join(paths) or '无'}")
        if excl:
            log(f"[{name}] 排除: {', '.join(sorted(set(excl)))}")
        if not paths and not inc:
            raise RuntimeError(f"{name} 没有可备份的路径(工作目录和挂载目录在本程序容器里都看不到,或被排除规则跳过),已取消,没有生成空备份")
        if paths:
            run(["tar", "-czpf", str(d / "data.tar.gz"), "-C", "/", "--no-check-device", f"--listed-incremental={tmp}"]
                + [f"--exclude={e.lstrip('/')}" for e in excl] + [p.lstrip("/") for p in paths], ok=(0, 1))
            if not inc:  # 完整备份却是个空压缩包(约 45 字节): 说明所有路径都被排除了或读不到,不能当成功
                n = subprocess.run(["tar", "-tzf", str(d / "data.tar.gz")], capture_output=True, text=True).stdout.count("\n")
                if n == 0:
                    raise RuntimeError(f"{name} 的备份结果是空的(路径: {', '.join(paths)})。通常是排除规则把它们全排除了,或本程序容器读不到这些路径,请看上面的「排除」日志")
        if not inc and images:
            run(["docker", "save", "-o", str(d / "images.tar")] + images)
        elif a["kind"] != "personal":
            log(f"[{name}] 商店/编排应用,不含镜像")
        (d / "meta.json").write_text(json.dumps({
            "name": name, "kind": a["kind"], "compose": a["compose"], "workdir": a["workdir"], "files": a["files"],
            "paths": paths, "images": [] if inc else images, "image_ids": ids, "time": ts,
            "type": "inc" if inc else "full", "base": bts, "scope": scope, "arch": arch(), "containers": a["_c"]}, ensure_ascii=False, indent=1))
        write_scripts(appdir, json.loads((d / "meta.json").read_text()),
                      ([base["time"]] + [m["time"] for m in incs] if inc else []) + [ts])
        if tmp.exists():
            os.replace(tmp, snar)
        log(f"[{name}] 完成 -> {d}")
    except Exception:
        shutil.rmtree(d, ignore_errors=True)
        tmp.unlink(missing_ok=True)
        raise
    finally:
        if stop and running:
            run(["docker", "start"] + running)
    prune(appdir, S["keep_full"], state)


# ---------- 还原 ----------
def arch():
    return subprocess.run(["docker", "version", "--format", "{{.Server.Arch}}"], capture_output=True, text=True).stdout.strip()


RESTORE_TEMPLATE = (Path(__file__).parent / "restore.sh.tpl").read_text()


def write_scripts(appdir, meta, chain):
    """在备份目录里生成独立的 restore.sh(和 containers.sh),脱离本程序也能还原"""
    d, q = appdir / meta["time"], shlex.quote
    cs = meta["containers"]
    nets = sorted({n for c in cs for n in ((c.get("NetworkSettings") or {}).get("Networks") or {})
                   if n not in ("bridge", "host", "none") and not (meta["compose"] and n.startswith(meta["name"] + "_"))})
    scope = meta.get("scope", "all")
    if scope == "data":  # 只有数据: 还原数据后启动原来的容器(应用本身需已用源文件部署好)
        names = " ".join(q(c["Name"].lstrip("/")) for c in cs)
        (d / "containers.sh").write_text("#!/bin/sh\necho '这是「仅数据」备份: 数据已还原到原位置'\n"
                                         + (f"docker start {names} || echo '容器还不存在,请先用源文件部署好应用再启动'\n" if names else ""))
    elif not meta["compose"]:
        lines = ["#!/bin/sh", "set -e"]
        for c in cs:
            lines.append("docker rm -f %s >/dev/null 2>&1 || true" % q(c["Name"].lstrip("/")))
            lines.append(" ".join(q(x) for x in ["docker"] + run_args(c)))
        (d / "containers.sh").write_text("\n".join(lines) + "\n")
    t = RESTORE_TEMPLATE
    for k, v in {"@@NAME@@": q(meta["name"]), "@@CHAIN@@": " ".join(chain), "@@BASE@@": q(meta.get("base", meta["time"])),
                 "@@WORKDIR@@": q(meta["workdir"]), "@@ARCH@@": meta.get("arch", ""),
                 "@@COMPOSE@@": "1" if meta["compose"] and meta["files"] and scope != "data" else "0",
                 "@@FILES@@": " ".join(q(f) for f in meta["files"]),
                 "@@CONTAINERS@@": " ".join(q(c["Name"].lstrip("/")) for c in cs),
                 "@@NETS@@": " ".join(q(n) for n in nets)}.items():
        t = t.replace(k, v)
    (d / "restore.sh").write_text(t)
    os.chmod(d / "restore.sh", 0o755)
    (appdir.parent / "README-还原说明.txt").write_text(
        "还原任意一个备份: 进入 应用名/时间戳/ 目录,以 root 运行  sh restore.sh\n"
        "换环境/换路径: sh restore.sh --map 旧路径前缀=新路径前缀\n"
        "数据是标准 tar.gz,镜像是标准 docker save 文件,不依赖 docker-backup 和 1Panel。\n")

def run_args(c):
    cfg, hc = c["Config"], c["HostConfig"]
    img = subprocess.run(["docker", "image", "inspect", cfg["Image"]], capture_output=True, text=True)
    try:
        ic = json.loads(img.stdout)[0]["Config"]
    except Exception:
        ic = {}
    a = ["run", "-d", "--name", c["Name"].lstrip("/")]
    rp = hc.get("RestartPolicy") or {}
    if rp.get("Name"):
        a += ["--restart", rp["Name"] + (f":{rp['MaximumRetryCount']}" if rp["Name"] == "on-failure" and rp.get("MaximumRetryCount") else "")]
    for e in cfg.get("Env") or []:
        a += ["-e", e]
    for cp, binds in (hc.get("PortBindings") or {}).items():
        for b in binds or []:
            a += ["-p", (b["HostIp"] + ":" if b.get("HostIp") else "") + f"{b['HostPort']}:{cp}"]
    for m in c.get("Mounts", []):
        s = m["Source"] if m["Type"] == "bind" else m.get("Name")
        if s:
            a += ["-v", f"{s}:{m['Destination']}" + ("" if m.get("RW", True) else ":ro")]
    nm = hc.get("NetworkMode", "default")
    if nm not in ("default", "bridge"):
        a += ["--network", nm]
    if hc.get("Privileged"): a.append("--privileged")
    for x in hc.get("CapAdd") or []: a += ["--cap-add", x]
    for x in hc.get("Devices") or []: a += ["--device", f"{x['PathOnHost']}:{x['PathInContainer']}"]
    for x in hc.get("ExtraHosts") or []: a += ["--add-host", x]
    if cfg.get("User"): a += ["--user", cfg["User"]]
    if cfg.get("WorkingDir") and cfg["WorkingDir"] != ic.get("WorkingDir"): a += ["--workdir", cfg["WorkingDir"]]
    if cfg.get("Hostname") and cfg["Hostname"] != c["Id"][:12]: a += ["--hostname", cfg["Hostname"]]
    if cfg.get("Entrypoint") != ic.get("Entrypoint") and cfg.get("Entrypoint"):
        a += ["--entrypoint", cfg["Entrypoint"][0]]
        extra = cfg["Entrypoint"][1:]
    else:
        extra = []
    a.append(cfg["Image"])
    return a + extra + ((cfg.get("Cmd") or []) if cfg.get("Cmd") != ic.get("Cmd") or extra else [])


BACKUP_MOUNT = "/backups"


def do_restore(folder, ts, with_images, with_data, maps=()):
    appdir = Path(settings()["backup_dir"]) / folder
    d = appdir / ts
    if not (d / "restore.sh").exists():  # 旧版本备份没有脚本,按当前链补生成
        meta = json.loads((d / "meta.json").read_text())
        write_scripts(appdir, meta, chain_of(appdir, meta, ts))
    flags = ([] if with_images else ["--no-images"]) + ([] if with_data else ["--no-data"])
    host = os.environ.get("HOST_BACKUP_DIR")
    ok, rules = re.compile(r"/[\w./-]+"), []
    for m in maps:
        o, _, n = m.partition("=")
        o, n = o.strip().rstrip("/"), n.strip().rstrip("/")
        if not o or not n or o == n:
            continue
        if not (ok.fullmatch(o) and ok.fullmatch(n)):
            raise RuntimeError(f"路径不合法: {o} -> {n} (只能以 / 开头,只含字母数字和 . _ - /)")
        if not host and not os.path.isdir(os.path.dirname(n) or "/"):
            raise RuntimeError(f"容器内看不到 {n} 的上级目录。请在 docker-compose.yml 里挂载它,或启用宿主机模式")
        rules.append((o, n))
    for o, n in sorted(rules, key=lambda r: -len(r[0])):  # 长的规则优先
        flags += ["--map", f"{o}={n}"]
    if host:  # 宿主机模式: 进入宿主机命名空间执行,还原路径不受容器挂载限制
        try:
            rel = d.relative_to(BACKUP_MOUNT)
        except ValueError:
            raise RuntimeError("宿主机模式要求备份目录位于 /backups 之下")
        run(["nsenter", "-t", "1", "-m", "-u", "-i", "-n", "--", "sh", f"{host.rstrip('/')}/{rel}/restore.sh"] + flags)
    else:
        run(["sh", str(d / "restore.sh")] + flags)
    log(f"还原完成(时间点 {ts})" + "".join(f"\n    {o} -> {n}" for o, n in rules))


def chain_of(appdir, meta, ts):
    base = meta.get("base", ts) if meta.get("type", "full") == "inc" else ts
    return [m["time"] for m in chain_info(appdir) if (m["time"] == base or m.get("base") == base) and m["time"] <= ts]


def do_verify(folder, ts):
    appdir = Path(settings()["backup_dir"]) / folder
    meta = json.loads((appdir / ts / "meta.json").read_text())
    for t in chain_of(appdir, meta, ts):
        for f, cmd in (("data.tar.gz", ["gzip", "-t"]), ("images.tar", ["tar", "-tf"])):
            p = appdir / t / f
            if p.exists():
                run(cmd + [str(p)])
                log(f"{t}/{f} 完好")
    log(f"校验通过: {folder} {ts}")


def save_history():
    try:
        h = json.loads(HIST.read_text())
    except Exception:
        h = []
    ok = job_ok(JOB["log"])
    h.append({"time": JOB["started"], "title": JOB["title"], "ok": ok, "lines": list(JOB["log"])})
    k = settings()["log_keep"]
    if k > 0:
        h = h[-k:]
    DATA.mkdir(parents=True, exist_ok=True)
    HIST.write_text(json.dumps(h, ensure_ascii=False))


def ntfy_send(url, token, title, message, priority=3, tags=()):
    """用 ntfy 的 JSON 发布接口(POST 到根地址),标题/正文含中文也不会有请求头编码问题"""
    import urllib.request, urllib.parse
    u = urllib.parse.urlparse(url.strip())
    topic = u.path.rstrip("/").rsplit("/", 1)[-1]
    if u.scheme not in ("http", "https") or not u.netloc or not topic:
        raise RuntimeError("通知地址格式应为 https://域名/主题,例如 https://ntfy.example.com/notice")
    base = u._replace(path=u.path.rstrip("/").rsplit("/", 1)[0] + "/", query="", fragment="").geturl()
    req = urllib.request.Request(base, method="POST", data=json.dumps(
        {"topic": topic, "title": title, "message": message[:1500], "priority": priority, "tags": list(tags)},
        ensure_ascii=False).encode())
    req.add_header("Content-Type", "application/json")
    if token:
        req.add_header("Authorization", "Bearer " + token)
    try:
        with urllib.request.urlopen(req, timeout=10) as r:
            r.read()
    except urllib.error.HTTPError as e:
        raise RuntimeError(f"ntfy 返回 {e.code}: {e.read().decode(errors='ignore')[:120]}")
    except Exception as e:
        raise RuntimeError(f"连接 ntfy 失败: {e}")


def notify_name(S):
    import socket
    return S.get("notify_name") or socket.gethostname()


def job_ok(lines):
    return not any(l.split(" ", 1)[-1].startswith("错误") for l in lines)


def fmt_dur(sec):
    sec = int(sec)
    return (f"{sec // 3600}小时" if sec >= 3600 else "") + (f"{sec % 3600 // 60}分" if sec >= 60 else "") + f"{sec % 60}秒"


def notify_job():
    S = settings()
    if not (S["notify_enabled"] and S["notify_url"]):
        return
    lines = list(JOB["log"])
    ok = job_ok(lines)
    if S["notify_on"] == "fail" and ok:
        return
    body = [l.split(" ", 1)[-1] for l in lines]
    errs = [l for l in body if l.startswith("错误")]
    done = [l for l in body if "完成" in l or "通过" in l or "跳过" in l or "范围过大" in l]
    detail = errs[:5] if errs else done[-5:]
    msg = f"{JOB.get('title', '任务')}\n耗时 {fmt_dur(time.time() - JOB.get('t0', time.time()))}"
    if detail:
        msg += "\n" + "\n".join(detail)
    try:
        ntfy_send(S["notify_url"], S["notify_token"], f"{'✅' if ok else '❌'} {notify_name(S)} · {'成功' if ok else '有错误'}",
                  msg, 3 if ok else 4, ["white_check_mark" if ok else "rotating_light"])
    except Exception as e:
        print("通知发送失败:", e, flush=True)


def job(fn, items, title=""):
    if not LOCK.acquire(blocking=False):
        return False
    JOB.update(running=True, log=[], title=title, started=time.strftime("%Y-%m-%d %H:%M:%S"), t0=time.time())

    def w():
        try:
            for it in items:
                try:
                    fn(*it)
                except Exception as e:
                    log(f"错误: {it[0]}: {e}")
        finally:
            log("全部结束")
            try:
                save_history()
                notify_job()
            finally:
                JOB["running"] = False
                LOCK.release()
    threading.Thread(target=w, daemon=True).start()
    return True


# ---------- API ----------
@app.get("/")
def index():
    return send_from_directory("static", "index.html")


def last_backup(name):
    d = Path(settings()["backup_dir"]) / re.sub(r"[^\w.-]", "_", name)
    return (sorted(m.parent.name for m in d.glob("*/meta.json")) or [""])[-1]


@app.get("/api/stats")
def api_stats():
    root = Path(settings()["backup_dir"])
    size = 0
    for dp, _, fs in os.walk(root):
        for f in fs:
            try:
                size += os.path.getsize(os.path.join(dp, f))
            except OSError:
                pass
    try:
        du = shutil.disk_usage(root if root.exists() else "/")
    except OSError:
        du = None
    return jsonify(backups=len(list(root.glob("*/*/meta.json"))), size=size,
                   free=du.free if du else 0, total=du.total if du else 0)


@app.get("/api/history")
def api_history():
    try:
        return jsonify(json.loads(HIST.read_text())[::-1])
    except Exception:
        return jsonify([])


@app.post("/api/history/clear")
def api_history_clear():
    HIST.unlink(missing_ok=True)
    return jsonify(ok=True)


# ---- 多服务器: 本机作为控制台,请求转发给其它已部署本程序的服务器 ----
@app.get("/api/servers")
def api_servers():
    return jsonify([{"id": v["id"], "name": v["name"], "url": v["url"]} for v in settings()["servers"]])


@app.post("/api/servers")
def api_servers_add():
    j = request.json
    S = settings()
    url = j["url"].strip().rstrip("/")
    if not re.match(r"https?://", url):
        return jsonify(ok=False, error="地址需以 http:// 或 https:// 开头"), 400
    old = next((v for v in S["servers"] if v["id"] == j.get("id")), None)
    item = {"id": (old or {}).get("id") or os.urandom(4).hex(), "name": j["name"].strip() or url, "url": url,
            "user": j.get("user", ""), "pass": j.get("pass") or (old or {}).get("pass", "")}
    S["servers"] = [v for v in S["servers"] if v["id"] != item["id"]] + [item]
    DATA.mkdir(parents=True, exist_ok=True)
    SETTINGS_FILE.write_text(json.dumps(S, ensure_ascii=False, indent=1))
    return jsonify(ok=True, id=item["id"])


@app.post("/api/servers/delete")
def api_servers_del():
    S = settings()
    S["servers"] = [v for v in S["servers"] if v["id"] != request.json["id"]]
    SETTINGS_FILE.write_text(json.dumps(S, ensure_ascii=False, indent=1))
    return jsonify(ok=True)


@app.route("/api/remote/<sid>/<path:p>", methods=["GET", "POST"])
def api_remote(sid, p):
    import base64, urllib.request, urllib.error
    sv = next((v for v in settings()["servers"] if v["id"] == sid), None)
    if not sv or p.startswith(("remote/", "servers")):
        return jsonify(error="未知服务器"), 404
    qs = request.query_string.decode()
    req = urllib.request.Request(sv["url"] + "/api/" + p + ("?" + qs if qs else ""), method=request.method,
                                 data=request.get_data() if request.method == "POST" else None)
    req.add_header("Content-Type", "application/json")
    if sv.get("user"):
        req.add_header("Authorization", "Basic " + base64.b64encode(f"{sv['user']}:{sv.get('pass', '')}".encode()).decode())
    try:
        r = urllib.request.urlopen(req, timeout=60)
    except urllib.error.HTTPError as e:
        return Response(e.read(), e.code, content_type="application/json")
    except Exception as e:
        return jsonify(error=f"连接 {sv['name']} 失败: {e}"), 502

    def gen():  # 流式转发,备份包可能很大
        try:
            while True:
                b = r.read(1 << 20)
                if not b:
                    break
                yield b
        finally:
            r.close()
    hdr = {k: r.headers[k] for k in ("Content-Disposition", "Content-Length") if r.headers.get(k)}
    return Response(gen(), r.status, content_type=r.headers.get("Content-Type", "application/json"), headers=hdr)


@app.get("/api/apps")
def api_apps():
    return jsonify([{
        "name": a["name"], "kind": a["kind"], "compose": a["compose"], "workdir": a["workdir"],
        "last": last_backup(a["name"]), "scope": (settings().get("scope") or {}).get(a["name"], "all"), "containers": [{"name": c["Name"].lstrip("/"), "image": c["Config"]["Image"], "state": c["State"]["Status"]} for c in a["_c"]]
    } for a in scan()])


@app.route("/api/settings", methods=["GET", "POST"])
def api_settings():
    if request.method == "POST":
        DATA.mkdir(parents=True, exist_ok=True)
        s = settings()
        j = dict(request.json)
        j.pop("servers", None)
        if "notify_token" in j:  # 令牌不回传给页面: 留空=保持不变, "-"=清除
            t = (j["notify_token"] or "").strip()
            if not t:
                j.pop("notify_token")
            elif t == "-":
                j["notify_token"] = ""
        s.update(j)
        SETTINGS_FILE.write_text(json.dumps(s, ensure_ascii=False, indent=1))
    out = {k: v for k, v in settings().items() if k not in ("servers", "notify_token")}
    out["notify_token_set"] = bool(settings()["notify_token"])
    return jsonify(out)


@app.post("/api/notify/test")
def api_notify_test():
    j, S = request.json or {}, settings()
    url = (j.get("url") or S["notify_url"]).strip()
    tok = (j.get("token") or "").strip()
    tok = "" if tok == "-" else (tok or S["notify_token"])
    if not url:
        return jsonify(error="请先填写通知地址"), 400
    try:
        ntfy_send(url, tok, f"🔔 {j.get('name') or notify_name(S)} · 测试通知", "docker-backup 通知配置正常", 3, ["bell"])
    except Exception as e:
        return jsonify(error=str(e)), 502
    return jsonify(ok=True)


@app.post("/api/backup")
def api_backup():
    j = request.json
    return jsonify(ok=job(do_backup, [(n, j.get("stop", False), j.get("mode", "auto")) for n in j["names"]],
                          ("完整备份 " if j.get("mode") == "full" else "备份 ") + ", ".join(j["names"])[:60]))


def common_prefix(meta):
    ps = [p for p in (meta.get("paths") or [meta.get("workdir")]) if p]
    try:
        c = os.path.commonpath(ps) if ps else ""
    except ValueError:
        c = ""
    return "" if c in ("", "/") else c


@app.get("/api/info")
def api_info():
    return jsonify(host_mode=bool(os.environ.get("HOST_BACKUP_DIR")))


@app.get("/api/backups")
def api_backups():
    out = []
    for m in sorted(Path(settings()["backup_dir"]).glob("*/*/meta.json"), reverse=True):
        d = m.parent
        meta = json.loads(m.read_text())
        out.append({"folder": d.parent.name, "ts": d.name, "name": meta["name"], "kind": meta["kind"],
                    "size": sum(f.stat().st_size for f in d.iterdir()), "images": meta["images"],
                    "type": meta.get("type", "full"), "base": meta.get("base", d.name), "scope": meta.get("scope", "all"),
                    "paths": meta.get("paths") or [meta.get("workdir")], "common": common_prefix(meta)})
    return jsonify(out)


@app.post("/api/restore")
def api_restore():
    j = request.json
    return jsonify(ok=job(do_restore, [(j["folder"], j["ts"], j.get("images", True), j.get("data", True),
                                        j.get("maps") or [])], f"还原 {j['folder']} {j['ts']}"))


@app.post("/api/verify")
def api_verify():
    j = request.json
    return jsonify(ok=job(do_verify, [(j["folder"], j["ts"])], f"校验 {j['folder']} {j['ts']}"))


def valid_part(x):
    return isinstance(x, str) and re.fullmatch(r"[\w.-]+", x) is not None and x.strip(".") != ""


@app.post("/api/delete")
def api_delete():
    j = request.json
    if not (valid_part(j.get("folder")) and valid_part(j.get("ts"))):
        return jsonify(ok=False), 400
    appdir = Path(settings()["backup_dir"]) / j["folder"]
    ts = j["ts"]
    if not (appdir / ts / "meta.json").exists():  # 已被连带删除(批量删除时常见)
        return jsonify(ok=True)
    meta = json.loads((appdir / ts / "meta.json").read_text())
    full = meta.get("type", "full") == "full"
    base = ts if full else meta.get("base")
    for m in chain_info(appdir):  # 删除某个备份时,依赖它的后续增量一并删除
        if (full and (m["time"] == ts or m.get("base") == ts)) or (not full and m.get("base") == base and m["time"] >= ts):
            shutil.rmtree(appdir / m["time"], ignore_errors=True)
    if full:
        (appdir / ".state" / f"{ts}.snar").unlink(missing_ok=True)
    return jsonify(ok=True)


def resolve_items(items, chain):
    """items: ["文件夹/时间戳", ...] -> [(文件夹, 时间戳), ...]。chain=True 时补齐还原所需的完整备份和前置增量。"""
    root, seen, out = Path(settings()["backup_dir"]), set(), []
    for it in items:
        folder, _, ts = it.partition("/")
        if not (valid_part(folder) and valid_part(ts)):
            raise ValueError("非法的备份标识: " + it[:60])
        appdir = root / folder
        mp = appdir / ts / "meta.json"
        if not mp.exists():
            raise FileNotFoundError(f"找不到备份 {folder}/{ts}")
        tss = chain_of(appdir, json.loads(mp.read_text()), ts) if chain else [ts]
        for t in tss:
            if (folder, t) not in seen:
                seen.add((folder, t))
                out.append((folder, t))
    return sorted(out)


@app.get("/api/download")
def api_download():
    """把选中的备份(保持 应用名/时间戳/ 目录结构)流式打成一个 .tar 下载,解开后 restore.sh 仍可直接使用。
    数据本身已是 gz,这里不再二次压缩;check=1 时只返回数量和体积,不真正下载。"""
    import urllib.parse
    items = [x for x in request.args.get("items", "").split(",") if x]
    if not items:
        return jsonify(error="没有选择备份"), 400
    try:
        lst = resolve_items(items, request.args.get("chain", "1") != "0")
    except FileNotFoundError as e:
        return jsonify(error=str(e)), 404
    except ValueError as e:
        return jsonify(error=str(e)), 400
    root = Path(settings()["backup_dir"])
    size = sum(x.stat().st_size for f, t in lst for x in (root / f / t).iterdir() if x.is_file())
    if request.args.get("check"):
        return jsonify(ok=True, count=len(lst), size=size)
    folders = {f for f, _ in lst}
    base = f"{lst[-1][0]}_{lst[-1][1]}" if len(folders) == 1 else "docker-backup_" + time.strftime("%Y%m%d-%H%M%S")
    fname = f"{base}_x{len(lst)}.tar" if len(lst) > 1 else base + ".tar"
    proc = subprocess.Popen(["tar", "-cf", "-", "-C", str(root)] + [f"{f}/{t}" for f, t in lst],
                            stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)

    def gen():
        try:
            while True:
                b = proc.stdout.read(1 << 20)
                if not b:
                    break
                yield b
        finally:  # 浏览器中途取消下载时也要收尾
            if proc.poll() is None:
                proc.kill()
            proc.stdout.close()
            proc.wait()
    return Response(gen(), content_type="application/x-tar", headers={
        "Content-Disposition": "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (
            re.sub(r"[^\x20-\x7e]", "_", fname), urllib.parse.quote(fname)),
        "X-Accel-Buffering": "no", "Cache-Control": "no-store"})


# ---------- 导出: 源文件(可分享,不含数据) / 仅数据 ----------
SECRET_RE = re.compile(r"(PASS|PWD|SECRET|TOKEN|API_?KEY|ACCESS_?KEY|PRIVATE|CREDENTIAL|AUTH|WEBHOOK|NOTIFY|DSN)", re.I)
MASK = "CHANGE_ME"
SRC_SKIP_DIRS = {".git", "node_modules", "__pycache__", ".venv", "venv", ".cache"}
# 工作目录里被挂载进容器的子目录,如果是下面这些名字(或只读挂载),按"源码/配置"处理,不当数据
CODE_DIR_NAMES = {"public", "static", "html", "www", "web", "dist", "build", "templates", "views", "src", "app", "lib", "assets",
                  "frontend", "client", "site", "pages", "conf", "conf.d", "scripts", "bin", "nginx", "theme", "themes"}
SRC_MAX_FILE = 10 << 20          # 源文件包里单个文件超过 10MB 就跳过(多半是数据/二进制)
KV_RE = re.compile(r"^(\s*(?:-\s*)?(?:export\s+)?)([A-Za-z_][\w.\-]*)(\s*[=:]\s*)(.*?)(\s+#.*)?$")
URLPW_RE = re.compile(r"(://[^/\s:@]+):[^@\s/]+@")


def mask_value(k, v):
    """k 像密码/令牌且 v 是写死的值 => 换成占位符;引用 ${VAR} 的保持不变"""
    s = v.strip()
    if not s or not SECRET_RE.search(k) or re.fullmatch(r"[\"']?\$\{?[\w]+\}?[\"']?", s):
        return v, False
    return MASK, True


def mask_text(text):
    out, keys = [], []
    for line in text.split("\n"):
        m = KV_RE.match(line.rstrip("\r"))
        if m:
            pre, k, sep, v, cm = m.group(1), m.group(2), m.group(3), m.group(4), m.group(5) or ""
            nv, hit = mask_value(k, v)
            if hit:
                keys.append(k)
                line = pre + k + sep + nv + cm + ("\r" if line.endswith("\r") else "")
        line2 = URLPW_RE.sub(r"\1:" + MASK + "@", line)
        if line2 != line:
            keys.append("(URL 里的密码)")
            line = line2
        out.append(line)
    return "\n".join(out), sorted(set(keys))


def is_maskable(fn):
    return fn == ".env" or fn.startswith(".env.") or fn.endswith((".env", ".yml", ".yaml"))


def skip_src(src):
    return (not src or src.startswith(("/var/run", "/run", "/proc", "/sys", "/dev"))
            or src in ("/etc/localtime", "/etc/timezone") or src.rstrip("/") in DANGEROUS_ROOTS)


def compose_mounts(a):
    """容器还没创建的 compose 项目: 从 `docker compose config` 里读出挂载"""
    if not a["files"]:
        return []
    try:
        r = subprocess.run(["docker", "compose", "-f", a["files"][0], "config", "--format", "json"], cwd=a["workdir"] or None,
                           capture_output=True, text=True, timeout=30)
        cfg = json.loads(r.stdout)
    except Exception:
        return []
    out = []
    for sv in (cfg.get("services") or {}).values():
        for v in sv.get("volumes") or []:
            if not isinstance(v, dict) or not v.get("source"):
                continue
            if v.get("type") == "bind":
                out.append({"src": v["source"], "dst": v.get("target", ""), "type": "bind", "name": "", "img": (sv.get("image") or "").lower(),
                            "rw": not v.get("read_only")})
            elif v.get("type") == "volume":
                nm = ((cfg.get("volumes") or {}).get(v["source"]) or {}).get("name") or v["source"]
                out.append({"src": f"/var/lib/docker/volumes/{nm}/_data", "dst": v.get("target", ""), "type": "volume", "name": nm,
                            "img": (sv.get("image") or "").lower(), "rw": not v.get("read_only")})
    return out


def mount_list(a):
    """应用的所有挂载。code=True 表示挂载的就是项目目录本身(如 .:/app),那是源码不是数据"""
    ms = []
    for c in a["_c"]:
        for m in c.get("Mounts", []):
            if m.get("Type") in ("bind", "volume") and m.get("Source"):
                ms.append({"src": m["Source"], "dst": m.get("Destination", ""), "type": m["Type"], "name": m.get("Name", ""),
                           "img": c["Config"]["Image"].lower(), "rw": m.get("RW", True)})
    if not ms:
        ms = compose_mounts(a)
    wd = (a["workdir"] or "").rstrip("/")
    out = []
    for m in ms:
        if skip_src(m["src"]):
            continue
        s = m["src"].rstrip("/")
        m["code"] = bool(wd) and (wd == s or wd.startswith(s + "/"))
        if (not m["code"] and wd and m["type"] == "bind" and s.startswith(wd + "/")
                and (not m.get("rw", True) or os.path.basename(s).lower() in CODE_DIR_NAMES)):
            m["code"] = True  # 工作目录里的只读挂载 / public、static 之类的目录: 是源码或配置,跟着应用走,不算数据
        out.append(m)
    return out


def plan_data(a, S):
    """只含数据: 挂载的目录 + 命名卷(单个文件算配置,留在源文件里)。返回 (路径, 排除, 提示)"""
    paths, excl, notes = [], list(S["excludes"]), []
    rules = [r.split(":", 1) for r in S["mount_rules"] if ":" in r]
    for m in mount_list(a):
        if m["code"] or (m["type"] == "bind" and not os.path.isdir(m["src"])):
            continue
        if any(k.lower() in m["img"] and fnmatch.fnmatch(m["dst"], g) for k, g in rules):
            excl.append(m["src"])
            continue
        paths.append(m["src"])
    out = []
    for p in sorted(set(paths)):
        if not any(p == q or p.startswith(q.rstrip("/") + "/") for q in out):
            out.append(p)
    out = [p for p in out if os.path.exists(p)]
    stats = self_stats()
    for p in out:
        for hit in find_self(p, stats):
            notes.append(f"{hit} 是本程序自己的备份/设置目录,已跳过")
            excl.append(hit)
    return out, excl, notes


def attach(fname, ctype):
    import urllib.parse
    return Response(None, content_type=ctype, headers={
        "Content-Disposition": "attachment; filename=\"%s\"; filename*=UTF-8''%s" % (
            re.sub(r"[^\x20-\x7e]", "_", fname), urllib.parse.quote(fname)),
        "X-Accel-Buffering": "no", "Cache-Control": "no-store"})


def pick_apps():
    names = [x for x in request.args.get("names", "").split(",") if x]
    if not names:
        raise ValueError("没有选择应用")
    allapps = {a["name"]: a for a in scan()}
    miss = [n for n in names if n not in allapps]
    if miss:
        raise FileNotFoundError("找不到应用 " + ", ".join(miss))
    return [allapps[n] for n in names]


def zinfo(path, arc):
    st = os.stat(path)
    i = zipfile.ZipInfo(arc, time.localtime(st.st_mtime)[:6])
    i.external_attr = (st.st_mode & 0xFFFF) << 16
    i.compress_type = zipfile.ZIP_DEFLATED
    return i


def add_source(z, a, prefix):
    """把一个应用的源文件(compose/.env/Dockerfile/配置/代码)写进 zip: 不含数据目录,密码类变量已脱敏"""
    root = (a["workdir"] or "").rstrip("/")
    ms = mount_list(a)
    data_dirs = [m["src"].rstrip("/") for m in ms if m["type"] == "bind" and not m["code"] and os.path.isdir(m["src"])]
    vols = sorted({m["name"] or m["src"] for m in ms if m["type"] == "volume"})
    masked, skipped_data, skipped_big, n = {}, [], [], 0

    def put(path, arc):
        nonlocal n
        fn = os.path.basename(path)
        if is_maskable(fn) and os.path.getsize(path) < (1 << 20):
            raw = open(path, "rb").read()
            txt, keys = mask_text(raw.decode("utf-8", "surrogateescape"))
            if keys:
                masked[arc[len(prefix):]] = keys
            z.writestr(zinfo(path, arc), txt.encode("utf-8", "surrogateescape"))
        else:
            with open(path, "rb") as f, z.open(zinfo(path, arc), "w", force_zip64=True) as w:
                shutil.copyfileobj(f, w, 1 << 20)
        n += 1

    if root and root not in DANGEROUS_ROOTS and os.path.isdir(root):
        for dp, dns, fns in os.walk(root):
            keep = []
            for d in dns:
                full = os.path.join(dp, d)
                if d in SRC_SKIP_DIRS or os.path.islink(full):
                    continue
                if any(full == x or full.startswith(x + "/") for x in data_dirs):
                    skipped_data.append(full)
                    continue
                keep.append(d)
            dns[:] = keep
            for f in fns:
                full = os.path.join(dp, f)
                try:
                    st = os.lstat(full)
                except OSError:
                    continue
                if not stat.S_ISREG(st.st_mode):
                    continue
                if st.st_size > SRC_MAX_FILE:
                    skipped_big.append(f"{os.path.relpath(full, root)} ({st.st_size >> 20}MB)")
                    continue
                put(full, prefix + os.path.relpath(full, root))
        for f in a["files"]:  # compose 文件在工作目录之外的情况
            if f and os.path.isfile(f) and not f.startswith(root + "/"):
                put(f, prefix + "_compose外部文件/" + os.path.basename(f))
    if not a["compose"] and a["_c"]:  # docker run 型应用: 生成一份 docker-run.sh(环境变量里的密码已脱敏)
        lines = ["#!/bin/sh", "set -e"]
        for c in a["_c"]:
            args, outa = run_args(c), []
            for i, x in enumerate(args):
                if i and args[i - 1] == "-e":
                    k, _, v = x.partition("=")
                    nv, hit = mask_value(k, v)
                    if hit:
                        masked.setdefault("docker-run.sh", []).append(k)
                        x = k + "=" + nv
                outa.append(shlex.quote(x))
            lines.append("docker " + " ".join(outa))
        z.writestr(prefix + "docker-run.sh", "\n".join(lines) + "\n")
        n += 1
    imgs = sorted({c["Config"]["Image"] for c in a["_c"]})
    t = [f"应用: {a['name']}    导出时间: {time.strftime('%Y-%m-%d %H:%M:%S')}", "",
         "这是「源文件包」: 只含 compose / .env / Dockerfile / 配置 / 代码,不含任何数据,可以直接分享。", "",
         "【怎么部署】",
         "1. 解压到目标机器的一个专属文件夹里。",
         "2. 打开下面「已脱敏」列出的文件,把 CHANGE_ME 改成你自己的值(账号/密码/令牌等)。",
         "3. compose 里如果有 /opt/... 之类的绝对路径,改成你自己机器上的路径。",
         ("4. 在该文件夹里运行: docker compose up -d --build" if a["compose"] else "4. 运行: sh docker-run.sh"), ""]
    if imgs:
        t += ["【用到的镜像】(没有 Dockerfile 的会自动拉取)"] + [f"  {i}" for i in imgs] + [""]
    if masked:
        t += ["【已脱敏的变量】(只列变量名,值已换成 CHANGE_ME)"] + [f"  {k}: {', '.join(v)}" for k, v in sorted(masked.items())] + [""]
    t += ["【没有打进来的数据】(对方需要自己准备,或留空让程序首次运行时自己创建)"]
    t += [f"  目录: {d}" for d in skipped_data] or ["  (没有检测到挂载的数据目录)"]
    t += [f"  命名卷: {v}" for v in vols]
    if skipped_big:
        t += ["", f"【体积超过 {SRC_MAX_FILE >> 20}MB 已跳过的文件】"] + [f"  {x}" for x in skipped_big]
    t += ["", "提醒: 只对 .env / compose 文件和 docker-run.sh 做了脱敏,其它配置文件(config.json、*.conf 等)里",
          "如果写了密码或密钥,分享前请自己再检查一遍。"]
    z.writestr(prefix + "README-部署说明.txt", "\n".join(t) + "\n")
    return n


@app.get("/api/export/source")
def api_export_source():
    """导出源文件包(zip): 不含数据目录、密码已脱敏,可直接分享。体积很小,先写临时文件再整体发送。"""
    try:
        sel = pick_apps()
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 400
    if request.args.get("check"):
        return jsonify(ok=True, count=len(sel))
    import tempfile
    tmp = tempfile.TemporaryFile()
    try:
        with zipfile.ZipFile(tmp, "w", zipfile.ZIP_DEFLATED) as z:
            total = sum(add_source(z, a, (re.sub(r"[^\w.-]", "_", a["name"]) + "/") if len(sel) > 1 else "") for a in sel)
        if not total:
            raise RuntimeError("这些应用没有可导出的源文件(没有 compose 工作目录)")
    except Exception as e:
        tmp.close()
        return jsonify(error=str(e)), 500
    size = tmp.tell()
    tmp.seek(0)

    def gen():
        try:
            while True:
                b = tmp.read(1 << 20)
                if not b:
                    break
                yield b
        finally:
            tmp.close()
    fname = f"{sel[0]['name']}_源文件_{time.strftime('%Y%m%d')}.zip" if len(sel) == 1 else f"源文件_x{len(sel)}_{time.strftime('%Y%m%d')}.zip"
    r = attach(fname, "application/zip")
    r.response, r.headers["Content-Length"] = gen(), str(size)
    return r


@app.get("/api/export/data")
def api_export_data():
    """只导出数据(挂载的目录+命名卷),实时流式打成 .tar.gz,不占服务器临时空间。
    解压回原位: tar -xzpf 文件 -C /    stop=1 时导出期间临时停止容器,结束(或取消下载)后自动启动。"""
    try:
        sel = pick_apps()
    except (ValueError, FileNotFoundError) as e:
        return jsonify(error=str(e)), 400
    S, paths, excl = settings(), [], []
    for a in sel:
        p, e, _ = plan_data(a, S)
        paths += p
        excl += e
    paths = sorted(set(paths))
    paths = [p for p in paths if not any(p != q and p.startswith(q.rstrip("/") + "/") for q in paths)]
    if not paths:
        return jsonify(error="没有可导出的数据: 这些应用没有挂载目录/命名卷,或路径没有挂载进本程序容器"), 400
    if request.args.get("check"):
        return jsonify(ok=True, count=len(paths), paths=paths)
    stop = request.args.get("stop") == "1"
    running = [c["Name"].lstrip("/") for a in sel for c in a["_c"] if c["State"]["Running"]] if stop else []
    proc = None

    def gen():
        nonlocal proc
        try:
            if running:
                subprocess.run(["docker", "stop"] + running, capture_output=True)
            proc = subprocess.Popen(["tar", "-czpf", "-", "-C", "/"] + [f"--exclude={e.lstrip('/')}" for e in sorted(set(excl))]
                                    + [p.lstrip("/") for p in paths], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
            while True:
                b = proc.stdout.read(1 << 20)
                if not b:
                    break
                yield b
        finally:  # 下载完成/中途取消/出错,都要收尾并把容器启动回来
            if proc:
                if proc.poll() is None:
                    proc.kill()
                proc.stdout.close()
                proc.wait()
            if running:
                subprocess.run(["docker", "start"] + running, capture_output=True)
    fname = f"{sel[0]['name']}_数据_{time.strftime('%Y%m%d-%H%M%S')}.tar.gz" if len(sel) == 1 else f"数据_x{len(sel)}_{time.strftime('%Y%m%d-%H%M%S')}.tar.gz"
    r = attach(fname, "application/gzip")
    r.response = gen()
    return r


@app.get("/api/job")
def api_job():
    return jsonify(JOB)


def scheduler():
    last = None
    while True:
        time.sleep(20)
        try:
            S = settings()
            now = time.localtime()
            key = time.strftime("%Y%m%d%H%M", now)
            if not S["schedule_enabled"] or key == last or time.strftime("%H:%M", now) != S["schedule_time"] \
                    or (now.tm_wday + 1) not in S["schedule_days"]:
                continue
            names = S["schedule_apps"] or [a["name"] for a in scan()]
            if job(do_backup, [(n, S["schedule_stop"], "auto") for n in names], "定时备份"):
                last = key
        except Exception:
            pass


threading.Thread(target=scheduler, daemon=True).start()
