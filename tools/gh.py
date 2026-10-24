#!/usr/bin/env python3
"""用 git 凭据里的 token 调 GitHub API，建 Release 并上传资产。
不打印 token；失败时只报状态码与响应体。"""
import base64, json, os, re, sys, urllib.request, urllib.error

REPO = "Sharl210/AntiHookBypass"

def token():
    p = os.path.expanduser("~/.git-credentials")
    for ln in open(p, encoding="utf-8"):
        m = re.search(r"https://([^:]+):([^@]+)@github\.com", ln.strip())
        if m:
            return m.group(2)
    raise SystemExit("找不到 token")

def api(method, path, data=None, raw=None, ctype="application/json"):
    url = "https://api.github.com" + path
    body = None
    if data is not None:
        body = json.dumps(data).encode()
    if raw is not None:
        body = raw
    req = urllib.request.Request(url, data=body, method=method)
    req.add_header("Authorization", "Bearer " + token())
    req.add_header("Accept", "application/vnd.github+json")
    req.add_header("Content-Type", ctype)
    try:
        with urllib.request.urlopen(req, timeout=90) as r:
            return r.status, json.loads(r.read() or b"{}")
    except urllib.error.HTTPError as e:
        return e.code, e.read().decode("utf-8", "replace")[:500]

cmd = sys.argv[1]
if cmd == "create":
    tag = sys.argv[2]
    body = open(sys.argv[3], encoding="utf-8").read()
    st, r = api("POST", f"/repos/{REPO}/releases", {
        "tag_name": tag, "name": tag, "body": body,
        "draft": False, "prerelease": False,
    })
    if st not in (200, 201):
        print("FAIL", st, r); sys.exit(1)
    print("RELEASE_ID", r["id"])
    print("UPLOAD_URL", r["upload_url"])
elif cmd == "upload":
    tag = sys.argv[2]; path = sys.argv[3]; name = sys.argv[4]
    st, r = api("GET", f"/repos/{REPO}/releases/tags/{tag}")
    if st != 200:
        print("FAIL get", st, r); sys.exit(1)
    up = r["upload_url"].split("{")[0]
    data = open(path, "rb").read()
    req = urllib.request.Request(up + "?name=" + name, data=data, method="POST")
    req.add_header("Authorization", "Bearer " + token())
    req.add_header("Content-Type", "application/vnd.android.package-archive")
    try:
        with urllib.request.urlopen(req, timeout=180) as resp:
            j = json.loads(resp.read()); print("UPLOADED", j["browser_download_url"], j["size"])
    except urllib.error.HTTPError as e:
        print("FAIL upload", e.code, e.read().decode("utf-8","replace")[:300]); sys.exit(1)
