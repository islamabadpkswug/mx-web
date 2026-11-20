import json, os, re, sys, time, urllib.request
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
from emailaudit.probe import smtp_probe, port25_shut, seal, unseal
KEY = os.environ.get("MXKEY", "").strip()
NONCE = os.environ.get("NONCE", "")
CB = os.environ.get("CB", "")
OK_CB = ("https://check.citant.ai/", "https://ai-crawler-check-")
out = {"nonce": NONCE, "port25_shut": False, "results": {}, "at": int(time.time() * 1000)}
def save():
    json.dump({"sealed": seal(KEY, json.dumps(out))}, open("results.json", "w"))
def run(lst):
    by_dom = defaultdict(list)
    for a in lst:
        by_dom[a.rsplit("@", 1)[1]].append(a)
    def one(dom):
        for i, a in enumerate(by_dom[dom]):
            if i:
                time.sleep(3)
            out["results"][a] = list(smtp_probe(a))
    with ThreadPoolExecutor(6) as ex:
        list(ex.map(one, sorted(by_dom)))
def post():
    if not CB.startswith(OK_CB):
        print("no callback")
        return
    body = json.dumps({"sealed": seal(KEY, json.dumps(out))}).encode()
    for wait in (0, 5, 20, 60):
        time.sleep(wait)
        try:
            req = urllib.request.Request(CB, data=body, method="POST", headers={"Content-Type": "application/json", "User-Agent": "citant-mx-web"})
            with urllib.request.urlopen(req, timeout=30) as r:
                print("callback", r.status)
                return
        except Exception as e:
            print("callback failed", type(e).__name__, getattr(e, "code", ""))
try:
    if not KEY:
        raise SystemExit("no key")
    raw = os.environ.get("ADDRS", "")
    if not raw.startswith("enc:"):
        raise SystemExit("addresses must be sealed")
    addrs = sorted({a.strip().lower() for a in unseal(KEY, raw[4:]).split() if "@" in a})[:20]
    out["port25_shut"] = port25_shut()
    if not out["port25_shut"]:
        run(addrs)
        grey = [a for a, (v, d) in out["results"].items() if v == "unknown" and re.search(r"(target|control) 4\d\d", d)]
        if grey:
            time.sleep(int(os.environ.get("GREY_WAIT", "120")))
            run(grey)
    out["at"] = int(time.time() * 1000)
except SystemExit as e:
    out["error"] = str(e)
except Exception as e:
    out["error"] = "run failed " + type(e).__name__
save()
post()
c = defaultdict(int)
for v, _ in out["results"].values():
    c[v] += 1
print(len(out["results"]), "answered;", dict(c), "; port 25 shut:", out["port25_shut"], "; error:", out.get("error", ""))
