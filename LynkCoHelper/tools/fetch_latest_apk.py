import json, os, sys, time, urllib.error, urllib.request 
HERE = os.path.dirname(os.path.abspath(__file__)) 
sys.path.insert(0, HERE) 
import appsecret_core as core 
REPO = os.environ.get("GITHUB_REPOSITORY", "") 
TOKEN = (os.environ.get("GH_TOKEN") or os.environ.get("GITHUB_TOKEN") or "").strip() 
API = "https://api.github.com" 
UA = "lynkco-apk-fetcher" 
def _headers(extra=None): 
    h = {"Authorization": "Bearer " + TOKEN, "Accept": "application/vnd.github+json", "User-Agent": UA} 
    if extra: 
        h.update(extra) 
    return h 
def gh_json(url, method="GET", data=None): 
    body = json.dumps(data).encode() if data is not None else None 
    req = urllib.request.Request(url, data=body, method=method, headers=_headers({"Content-Type": "application/json"} if body else None)) 
    return json.loads(urllib.request.urlopen(req, timeout=60).read()) 
def upload_asset(release_id, name, path): 
    url = "https://uploads.github.com/repos/" + REPO + "/releases/" + str(release_id) + "/assets?name=" + name 
    data = open(path, "rb").read() 
    req = urllib.request.Request(url, data=data, method="POST", headers=_headers({"Content-Type": "application/vnd.android.package-archive", "Content-Length": str(len(data))})) 
    urllib.request.urlopen(req, timeout=1800).read() 
def ensure_release(tag): 
    try: 
        return gh_json(API + "/repos/" + REPO + "/releases/tags/" + tag) 
    except urllib.error.HTTPError as e: 
        if e.code != 404: 
            raise 
        return gh_json(API + "/repos/" + REPO + "/releases", method="POST", data={"tag_name": tag, "name": tag, "body": "lynkco apk " + tag}) 
def delete_asset(release, name): 
    for a in release.get("assets", []): 
        if a.get("name") == name: 
            req = urllib.request.Request(API + "/repos/" + REPO + "/releases/assets/" + str(a.get("id")), method="DELETE", headers=_headers()) 
            urllib.request.urlopen(req, timeout=60).read() 
def main(): 
    if not TOKEN: 
        sys.exit("no token") 
    ver = "" 
    for attempt in range(1, 4): 
        try: 
            data = json.loads(urllib.request.urlopen(core.LYNKCO_VER_API, timeout=15).read()) 
            ver = (data.get("data") or {}).get("androidNewestVersion", "").lstrip("V") 
            break 
        except Exception as e: 
            print("version api attempt", attempt, "failed:", e) 
            time.sleep(10) 
    if not ver: 
        sys.exit("no version from api") 
    print("latest version: v" + ver) 
    apk = os.path.join(core.TOOLS_DIR, "lynkco-v" + ver + ".apk") 
    if not os.path.exists(apk): 
        os.makedirs(core.TOOLS_DIR, exist_ok=True) 
        core._download("https://app-cdn.lynkco.com/android/lynkco-64-v" + ver + ".apk", apk, 285) 
    rel = ensure_release("apk-v" + ver) 
    names = [a.get("name") for a in rel.get("assets", [])] 
    if "lynkco-v" + ver + ".apk" in names: 
        print("skip: version asset exists") 
    else: 
        upload_asset(rel.get("id"), "lynkco-v" + ver + ".apk", apk) 
        print("uploaded version asset") 
    latest = ensure_release("apk-latest") 
    delete_asset(latest, "lynkco-latest.apk") 
    upload_asset(latest.get("id"), "lynkco-latest.apk", apk) 
    print("apk-latest updated") 
main() 
