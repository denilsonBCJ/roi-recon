#!/usr/bin/env python3
# -*- coding: utf-8 -*-

import os
import re
import sys
import json
import shutil
import signal
import subprocess
from datetime import datetime
from urllib.parse import urlparse, parse_qsl, urlencode, urlunparse
from concurrent.futures import ThreadPoolExecutor, as_completed

# =========================================================
# CONFIG
# =========================================================

HTTPX_MATCH_CODES = {"200", "201", "202", "203", "204", "301", "302", "307", "308", "401", "403"}
HTTPX_TIMEOUT_SECONDS = 1200
NUCLEI_TIMEOUT_SECONDS = 2400

# Limites para eficiência
MAX_URLS_PRE_HTTPX = 6000
MAX_URLS_PRE_NUCLEI = 1200
MAX_URLS_PRE_NUCLEI_HIGH_VALUE = 400

# Nuclei: tags mais úteis para ROI em web bug bounty
NUCLEI_TAGS = ",".join([
    "exposures",
    "misconfig",
    "default-login",
    "takeover",
    "files",
    "panels",
    "cves",
    "tech",
    "token-spray",
])

NUCLEI_SEVERITIES = "critical,high,medium"

PROMISING_EXTENSIONS = {
    ".php", ".asp", ".aspx", ".jsp", ".jspx", ".do", ".action",
    ".json", ".xml", ".env", ".bak", ".old", ".backup", ".zip",
    ".sql", ".conf", ".config", ".yml", ".yaml", ".log", ".txt"
}

STATIC_EXTENSIONS = {
    ".png", ".jpg", ".jpeg", ".gif", ".svg", ".css", ".woff", ".woff2",
    ".ttf", ".ico", ".mp4", ".webm", ".avi", ".mov", ".mp3", ".wav",
    ".pdf"
}

HOT_PATH_KEYWORDS = {
    "admin", "login", "signin", "signup", "register", "auth", "oauth",
    "api", "graphql", "gql", "rest", "upload", "download", "export", "import",
    "account", "profile", "user", "users", "member", "team", "org", "tenant",
    "workspace", "project", "settings", "config", "debug", "internal", "private",
    "secret", "token", "key", "backup", "test", "dev", "stage", "staging", "prod",
    "uat", "callback", "redirect", "sso", "session", "password", "reset", "verify",
    "invite", "notification", "webhook", "billing", "payment", "checkout",
    "invoice", "order", "cart", "search", "query", "file", "document", "download"
}

HOT_PARAMS = {
    "id", "ids", "user", "uid", "account", "member", "profile", "email",
    "username", "token", "auth", "key", "apikey", "api_key", "access_token",
    "redirect", "return", "next", "url", "callback", "continue", "dest",
    "file", "filename", "path", "folder", "dir", "download", "doc", "document",
    "search", "query", "q", "filter", "sort", "lang", "locale", "page",
    "size", "limit", "offset", "order", "view", "invoice", "payment",
    "amount", "price", "coupon", "discount", "debug", "test", "env", "config"
}

HIGH_VALUE_PATTERNS = [
    r"/api/",
    r"/graphql",
    r"/gql",
    r"/admin",
    r"/login",
    r"/auth",
    r"/oauth",
    r"/callback",
    r"/redirect",
    r"/upload",
    r"/download",
    r"/export",
    r"/import",
    r"/settings",
    r"/billing",
    r"/payment",
    r"/checkout",
    r"/internal",
    r"/debug",
    r"/private",
]

EXCLUDED_SCHEMES = {"javascript", "data", "mailto", "tel"}

TECH_BONUS = {
    "graphql": 7,
    "next.js": 2,
    "nextjs": 2,
    "nginx": 1,
    "apache": 1,
    "node.js": 2,
    "express": 3,
    "spring": 3,
    "php": 2,
    "laravel": 3,
    "django": 3,
    "rails": 3,
    "asp.net": 3,
    "cloudflare": 0,
    "wordpress": 4,
    "drupal": 4,
}

TITLE_BONUS_PATTERNS = [
    (r"admin", 5),
    (r"login", 4),
    (r"sign in", 4),
    (r"dashboard", 4),
    (r"api", 3),
    (r"graphql", 5),
    (r"swagger", 6),
    (r"openapi", 6),
    (r"staging", 5),
    (r"dev", 2),
    (r"test", 1),
]

# =========================================================
# HELPERS
# =========================================================

def color(text, code):
    return f"\033[{code}m{text}\033[0m" if sys.stdout.isatty() else text

def info(msg): print(color(f"[*] {msg}", "1;34"))
def good(msg): print(color(f"[+] {msg}", "1;32"))
def warn(msg): print(color(f"[!] {msg}", "1;33"))
def bad(msg): print(color(f"[x] {msg}", "1;31"))

def banner():
    print("=" * 82)
    print(" ROI Recon v2 - Smart Recon Pipeline (gau + waybackurls + httpx + nuclei) ")
    print("=" * 82)

def abort_handler(sig, frame):
    warn("Interrompido pelo usuário.")
    sys.exit(1)

signal.signal(signal.SIGINT, abort_handler)

BINARIES = {}

def resolve_binary(binary: str) -> str:
    candidates = [
        os.path.expanduser(f"~/go/bin/{binary}"),
        shutil.which(binary),
        os.path.expanduser(f"~/go/bin/{binary}"),
        os.path.expanduser(f"~/.local/bin/{binary}"),
        f"/usr/local/bin/{binary}",
        f"/usr/bin/{binary}",
        f"/bin/{binary}",
    ]

    for candidate in candidates:
        if candidate and os.path.isfile(candidate) and os.access(candidate, os.X_OK):
            return candidate

    return ""

def check_dependency(binary: str) -> bool:
    resolved = resolve_binary(binary)
    if resolved:
        BINARIES[binary] = resolved
        return True
    return False

def ensure_dependencies():
    deps = ["gau", "waybackurls", "httpx", "nuclei"]
    missing = [d for d in deps if not check_dependency(d)]

    if missing:
        bad(f"Dependências faltando: {', '.join(missing)}")
        print("\nInstale com:")
        print("  go install github.com/lc/gau/v2/cmd/gau@latest")
        print("  go install github.com/tomnomnom/waybackurls@latest")
        print("  go install github.com/projectdiscovery/httpx/cmd/httpx@latest")
        print("  go install github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
        sys.exit(1)

    good("Binários resolvidos:")
    for dep in deps:
        good(f"  {dep}: {BINARIES[dep]}")

def safe_mkdir(path: str):
    os.makedirs(path, exist_ok=True)

def read_lines(path: str):
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [x.strip() for x in f if x.strip()]

def write_lines(path: str, lines):
    with open(path, "w", encoding="utf-8") as f:
        for x in lines:
            f.write(str(x) + "\n")

def write_json(path: str, data):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2, ensure_ascii=False)

def normalize_target(raw: str) -> str:
    raw = raw.strip()
    if not raw:
        return ""
    if not re.match(r"^https?://", raw, re.I):
        raw = "https://" + raw
    parsed = urlparse(raw)
    host = parsed.netloc or parsed.path
    host = host.lower().strip().split("/")[0]
    if host.startswith("www."):
        host = host[4:]
    return host

def run_cmd(cmd, timeout=None, stdin_data=None, output_file=None):
    try:
        if isinstance(cmd, list):
            cmd = [os.path.expanduser(str(x)) for x in cmd]

        if output_file:
            with open(output_file, "w", encoding="utf-8") as f:
                proc = subprocess.run(
                    cmd,
                    input=stdin_data,
                    text=True,
                    stdout=f,
                    stderr=subprocess.PIPE,
                    timeout=timeout,
                    check=False
                )
                return proc.returncode, "", proc.stderr
        else:
            proc = subprocess.run(
                cmd,
                input=stdin_data,
                text=True,
                stdout=subprocess.PIPE,
                stderr=subprocess.PIPE,
                timeout=timeout,
                check=False
            )
            return proc.returncode, proc.stdout, proc.stderr
    except subprocess.TimeoutExpired:
        return 124, "", "timeout"
    except Exception as e:
        return 1, "", str(e)

def unique_keep_best(items, keyfunc, scorefunc):
    best = {}
    for item in items:
        key = keyfunc(item)
        score = scorefunc(item)
        if key not in best or score > best[key][0]:
            best[key] = (score, item)
    return [v[1] for v in best.values()]

# =========================================================
# URL NORMALIZATION / CANONICALIZATION
# =========================================================

def is_valid_url(url: str) -> bool:
    try:
        parsed = urlparse(url)
        if parsed.scheme.lower() in EXCLUDED_SCHEMES:
            return False
        return parsed.scheme in ("http", "https") and bool(parsed.netloc)
    except Exception:
        return False

def normalize_url(url: str) -> str:
    url = url.strip()
    if not is_valid_url(url):
        return ""

    parsed = urlparse(url)

    scheme = parsed.scheme.lower()
    host = parsed.netloc.lower()

    path = parsed.path or "/"
    path = re.sub(r"/{2,}", "/", path)

    # Remove fragment
    fragment = ""

    # Normaliza query ordenando params
    pairs = parse_qsl(parsed.query, keep_blank_values=True)
    pairs.sort(key=lambda x: (x[0], x[1]))
    query = urlencode(pairs, doseq=True)

    return urlunparse((scheme, host, path, "", query, fragment))

def get_extension(path: str) -> str:
    m = re.search(r"(\.[a-zA-Z0-9]{1,10})$", path.lower())
    return m.group(1) if m else ""

# =========================================================
# COLLECTION
# =========================================================

def collect_with_gau(domain: str, output_file: str):
    info(f"Rodando gau em {domain}")
    cmd = [BINARIES["gau"], "--subs", domain]
    code, _, err = run_cmd(cmd, timeout=900, output_file=output_file)
    return {"tool": "gau", "code": code, "stderr": err[:500], "file": output_file}

def collect_with_waybackurls(domain: str, output_file: str):
    info(f"Rodando waybackurls em {domain}")
    cmd = [BINARIES["waybackurls"]]
    code, _, err = run_cmd(cmd, timeout=900, stdin_data=domain + "\n", output_file=output_file)
    return {"tool": "waybackurls", "code": code, "stderr": err[:500], "file": output_file}

def collect_urls_parallel(domain: str, outdir: str):
    jobs = [
        ("gau", os.path.join(outdir, "gau.txt"), collect_with_gau),
        ("waybackurls", os.path.join(outdir, "waybackurls.txt"), collect_with_waybackurls),
    ]

    results = []
    with ThreadPoolExecutor(max_workers=2) as executor:
        future_map = {
            executor.submit(fn, domain, path): name
            for name, path, fn in jobs
        }
        for future in as_completed(future_map):
            results.append(future.result())

    all_urls = []

    for result in results:
        lines = read_lines(result["file"])
        all_urls.extend(lines)
        good(f"{result['tool']}: {len(lines)} URLs")

        if result["code"] != 0:
            warn(f"{result['tool']} retornou código {result['code']} - {result['stderr']}")

    normalized = []
    for url in all_urls:
        norm = normalize_url(url)
        if norm:
            normalized.append(norm)

    normalized = sorted(set(normalized))
    merged_file = os.path.join(outdir, "all_urls.txt")
    write_lines(merged_file, normalized)
    good(f"Total de URLs únicas: {len(normalized)}")
    return normalized, results, merged_file

# =========================================================
# ROI SCORING
# =========================================================

def url_base_score(url: str) -> int:
    parsed = urlparse(url)
    path = parsed.path.lower()
    full = url.lower()
    params = [k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True)]
    ext = get_extension(path)

    score = 0

    # Parâmetros geralmente aumentam muito a chance de bug útil
    if params:
        score += 5
        score += min(len(params), 8)

    # Arquivos estáticos perdem muito
    if ext in STATIC_EXTENSIONS:
        score -= 10

    # JS pode servir para triagem, mas não para nuclei direto
    if ext == ".js":
        score -= 2

    # Arquivos sensíveis / configs
    if ext in PROMISING_EXTENSIONS:
        score += 6

    # Keywords quentes no path/url
    for kw in HOT_PATH_KEYWORDS:
        if kw in path or kw in full:
            score += 3

    # Paths altamente valiosos
    for patt in HIGH_VALUE_PATTERNS:
        if re.search(patt, full):
            score += 6

    # Params importantes
    for p in params:
        if p in HOT_PARAMS:
            score += 5
        elif any(x in p for x in ("id", "user", "token", "auth", "file", "redirect", "key")):
            score += 3

    # APIs e GraphQL
    if "/api/" in path:
        score += 7
    if "graphql" in full or "/gql" in path:
        score += 8

    # Evitar lixo óbvio
    if "favicon" in full or "robots.txt" in full or "sitemap.xml" in full:
        score -= 4

    # Multi-tenant / auth / billing geralmente pagam bem
    special_words = ("tenant", "workspace", "team", "org", "account", "billing", "invoice", "payment")
    for w in special_words:
        if w in full:
            score += 4

    return score

def filter_roi_urls(urls, min_score=6):
    scored = []
    for url in urls:
        s = url_base_score(url)
        if s >= min_score:
            scored.append({
                "url": url,
                "score": s,
                "phase": "pre-httpx"
            })
    scored.sort(key=lambda x: (-x["score"], x["url"]))
    return scored

def dedupe_by_signature(scored_items):
    def signature(item):
        parsed = urlparse(item["url"])
        keys = sorted(k.lower() for k, _ in parse_qsl(parsed.query, keep_blank_values=True))
        return f"{parsed.scheme}://{parsed.netloc}{parsed.path}?{'&'.join(keys)}"
    return unique_keep_best(scored_items, keyfunc=signature, scorefunc=lambda i: i["score"])

# =========================================================
# HTTPX
# =========================================================

def run_httpx(input_file: str, output_file: str):
    info("Executando httpx nos alvos promissores")
    cmd = [
        BINARIES["httpx"],
        "-l", input_file,
        "-silent",
        "-json",
        "-title",
        "-tech-detect",
        "-status-code",
        "-follow-redirects",
        "-random-agent",
        "-timeout", "10",
        "-retries", "1",
        "-threads", "50",
        "-o", output_file,
    ]
    code, _, err = run_cmd(cmd, timeout=HTTPX_TIMEOUT_SECONDS)
    if code not in (0,):
        warn(f"httpx retornou código {code} - {err[:300]}")
    return output_file

def parse_httpx_jsonl(path: str):
    results = []
    for line in read_lines(path):
        try:
            obj = json.loads(line)
        except Exception:
            continue

        url = obj.get("url") or obj.get("input") or ""
        status_code = str(obj.get("status_code", ""))
        title = (obj.get("title") or "").strip()
        techs = obj.get("tech") or []
        if not isinstance(techs, list):
            techs = []

        if not url:
            continue

        results.append({
            "url": normalize_url(url),
            "status_code": status_code,
            "title": title,
            "tech": techs
        })
    return results

def httpx_score_bonus(item):
    score = 0
    status = item.get("status_code", "")
    title = (item.get("title") or "").lower()
    techs = [t.lower() for t in item.get("tech") or []]

    if status in {"200", "201", "202"}:
        score += 5
    elif status in {"401", "403"}:
        score += 4
    elif status in {"301", "302", "307", "308"}:
        score += 2

    for patt, bonus in TITLE_BONUS_PATTERNS:
        if re.search(patt, title):
            score += bonus

    for tech in techs:
        for key, bonus in TECH_BONUS.items():
            if key in tech:
                score += bonus

    return score

def rescore_alive(pre_scored, httpx_items):
    pre_map = {item["url"]: item["score"] for item in pre_scored}
    rescored = []

    for item in httpx_items:
        url = item["url"]
        status = item.get("status_code", "")
        if status not in HTTPX_MATCH_CODES:
            continue

        base = pre_map.get(url, url_base_score(url))
        bonus = httpx_score_bonus(item)
        total = base + bonus

        rescored.append({
            "url": url,
            "score": total,
            "base_score": base,
            "bonus_score": bonus,
            "status_code": status,
            "title": item.get("title", ""),
            "tech": item.get("tech", []),
            "phase": "post-httpx"
        })

    rescored.sort(key=lambda x: (-x["score"], x["url"]))
    return rescored

# =========================================================
# NUCLEI
# =========================================================

def select_nuclei_targets(scored_alive):
    high_value = []
    normal = []

    for item in scored_alive:
        url = item["url"]
        score = item["score"]
        status = item["status_code"]

        is_high_value = (
            score >= 18 or
            "graphql" in url.lower() or
            "/api/" in url.lower() or
            any(x in url.lower() for x in ["/admin", "/login", "/auth", "/upload", "/download", "/billing", "/payment"])
        )

        if status not in HTTPX_MATCH_CODES:
            continue

        if is_high_value:
            high_value.append(item)
        else:
            normal.append(item)

    high_value = high_value[:MAX_URLS_PRE_NUCLEI_HIGH_VALUE]
    remaining = max(0, MAX_URLS_PRE_NUCLEI - len(high_value))
    normal = normal[:remaining]

    selected = high_value + normal
    selected.sort(key=lambda x: (-x["score"], x["url"]))
    return selected

def run_nuclei(input_file: str, output_file: str):
    info("Executando nuclei nos melhores alvos vivos")
    cmd = [
        BINARIES["nuclei"],
        "-l", input_file,
        "-silent",
        "-tags", NUCLEI_TAGS,
        "-severity", NUCLEI_SEVERITIES,
        "-rl", "20",
        "-c", "20",
        "-retries", "1",
        "-stats",
        "-stats-interval", "20",
        "-etags", "intrusive,fuzz,dos,network",
        "-o", output_file
    ]
    code, _, err = run_cmd(cmd, timeout=NUCLEI_TIMEOUT_SECONDS)
    if code not in (0,):
        warn(f"nuclei retornou código {code} - {err[:300]}")
    return output_file

# =========================================================
# REPORTING
# =========================================================

def print_top(title, items, limit=25, post_httpx=False):
    print(f"\n{title}")
    print("-" * len(title))
    for idx, item in enumerate(items[:limit], 1):
        if post_httpx:
            status = item.get("status_code", "-")
            print(f"{idx:02d}. [{item['score']:02d}] [{status}] {item['url']}")
        else:
            print(f"{idx:02d}. [{item['score']:02d}] {item['url']}")

def save_summary_txt(path, summary):
    with open(path, "w", encoding="utf-8") as f:
        f.write("ROI Recon v2 - Resumo\n")
        f.write("=" * 60 + "\n")
        for key, value in summary.items():
            f.write(f"{key}: {value}\n")

# =========================================================
# MAIN
# =========================================================

def main():
    banner()
    ensure_dependencies()

    target = input("[?] Digite a URL/domínio: ").strip()
    domain = normalize_target(target)

    if not domain:
        bad("Domínio inválido.")
        sys.exit(1)

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    outdir = f"scan_{domain}_{ts}"
    safe_mkdir(outdir)

    good(f"Alvo normalizado: {domain}")
    good(f"Diretório de saída: {outdir}")

    # -------------------------
    # Coleta
    # -------------------------
    all_urls, collection_meta, merged_file = collect_urls_parallel(domain, outdir)

    if not all_urls:
        warn("Nenhuma URL coletada.")
        sys.exit(0)

    # Limita pré-httpx para eficiência
    pre_scored = filter_roi_urls(all_urls, min_score=6)
    pre_scored = dedupe_by_signature(pre_scored)
    pre_scored.sort(key=lambda x: (-x["score"], x["url"]))

    if len(pre_scored) > MAX_URLS_PRE_HTTPX:
        warn(f"Limitando URLs pré-httpx para {MAX_URLS_PRE_HTTPX}")
        pre_scored = pre_scored[:MAX_URLS_PRE_HTTPX]

    roi_urls_file = os.path.join(outdir, "roi_urls_pre_httpx.txt")
    write_lines(roi_urls_file, [x["url"] for x in pre_scored])

    good(f"URLs promissoras pré-httpx: {len(pre_scored)}")
    print_top("Top URLs por ROI antes do httpx", pre_scored, limit=25, post_httpx=False)

    if not pre_scored:
        warn("Nenhuma URL promissora suficiente para continuar.")
        sys.exit(0)

    # -------------------------
    # httpx
    # -------------------------
    httpx_file = os.path.join(outdir, "httpx_alive.jsonl")
    run_httpx(roi_urls_file, httpx_file)

    httpx_items = parse_httpx_jsonl(httpx_file)
    good(f"Respostas parseadas do httpx: {len(httpx_items)}")

    rescored_alive = rescore_alive(pre_scored, httpx_items)
    rescored_alive = dedupe_by_signature(rescored_alive)

    alive_urls_file = os.path.join(outdir, "alive_urls_post_httpx.txt")
    write_lines(alive_urls_file, [x["url"] for x in rescored_alive])

    alive_json_file = os.path.join(outdir, "alive_ranked_post_httpx.json")
    write_json(alive_json_file, rescored_alive)

    good(f"URLs vivas e ranqueadas: {len(rescored_alive)}")
    print_top("Top URLs vivas por ROI após httpx", rescored_alive, limit=25, post_httpx=True)

    if not rescored_alive:
        warn("Nenhum alvo vivo com ROI suficiente.")
        sys.exit(0)

    # -------------------------
    # seleção nuclei
    # -------------------------
    nuclei_targets = select_nuclei_targets(rescored_alive)
    nuclei_targets_file = os.path.join(outdir, "nuclei_targets.txt")
    write_lines(nuclei_targets_file, [x["url"] for x in nuclei_targets])

    nuclei_targets_json = os.path.join(outdir, "nuclei_targets_ranked.json")
    write_json(nuclei_targets_json, nuclei_targets)

    good(f"Alvos selecionados para nuclei: {len(nuclei_targets)}")

    if not nuclei_targets:
        warn("Sem alvos para nuclei.")
        sys.exit(0)

    # -------------------------
    # nuclei
    # -------------------------
    nuclei_file = os.path.join(outdir, "nuclei_results.txt")
    run_nuclei(nuclei_targets_file, nuclei_file)
    nuclei_lines = read_lines(nuclei_file)

    if nuclei_lines:
        good(f"Achados do nuclei: {len(nuclei_lines)}")
    else:
        warn("Nuclei não retornou achados nas tags/severidades configuradas.")

    # -------------------------
    # resumo
    # -------------------------
    summary = {
        "target": domain,
        "timestamp": ts,
        "output_dir": outdir,
        "total_urls_collected": len(all_urls),
        "total_urls_pre_httpx": len(pre_scored),
        "total_alive_post_httpx": len(rescored_alive),
        "total_nuclei_targets": len(nuclei_targets),
        "total_nuclei_findings": len(nuclei_lines),
        "files": {
            "all_urls": merged_file,
            "roi_urls_pre_httpx": roi_urls_file,
            "httpx_jsonl": httpx_file,
            "alive_urls_post_httpx": alive_urls_file,
            "alive_ranked_post_httpx_json": alive_json_file,
            "nuclei_targets": nuclei_targets_file,
            "nuclei_targets_ranked_json": nuclei_targets_json,
            "nuclei_results": nuclei_file
        },
        "collection_meta": collection_meta
    }

    summary_json = os.path.join(outdir, "summary.json")
    summary_txt = os.path.join(outdir, "summary.txt")
    write_json(summary_json, summary)
    save_summary_txt(summary_txt, summary)

    print("\n[✓] Concluído.")
    print(f"[*] Pasta: {outdir}")
    print(f"[*] Resumo TXT: {summary_txt}")
    print(f"[*] Resumo JSON: {summary_json}")

if __name__ == "__main__":
    main()
