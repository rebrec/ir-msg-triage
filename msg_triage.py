#!/usr/bin/env python3
"""
msg_triage.py - Triage IR d'un fichier .msg potentiellement malveillant.

Extraction READ-ONLY (rien n'est exécuté) :
  - Métadonnées (sujet, dates, expéditeur affiche vs reel)
  - En-tetes SMTP bruts + analyse SPF/DKIM/DMARC + chemin Received
  - Corps texte + détection d'URLs / IPs / emails (IOCs)
  - Pieces jointes : nom, taille, type, hashes (MD5/SHA1/SHA256)
  - Scan macros VBA des PJ Office (oletools)
  - Détection PJ a risque (exe, scripts, archives, OLE)

Usage:
    python3 msg_triage.py "infected-Facture Villard.msg" [--dump-dir ./pj]
"""
import argparse
import hashlib
import json
import re
import sys
from pathlib import Path

RISKY_EXT = {
    ".exe", ".scr", ".com", ".pif", ".bat", ".cmd", ".js", ".jse", ".vbs",
    ".vbe", ".wsf", ".wsh", ".ps1", ".psm1", ".hta", ".lnk", ".jar", ".msi",
    ".reg", ".dll", ".cpl", ".iso", ".img", ".vhd", ".docm", ".xlsm", ".pptm",
    ".xlsb", ".dotm", ".xlam", ".one", ".gz", ".7z", ".rar", ".zip", ".ace",
}

URL_RE = re.compile(r'https?://[^\s<>"\')]+', re.I)
IP_RE = re.compile(r'\b(?:\d{1,3}\.){3}\d{1,3}\b')
EMAIL_RE = re.compile(r'[\w.\-+]+@[\w.\-]+\.\w+')

# Bloc Received complet, continuations repliees incluses.
RECEIVED_RE = re.compile(r'^Received:.*?(?=^\S|\Z)', re.M | re.S | re.I)

# Types MISP -> categorie MISP. Vocabulaire aligne sur l'objet "email" de
# misp-objects, pour rester importable dans MISP sans retraduction.
IOC_TYPE_CATEGORY = {
    "url": "Payload delivery",
    "ip-src": "Network activity",
    "email": "Payload delivery",
    "email-src": "Payload delivery",
    "email-dst": "Payload delivery",
    "email-reply-to": "Payload delivery",
    "email-message-id": "Payload delivery",
}

# Type MISP -> section du rapport.
IOC_BUCKET = {
    "url": "urls",
    "ip-src": "ips",
    "email": "emails",
    "email-src": "emails",
    "email-dst": "emails",
    "email-reply-to": "emails",
    "email-message-id": "emails",
}

# Provenance d'un IOC : cle machine -> libelle affiche.
ORIGIN_LABELS = {
    "header.from": "Expediteur (From)",
    "header.sender_display": "Expediteur affiche",
    "header.to": "Destinataire (To)",
    "header.cc": "Destinataire (Cc)",
    "header.reply_to": "Adresse de reponse (Reply-To)",
    "header.return_path": "Chemin de retour (Return-Path)",
    "header.message_id": "Identifiant du message (Message-ID)",
    "header.received_spf": "IP emettrice declaree SPF",
    "body.text": "Corps du message (texte)",
    "body.html.text": "Texte visible du corps HTML",
    "body.html.href": "Lien cliquable dans le corps HTML",
    "body.html.img": "Image distante (pixel de tracage possible)",
    "body.html.comment": "Commentaire HTML - non visible a la lecture",
    "body.html.style": "CSS (background-image, @import)",
    "body.html.other": "Balise HTML (source, non visible a la lecture)",
    "attachment.name": "Nom de piece jointe",
}

# Origines par ordre de valeur d'analyse : quand un IOC apparait a plusieurs
# endroits, c'est le contexte de la plus haute qui est retenu.
ORIGIN_PRIORITY = (
    "header.received_spf", "header.from", "header.sender_display",
    "header.reply_to", "header.return_path", "header.received",
    "header.to", "header.cc", "header.message_id",
    "body.html.meta", "body.html.href", "body.html.img",
    "body.html.comment", "body.html.style",
    "body.text", "body.html.text", "body.html.other", "attachment.name",
)

# Hotes de namespace XML/DTD : presents dans tout mail HTML, jamais un IOC.
NAMESPACE_HOSTS = {
    "www.w3.org", "w3.org", "schemas.microsoft.com", "schemas.openxmlformats.org",
    "purl.org", "schema.org", "www.iana.org", "ns.adobe.com",
}


def hashes(data: bytes) -> dict:
    return {
        "md5": hashlib.md5(data).hexdigest(),
        "sha1": hashlib.sha1(data).hexdigest(),
        "sha256": hashlib.sha256(data).hexdigest(),
        "size": len(data),
    }


def defang(s: str) -> str:
    """Neutralise le schema seulement (hxxp) pour casser le lien cliquable,
    en gardant les vrais points pour rester copiable/collable."""
    return s.replace("http://", "hxxp://").replace("https://", "hxxps://")


def origin_label(origin: str) -> str:
    """Libelle affichable d'une origine, y compris les formes indexees
    (header.received[3], body.html.meta[og:url])."""
    if origin in ORIGIN_LABELS:
        return ORIGIN_LABELS[origin]
    m = re.match(r"header\.received\[(\d+)\]$", origin)
    if m:
        return f"Saut Received n{m.group(1)}"
    m = re.match(r"body\.html\.meta\[(.+)\]$", origin)
    if m:
        prop = m.group(1)
        if prop.lower() == "og:url":
            return "Metadonnee Open Graph (og:url) - URL canonique, non visible a la lecture"
        return f"Metadonnee HTML <{prop}> - non visible a la lecture"
    return origin


def origin_rank(origin: str) -> int:
    for i, prefix in enumerate(ORIGIN_PRIORITY):
        if origin.startswith(prefix):
            return i
    return len(ORIGIN_PRIORITY)


def url_host(url: str) -> str:
    from urllib.parse import urlsplit
    try:
        return (urlsplit(url).hostname or "").lower()
    except ValueError:
        return ""


def clean_url(url: str) -> str:
    """Retire la ponctuation de fin, souvent capturee par le regex."""
    return url.rstrip(".,;:!?")


def valid_ipv4(value: str) -> bool:
    import ipaddress
    try:
        ipaddress.IPv4Address(value)
        return True
    except ValueError:
        return False


def non_actionable_ip(value: str) -> str:
    """Motif pour lequel une IP n'est pas exploitable en detection, sinon ''."""
    import ipaddress
    ip = ipaddress.IPv4Address(value)
    if ip.is_private or ip.is_loopback or ip.is_link_local:
        return "RFC1918/locale - infrastructure de transit"
    if ip.is_reserved or ip.is_multicast or ip.is_unspecified:
        return "plage reservee - non routable"
    return ""


def extract_snippet(source: str, value: str, span: int = 150) -> str:
    """Extrait le contexte source autour de la 1re occurrence, pour que
    l'analyste retrouve l'IOC dans le message."""
    if not source or not value:
        return ""
    i = source.find(value)
    if i < 0:
        return ""
    a = max(0, i - span // 2)
    b = min(len(source), i + len(value) + span // 2)
    frag = " ".join(source[a:b].split())
    return ("..." if a > 0 else "") + frag + ("..." if b < len(source) else "")


def make_ioc(value: str, type_: str, origin: str, context: str = "", source: str = "") -> dict:
    """Fabrique un IOC annote : type/categorie MISP, provenance, actionnabilite."""
    value = value.strip()
    reason = ""
    if type_ == "ip-src":
        reason = non_actionable_ip(value)
    elif type_ == "url":
        if url_host(value) in NAMESPACE_HOSTS:
            reason = "namespace XML/DTD - pas un IOC"
    elif type_ == "email-dst":
        reason = "destinataire (victime) - ne pas bloquer"
    elif type_ == "email-message-id":
        reason = "identifiant unique du message - non bloquant"
    return {
        "value": value,
        "display": defang(value),
        "type": type_,
        "category": IOC_TYPE_CATEGORY.get(type_, "Other"),
        "origins": [origin],
        "context": context or origin_label(origin),
        "snippet": defang(extract_snippet(source, value)),
        "to_ids": not reason,
        "reason": reason or None,
        "occurrences": 1,
        "_rank": origin_rank(origin),
    }


def merge_iocs(records: list) -> list:
    """Fusionne par (valeur, type) : union des origines, contexte et extrait
    de l'origine la plus significative."""
    merged = {}
    for r in records:
        key = (r["value"], r["type"])
        cur = merged.get(key)
        if cur is None:
            merged[key] = r
            continue
        for o in r["origins"]:
            if o not in cur["origins"]:
                cur["origins"].append(o)
        cur["occurrences"] += r["occurrences"]
        if r["_rank"] < cur["_rank"]:
            cur["context"] = r["context"]
            cur["snippet"] = r["snippet"] or cur["snippet"]
            cur["_rank"] = r["_rank"]
    out = []
    for r in merged.values():
        r["origins"].sort(key=origin_rank)
        r.pop("_rank", None)
        out.append(r)
    return out


def scan_region(text: str, origin: str, source: str, context: str = "") -> list:
    """Extrait URLs / IPs / emails d'une zone, toutes rattachees a une origine."""
    recs = []
    for u in URL_RE.findall(text):
        recs.append(make_ioc(clean_url(u), "url", origin, context, source))
    for ip in IP_RE.findall(text):
        if valid_ipv4(ip):
            recs.append(make_ioc(ip, "ip-src", origin, context, source))
    for a in EMAIL_RE.findall(text):
        # type generique : une adresse citee dans un corps n'est pas l'expediteur
        recs.append(make_ioc(a, "email", origin, context, source))
    return recs


def meta_origin(m) -> str:
    prop = re.search(r'\b(?:property|name)\s*=\s*["\']([^"\']+)["\']', m.group(0), re.I)
    return f"body.html.meta[{prop.group(1)}]" if prop else "body.html.meta"


def consume(src: str, pattern: str, origin_of):
    """Retire du source les zones correspondant au motif et renvoie
    (reste, [(origine, zone)]). Le remplacement conserve la longueur."""
    found = []

    def repl(m):
        found.append((origin_of(m), m.group(0)))
        return " " * (m.end() - m.start())

    return re.sub(pattern, repl, src, flags=re.I | re.S), found


def collect_html_iocs(html_src: str) -> list:
    """Passes ordonnees sur le source HTML : chaque zone reconnue est retiree
    du reste, pour qu'un IOC soit rattache a son role exact et une seule fois."""
    steps = [
        (r"<!--.*?-->", lambda m: "body.html.comment"),
        (r"<meta\b[^>]*>", meta_origin),
        (r"<style\b[^>]*>.*?</style>", lambda m: "body.html.style"),
        (r"""\bstyle\s*=\s*"[^"]*"|\bstyle\s*=\s*'[^']*'""", lambda m: "body.html.style"),
        (r"<a\b[^>]*>", lambda m: "body.html.href"),
        (r"<img\b[^>]*>", lambda m: "body.html.img"),
        (r"<[^>]+>", lambda m: "body.html.other"),
    ]
    recs, rest = [], html_src
    for pattern, origin_of in steps:
        rest, found = consume(rest, pattern, origin_of)
        for origin, region in found:
            recs += scan_region(region, origin, html_src)
    recs += scan_region(rest, "body.html.text", html_src)
    return recs


def collect_iocs(data: dict, auth: dict, body_text: str, body_html: str) -> dict:
    """IOCs annotes issus des en-tetes, des deux corps et des noms de PJ."""
    from email.utils import getaddresses

    raw = data.get("raw_headers") or ""
    recs = []

    # 1. En-tetes d'adresses (getaddresses gere les formes 'Nom <adresse>')
    from_domain = ""
    for key, origin, type_ in (
        ("from", "header.from", "email-src"),
        ("sender_display", "header.sender_display", "email-src"),
        ("to", "header.to", "email-dst"),
        ("cc", "header.cc", "email-dst"),
        ("reply_to", "header.reply_to", "email-reply-to"),
        ("return_path", "header.return_path", "email-src"),
        ("message_id", "header.message_id", "email-message-id"),
    ):
        value = data.get(key)
        if not value:
            continue
        for _, addr in getaddresses([str(value)]):
            if "@" not in addr:
                continue
            domain = addr.rsplit("@", 1)[1].lower()
            if key == "from":
                from_domain = domain
            context = ""
            if key == "reply_to" and from_domain and domain != from_domain:
                context = ("Adresse de reponse (Reply-To) - domaine different du From, "
                           "detournement de reponse possible")
            recs.append(make_ioc(addr, type_, origin, context, raw))

    # 2. IP declaree par le Received-SPF : l'emetteur reel vu par le destinataire
    if auth.get("spf_client_ip"):
        verdict = auth.get("spf_result") or "?"
        recs.append(make_ioc(
            auth["spf_client_ip"], "ip-src", "header.received_spf",
            f"IP emettrice declaree SPF (SPF {verdict})", raw))

    # 3. Chemin Received : le saut le plus ancien porte l'origine declaree
    hops = RECEIVED_RE.findall(raw)
    for n, hop in enumerate(hops, 1):
        context = ""
        if n == len(hops) > 1:
            context = f"Saut Received n{n} - le plus ancien, origine declaree"
        for ip in IP_RE.findall(hop):
            if valid_ipv4(ip):
                recs.append(make_ioc(ip, "ip-src", f"header.received[{n}]", context, raw))

    # 4/5. Corps. Le HTML est desechappe d'abord, sinon chaque URL ressort en
    # double (variante &amp; et variante &).
    recs += scan_region(body_text, "body.text", body_text)
    if body_html:
        from html import unescape
        html_src = unescape(body_html)
        recs += collect_html_iocs(html_src)

    # 6. Noms de PJ (une URL ou une adresse peut s'y cacher)
    for att in data.get("attachments") or []:
        name = att.get("name") or ""
        recs += scan_region(name, "attachment.name", name)

    out = {"urls": [], "ips": [], "emails": []}
    for r in merge_iocs(recs):
        out[IOC_BUCKET[r["type"]]].append(r)
    for bucket in out.values():
        bucket.sort(key=lambda r: (not r["to_ids"], r["value"]))
    return out


def analyse_headers(raw: str) -> dict:
    out = {"spf": None, "dkim": None, "dmarc": None, "received_path": [],
           "spf_client_ip": None, "spf_result": None}
    for line in raw.splitlines():
        low = line.lower()
        if "received-spf:" in low and out["spf"] is None:
            spf = line.split(":", 1)[1].strip()
            out["spf"] = spf[:200]
            out["spf_result"] = spf.split(None, 1)[0] if spf else None
            m = re.search(r"client-ip=([0-9.]+)", spf, re.I)
            if m and valid_ipv4(m.group(1)):
                out["spf_client_ip"] = m.group(1)
        if "dkim=" in low and out["dkim"] is None:
            m = re.search(r"dkim=(\w+)", low)
            out["dkim"] = m.group(1) if m else None
        if "dmarc=" in low and out["dmarc"] is None:
            m = re.search(r"dmarc=(\w+)", low)
            out["dmarc"] = m.group(1) if m else None
        if low.startswith("received:") or low.startswith("\treceived:"):
            out["received_path"].append(line.strip()[:200])
    return out


def render_html(report: dict) -> str:
    """Genere un rapport HTML autonome. Le corps HTML d'origine est affiche
    dans une iframe sandboxée (pas de script, pas de reseau)."""
    from html import escape
    import base64

    ar = report["auth_results"]
    io = report["iocs"]

    def badge(val):
        v = (str(val) or "").lower()
        col = "#2e7d32" if "pass" in v else ("#c62828" if v not in ("none", "") else "#757575")
        return f'<span style="background:{col};color:#fff;padding:2px 8px;border-radius:4px">{escape(str(val))}</span>'

    rows = "".join(
        f"<tr><th>{escape(k)}</th><td>{escape(str(v) or '-')}</td></tr>"
        for k, v in [
            ("Sujet", report["subject"]), ("Date", report["date"]),
            ("From (affiche)", report["sender_display"]), ("From (entete)", report["from"]),
            ("Reply-To", report["reply_to"]), ("Return-Path", report["return_path"]),
            ("To", report["to"]), ("Cc", report.get("cc")),
            ("Message-ID", report["message_id"]),
        ])

    def ioc_block(title, key):
        actionable = [r for r in io[key] if r["to_ids"]]
        discarded = [r for r in io[key] if not r["to_ids"]]
        rows = ""
        for r in actionable:
            snip = (f"<br><span class='snip'>{escape(r['snippet'])}</span>"
                    if r["snippet"] else "")
            rows += (f"<tr><td><code>{escape(r['display'])}</code>{snip}</td>"
                     f"<td>{escape(r['type'])}</td>"
                     f"<td>{escape(r['context'])}</td></tr>")
        body = (f"<table><tr><th>Valeur</th><th>Type</th><th>Origine / contexte</th></tr>"
                f"{rows}</table>" if rows else "<p>-</p>")
        if discarded:
            drows = "".join(
                f"<tr><td><code>{escape(r['display'])}</code></td>"
                f"<td>{escape(r['type'])}</td><td>{escape(r['reason'])}</td></tr>"
                for r in discarded)
            body += (f"<details class='muted'><summary>{len(discarded)} non actionnable(s)"
                     f"</summary><table>{drows}</table></details>")
        return f"<h3>{title} ({len(actionable)})</h3>{body}"

    iocs_html = "".join(ioc_block(t, k) for t, k in
                        (("URLs", "urls"), ("IPs", "ips"), ("Emails", "emails")))

    att_rows = ""
    for a in report["attachments"]:
        flags = []
        if a.get("risky"):
            flags.append('<span style="color:#c62828">RISQUE</span>')
        if a.get("vba_macros"):
            flags.append('<span style="color:#c62828">MACROS VBA</span>')
        vba = "<br>".join(escape(s) for s in a.get("vba_suspicious", []))
        att_rows += (f"<tr><td>{escape(a['name'])}</td><td>{a['size']}</td>"
                     f"<td>{' '.join(flags) or '-'}</td>"
                     f"<td style='font-family:monospace;font-size:11px'>{a['sha256']}"
                     + (f"<br><b>{vba}</b>" if vba else "") + "</td></tr>")

    received = "".join(f"<li><code>{escape(r)}</code></li>" for r in ar["received_path"]) or "<li>-</li>"

    # corps HTML d'origine, isole dans une iframe sandbox (aucun script/reseau)
    b64 = base64.b64encode((report["body_html"] or "").encode("utf-8")).decode()
    iframe = (f'<iframe sandbox="" src="data:text/html;base64,{b64}" '
              'style="width:100%;height:500px;border:1px solid #ccc"></iframe>'
              if report["body_html"] else "<p>(pas de corps HTML)</p>")

    return f"""<!doctype html><html lang="fr"><head><meta charset="utf-8">
<title>Triage IR - {escape(report['subject'] or '')}</title>
<style>
body{{font-family:system-ui,Arial,sans-serif;max-width:1000px;margin:auto;padding:20px;color:#222}}
h1{{border-bottom:3px solid #c62828}} h2{{margin-top:30px;color:#444;border-bottom:1px solid #ddd}}
table{{border-collapse:collapse;width:100%}} th,td{{border:1px solid #ddd;padding:6px;text-align:left;vertical-align:top}}
th{{background:#f5f5f5;white-space:nowrap}} code{{background:#f0f0f0;padding:1px 4px;border-radius:3px}}
pre{{background:#f8f8f8;padding:10px;border:1px solid #ddd;white-space:pre-wrap;word-break:break-word}}
.warn{{background:#fff3e0;border-left:4px solid #ef6c00;padding:10px;margin:10px 0}}
h3{{margin:18px 0 6px;font-size:15px;color:#555}}
.snip{{color:#666;font-size:11px;font-family:monospace;word-break:break-all}}
.muted{{margin-top:6px}} .muted table{{opacity:.6}}
.muted summary{{cursor:pointer;color:#757575;font-size:13px}}
</style></head><body>
<h1>Triage IR - .MSG</h1>
<div class="warn">Rapport defang : les URLs sont en <code>hxxp(s)</code>. Le corps HTML d'origine est isole dans une iframe <b>sandbox</b> (scripts et reseau bloques).</div>
<p><b>Fichier :</b> {escape(report['file'])} &mdash; <b>SHA256 :</b> <code>{report['file_hashes']['sha256']}</code></p>

<h2>Metadonnees</h2><table>{rows}</table>

<h2>Authentification</h2>
<p>SPF : {badge(ar['spf'])} &nbsp; DKIM : {badge(ar['dkim'])} &nbsp; DMARC : {badge(ar['dmarc'])}</p>
<details><summary>Chemin Received</summary><ul>{received}</ul></details>

<h2>IOCs</h2>
<p>Chaque IOC porte son origine dans le message. Les valeurs non exploitables en detection
(IP de transit, namespace XML, destinataire) sont regroupees a part.</p>
{iocs_html}

<h2>Pieces jointes ({len(report['attachments'])})</h2>
<table><tr><th>Nom</th><th>Taille</th><th>Flags</th><th>SHA256 / VBA</th></tr>{att_rows}</table>

<h2>Corps du message (texte brut)</h2>
<pre>{escape(report['body_text'] or '(vide)')}</pre>

<h2>Corps du message (HTML rendu - sandbox)</h2>
{iframe}

<h2>Source HTML</h2>
<p>Source defangee, pour retrouver un IOC qui n'apparait pas a la lecture (metadonnee,
commentaire, CSS).</p>
<details><summary>Afficher</summary><pre>{escape(report['body_html'] or '(aucun corps HTML)')}</pre></details>

<h2>En-tetes bruts</h2>
<details><summary>Afficher</summary><pre>{escape(report['raw_headers'])}</pre></details>

</body></html>"""


def render_text(report: dict, dump=None) -> str:
    """Rapport lisible en texte brut (terminal ou fichier .txt)."""
    L = []
    p = L.append
    p(f"\n{'='*70}\n  TRIAGE IR : {report['subject']}\n{'='*70}")
    p(f"Fichier       : {report['file']}")
    p(f"SHA256 fichier: {report['file_hashes']['sha256']}")
    p(f"Date          : {report['date']}")
    p(f"From (affiche): {report['sender_display']}")
    p(f"From (entete) : {report['from']}")
    p(f"Reply-To      : {report['reply_to']}")
    p(f"Return-Path   : {report['return_path']}")
    p(f"To            : {report['to']}")
    if report.get("cc"):
        p(f"Cc            : {report['cc']}")
    p(f"Message-ID    : {report['message_id']}")

    ar = report["auth_results"]
    p(f"\n-- Authentification --")
    p(f"SPF   : {ar['spf']}\nDKIM  : {ar['dkim']}\nDMARC : {ar['dmarc']}")
    if ar["received_path"]:
        p(f"Saut Received le + ancien : {ar['received_path'][-1]}")

    io = report["iocs"]
    p(f"\n-- IOCs (defanged) --")
    for title, key in (("URLs", "urls"), ("IPs", "ips"), ("Emails", "emails")):
        actionable = [r for r in io[key] if r["to_ids"]]
        discarded = [r for r in io[key] if not r["to_ids"]]
        p(f"\n{title} : {len(actionable)} actionnable(s)"
          + (f", {len(discarded)} ecarte(s)" if discarded else ""))
        for r in actionable or []:
            p(f"   {r['display']}")
            p(f"      [{r['type']}] {r['context']}")
        if not actionable:
            p("   -")
        for r in discarded:
            p(f"   (ecarte) {r['display']}  -> {r['reason']}")

    atts = report["attachments"]
    p(f"\n-- Pieces jointes ({len(atts)}) --")
    for a in atts:
        flag = "  [!] RISQUE" if a.get("risky") else ""
        macro = "  [!] MACROS VBA" if a.get("vba_macros") else ""
        p(f" * {a['name']} ({a['size']} o){flag}{macro}")
        p(f"     sha256: {a['sha256']}")
        for s in a.get("vba_suspicious", []):
            p(f"     VBA> {s}")
    if not atts:
        p(" (aucune)")
    if dump:
        p(f"\nPJ extraites dans : {dump}")

    p(f"\n-- Corps du message (texte) --")
    p(report["body_text"] or "(vide)")
    return "\n".join(L) + "\n"


def render_iocs(report: dict) -> str:
    """Liste plate d'IOCs defanges, une par ligne (import SIEM / blocage)."""
    io = report["iocs"]
    L = [f"# IOCs - {report['file']}", f"# {report['subject']}",
         "# Seuls les IOCs actionnables (to_ids) sont exportes.", ""]
    for title, key in (("URLs", "urls"), ("IPs", "ips"), ("Emails", "emails")):
        rows = [r for r in io[key] if r["to_ids"]]
        L.append(f"[{title}]")
        L += [f"{r['display']}  # {r['context']}" for r in rows] or ["-"]
        L.append("")
    L.append("[Hashes PJ - SHA256]")
    L += [f"{a['sha256']}  {a['name']}" for a in report["attachments"]] or ["-"]
    return "\n".join(L) + "\n"


def slugify(name: str) -> str:
    """Normalise un nom de fichier en nom de dossier sur (ASCII, sans espace)."""
    import unicodedata
    stem = Path(name).stem
    stem = unicodedata.normalize("NFKD", stem).encode("ascii", "ignore").decode()
    stem = re.sub(r"[^A-Za-z0-9._-]+", "_", stem).strip("._-")
    return (stem or "message")[:100]


def export_all(report: dict, src_path: str, blobs: list) -> None:
    """--all : genere tous les livrables dans output/<nom-normalise>/."""
    root = Path(__file__).resolve().parent / "output"
    outdir = root / slugify(src_path)
    attdir = outdir / "attachments"
    outdir.mkdir(parents=True, exist_ok=True)

    created = []

    def rel(p: Path) -> str:
        try:
            return str(p.relative_to(Path.cwd()))
        except ValueError:
            return str(p)

    f = outdir / "rapport.html"
    f.write_text(render_html(report), encoding="utf-8")
    created.append((rel(f), "rapport HTML (corps en iframe sandbox)"))

    f = outdir / "rapport.txt"
    f.write_text(render_text(report, attdir if report["attachments"] else None), encoding="utf-8")
    created.append((rel(f), "rapport texte"))

    f = outdir / "rapport.json"
    f.write_text(json.dumps(report, indent=2, ensure_ascii=False, default=str), encoding="utf-8")
    created.append((rel(f), "export JSON complet"))

    f = outdir / "iocs.txt"
    f.write_text(render_iocs(report), encoding="utf-8")
    created.append((rel(f), "IOCs defanges (URLs/IPs/emails/hashes)"))

    f = outdir / "headers.txt"
    f.write_text(report["raw_headers"] or "(aucun)", encoding="utf-8")
    created.append((rel(f), "en-tetes SMTP bruts"))

    if report["body_html"]:
        # Extension .txt volontaire : un .html s'ouvrirait dans un navigateur au
        # double-clic et executerait ses scripts, que defang() ne neutralise pas.
        f = outdir / "corps_html_source.txt"
        f.write_text(report["body_html"], encoding="utf-8")
        created.append((rel(f), "source HTML defangee (greppable)"))

    if blobs:
        attdir.mkdir(parents=True, exist_ok=True)
        for name, blob in blobs:
            safe = slugify(name) + Path(name).suffix
            (attdir / safe).write_bytes(blob)
            created.append((rel(attdir / safe), f"piece jointe ({len(blob)} o)"))

    print(f"\nExport termine -> {rel(outdir)}/\n")
    width = max(len(c[0]) for c in created)
    for path, desc in created:
        print(f"  {path.ljust(width)}   {desc}")
    print(f"\n{len(created)} fichier(s) cree(s).\n")


def load_msg(path: str) -> dict:
    """Charge un .msg (format Outlook/OLE) vers la structure normalisee."""
    try:
        import extract_msg
    except ImportError:
        sys.exit("Manque extract-msg : pip install extract-msg")
    m = extract_msg.openMsg(path)
    atts = []
    for att in m.attachments:
        data = att.data if isinstance(att.data, bytes) else b""
        name = att.longFilename or att.shortFilename or "unknown"
        atts.append({"name": name, "data": data})
    out = {
        "subject": m.subject,
        "date": str(m.date),
        "sender_display": m.sender,
        "from": m.header.get("From") if m.header else None,
        "reply_to": m.header.get("Reply-To") if m.header else None,
        "return_path": m.header.get("Return-Path") if m.header else None,
        "to": m.to,
        "cc": m.cc,
        "message_id": m.messageId,
        "raw_headers": m.headerText or "",
        "body_text": m.body or "",
        "body_html": m.htmlBody.decode("utf-8", "ignore") if m.htmlBody else "",
        "attachments": atts,
    }
    m.close()
    return out


def load_eml(path: str) -> dict:
    """Charge un .eml (RFC822) via le module standard email."""
    import email
    from email import policy
    with open(path, "rb") as f:
        msg = email.message_from_binary_file(f, policy=policy.default)

    raw_headers = "".join(f"{k}: {v}\n" for k, v in msg.items())
    body_text, body_html = "", ""
    atts = []
    for part in msg.walk():
        if part.is_multipart():
            continue
        ctype = part.get_content_type()
        disp = (part.get_content_disposition() or "").lower()
        filename = part.get_filename()
        if disp == "attachment" or filename:
            data = part.get_payload(decode=True) or b""
            atts.append({"name": filename or "unknown", "data": data})
            continue
        try:
            content = part.get_content()
        except Exception:
            content = part.get_payload(decode=True)
            content = content.decode("utf-8", "ignore") if isinstance(content, bytes) else ""
        if ctype == "text/plain":
            body_text += content
        elif ctype == "text/html":
            body_html += content

    def hdr(name):
        v = msg[name]
        return str(v) if v is not None else None

    return {
        "subject": hdr("Subject"),
        "date": hdr("Date"),
        "sender_display": hdr("From"),
        "from": hdr("From"),
        "reply_to": hdr("Reply-To"),
        "return_path": hdr("Return-Path"),
        "to": hdr("To"),
        "cc": hdr("Cc"),
        "message_id": hdr("Message-ID"),
        "raw_headers": raw_headers,
        "body_text": body_text,
        "body_html": body_html,
        "attachments": atts,
    }


def load_message(path: str) -> dict:
    """Dispatcher : choisit le parseur selon l'extension."""
    return load_eml(path) if path.lower().endswith(".eml") else load_msg(path)


def main():
    ap = argparse.ArgumentParser(description="Triage IR d'un fichier .msg / .eml")
    ap.add_argument("msg", help="chemin du fichier .msg ou .eml")
    ap.add_argument("--dump-dir", help="dossier ou extraire les PJ (sans exécution)")
    ap.add_argument("--json", action="store_true", help="sortie JSON brute")
    ap.add_argument("--html", metavar="FICHIER", help="genere un rapport HTML")
    ap.add_argument("--all", action="store_true",
                    help="genere tous les livrables dans output/<nom-normalise>/")
    args = ap.parse_args()

    data = load_message(args.msg)
    report = {
        "schema_version": 2,
        "file": args.msg,
        "file_hashes": hashes(Path(args.msg).read_bytes()),
        "subject": data["subject"],
        "date": data["date"],
        "sender_display": data["sender_display"],
        "from": data["from"],
        "reply_to": data["reply_to"],
        "return_path": data["return_path"],
        "to": data["to"],
        "cc": data.get("cc"),
        "message_id": data["message_id"],
    }

    raw_headers = data["raw_headers"]
    report["auth_results"] = analyse_headers(raw_headers)

    body_text = data["body_text"] or ""
    body_html = data["body_html"] or ""
    if not body_text.strip() and body_html:
        # pas de version texte : on derive un texte lisible depuis le HTML
        txt = re.sub(r"(?is)<(script|style).*?</\1>", "", body_html)
        txt = re.sub(r"(?i)<br\s*/?>|</p>|</div>|</tr>", "\n", txt)
        txt = re.sub(r"<[^>]+>", "", txt)
        from html import unescape
        txt = unescape(txt)
        body_text = "\n".join(l.strip() for l in txt.splitlines() if l.strip())
        body_text = "[derive du HTML]\n" + body_text
    # IOCs extraits AVANT defang (sinon le regex http(s) ne matche plus)
    report["iocs"] = collect_iocs(data, report["auth_results"], body_text, body_html)
    # On defang les corps stockes : liens non cliquables dans l'iframe HTML
    # (href/src casses) et dans le texte.
    report["raw_headers"] = defang(raw_headers)
    report["body_text"] = defang(body_text)
    report["body_html"] = defang(body_html)

    dump = Path(args.dump_dir) if args.dump_dir else None
    if dump:
        dump.mkdir(parents=True, exist_ok=True)

    atts = []
    blobs = []
    for att in data["attachments"]:
        blob = att["data"] if isinstance(att["data"], bytes) else b""
        name = att["name"] or "unknown"
        blobs.append((name, blob))
        ext = Path(name).suffix.lower()
        info = {"name": name, "ext": ext, "risky": ext in RISKY_EXT, **hashes(blob)}

        # Scan macros VBA si Office/OLE
        if blob:
            try:
                from oletools.olevba import VBA_Parser
                vba = VBA_Parser(name, data=blob)
                if vba.detect_vba_macros():
                    macros = [code for _, _, _, code in vba.extract_macros()]
                    results = vba.analyze_macros()
                    info["vba_macros"] = True
                    info["vba_suspicious"] = [r[2] for r in results if r[0] in ("Suspicious", "AutoExec", "IOC")]
                vba.close()
            except Exception as e:
                info["vba_scan_error"] = str(e)

        if dump and blob:
            (dump / name.replace("/", "_")).write_bytes(blob)
        atts.append(info)
    report["attachments"] = atts

    if args.all:
        export_all(report, args.msg, blobs)
        return

    if args.json:
        print(json.dumps(report, indent=2, ensure_ascii=False, default=str))
        return

    if args.html:
        Path(args.html).write_text(render_html(report), encoding="utf-8")
        print(f"Rapport HTML genere : {args.html}")
        return

    print(render_text(report, dump))


if __name__ == "__main__":
    main()
