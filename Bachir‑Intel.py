#!/usr/bin/env python3
# ==========================================================
# Bachir‑Intel  |  FINAL EDITION
# Author : Bachir
# Type   : Legal OSINT Email Intelligence Engine
# ==========================================================

import argparse, hashlib, os, sys, requests, dns.resolver
from datetime import datetime

UA = {"User-Agent": "Bachir-Intel"}
HIBP_KEY = os.getenv("HIBP_API_KEY")

# ---------------- VALIDATION ----------------
def valid_email(e):
    return "@" in e and "." in e.split("@")[-1]

# ---------------- DNS SECURITY ----------------
def dns_security(domain):
    r = {"MX":False,"SPF":False,"DMARC":False}
    try: dns.resolver.resolve(domain,"MX"); r["MX"]=True
    except: pass
    try:
        for x in dns.resolver.resolve(domain,"TXT"):
            if "spf" in str(x).lower(): r["SPF"]=True
    except: pass
    try: dns.resolver.resolve("_dmarc."+domain,"TXT"); r["DMARC"]=True
    except: pass
    return r

# ---------------- HIBP ----------------
def hibp(email):
    if not HIBP_KEY: return []
    h = {"hibp-api-key":HIBP_KEY, **UA}
    r = requests.get(
        f"https://haveibeenpwned.com/api/v3/breachedaccount/{email}",
        headers=h, params={"truncateResponse":"false"}
    )
    if r.status_code != 200: return []
    return [{
        "name":b["Name"],
        "year":int(b["BreachDate"][:4]),
        "data":b["DataClasses"]
    } for b in r.json()]

# ---------------- GRAVATAR ----------------
def gravatar(email):
    h = hashlib.md5(email.strip().lower().encode()).hexdigest()
    r = requests.get(f"https://www.gravatar.com/avatar/{h}?d=404", headers=UA)
    return r.status_code == 200

# ---------------- GITHUB ----------------
def github(email):
    r = requests.get(
        f'https://api.github.com/search/code?q="{email}"',
        headers=UA
    )
    if r.status_code != 200: return 0
    return r.json().get("total_count",0)

# ---------------- PASTE SIGNAL ----------------
def paste_signal(email):
    try:
        r = requests.get(f"https://psbdmp.ws/api/v3/search/{email}",
                         headers=UA, timeout=6)
        return r.status_code == 200 and r.json().get("count",0) > 0
    except:
        return False

# ---------------- RISK ENGINE ----------------
def risk_engine(hibp_r, grav, gh, paste, dnsr):
    score = 0
    reasons = []

    if hibp_r:
        score += 50
        reasons.append("Confirmed public breach")
        if len(hibp_r) > 1:
            score += 10
            reasons.append("Multiple breach events")
        if max(b["year"] for b in hibp_r) >= datetime.now().year-4:
            score += 15
            reasons.append("Recent exposure")

    if paste:
        score += 15
        reasons.append("Email seen in paste leaks")

    if gh > 0:
        score += 10
        reasons.append(f"Email found in GitHub code ({gh})")

    if grav:
        score += 5
        reasons.append("Public Gravatar profile")

    if not dnsr["DMARC"]:
        score += 10
        reasons.append("DMARC not configured")

    if not dnsr["SPF"]:
        score += 5
        reasons.append("SPF not configured")

    level = "HIGH" if score >= 70 else "MEDIUM" if score >= 40 else "LOW"
    return score, level, reasons

# ---------------- REPORT ----------------
def report(email, dnsr, hibp_r, grav, gh, paste, score, level, reasons):
    print("\n========== Bachir‑Intel ==========\n")
    print("Target Email :", email)
    print("Analyst      : Bachir")

    print("\n[ Domain Security ]")
    for k,v in dnsr.items():
        print(f"  {k:<6} :", "OK" if v else "Missing")

    print("\n[ Exposure Evidence ]")
    if hibp_r:
        for b in hibp_r:
            print(f"  - {b['year']} | {b['name']} | {', '.join(b['data'])}")
    else:
        print("  - No confirmed public breaches")

    print(f"  - Gravatar       : {'Yes' if grav else 'No'}")
    print(f"  - GitHub traces  : {gh}")
    print(f"  - Paste signals  : {'Yes' if paste else 'No'}")

    print("\n[ Risk Assessment ]")
    print(f"  Score      : {score}/100")
    print(f"  Confidence : {level}")

    print("\n[ Analyst Notes ]")
    for r in reasons:
        print("  -", r)

    print("\n⚠️  OSINT tool by Bachir | Evidence‑based | Legal use only\n")

# ---------------- MAIN ----------------
def main():
    p = argparse.ArgumentParser(description="Bachir‑Intel OSINT Email Tool")
    p.add_argument("--email", required=True)
    a = p.parse_args()

    if not valid_email(a.email):
        sys.exit("Invalid email format")

    domain = a.email.split("@")[-1]

    dnsr   = dns_security(domain)
    hibp_r = hibp(a.email)
    grav   = gravatar(a.email)
    gh     = github(a.email)
    paste  = paste_signal(a.email)

    score, level, reasons = risk_engine(hibp_r, grav, gh, paste, dnsr)
    report(a.email, dnsr, hibp_r, grav, gh, paste, score, level, reasons)

if __name__ == "__main__":
    main()
