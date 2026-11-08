#!/usr/bin/env python3
"""
Request a personalized APTicket (IM4M) for the connected device from Apple TSS,
using the device's *current* ApNonce/SepNonce (read from recovery via irecovery -q).
Uses pymobiledevice3's TSS client (https://github.com/doronz88/pymobiledevice3).

Usage: get_apticket.py BuildManifest.plist out.im4m [--behavior Update|Erase] [--board d421ap]
"""
import argparse, asyncio, plistlib, re, subprocess, sys
from pymobiledevice3.restore.tss import TSSRequest

KEYS = ["UniqueBuildID", "Ap,OSLongVersion", "Ap,OSReleaseType", "Ap,ProductType", "Ap,SDKPlatform",
        "Ap,SikaFuse", "Ap,Target", "Ap,TargetType", "ApBoardID", "ApChipID", "ApSecurityDomain",
        "Ap,ProductMarketingVersion"]

def irecv_query():
    out = subprocess.run(["irecovery", "-q"], capture_output=True, text=True).stdout
    q = dict(re.findall(r"^(\w+): (.*)$", out, re.M))
    return q

def to_int(v): return int(v, 16) if isinstance(v, str) and v.startswith("0x") else v

async def main():
    ap = argparse.ArgumentParser()
    ap.add_argument("manifest"); ap.add_argument("out")
    ap.add_argument("--behavior", default="Update")
    ap.add_argument("--board", default="d421ap")
    a = ap.parse_args()
    bm = plistlib.load(open(a.manifest, "rb"))
    ids = [i for i in bm["BuildIdentities"]
           if i["Info"]["DeviceClass"].lower() == a.board and i["Info"].get("RestoreBehavior") == a.behavior
           and "Variant" in i["Info"] and "Customer" in i["Info"]["Variant"]]
    if not ids: sys.exit("no identity")
    ident = ids[0]
    print("identity:", ident["Info"]["Variant"])
    q = irecv_query()
    print("device:", q.get("ECID"), q.get("MODE"), "NONC", q.get("NONC"), "SNON", q.get("SNON"))
    params = {
        "ApECID": int(q["ECID"], 16),
        "ApNonce": bytes.fromhex(q["NONC"]),
        "ApSepNonce": bytes.fromhex(q["SNON"]),
        "ApProductionMode": True,
        "ApSecurityMode": True,
        "ApSupportsImg4": True,
        "Manifest": ident["Manifest"],
    }
    for k in KEYS:
        if k in ident: params[k] = to_int(ident[k])
    tss = TSSRequest()
    tss.add_common_tags(params)
    tss.add_ap_tags(params)
    tss.add_ap_img4_tags(params)
    resp = await tss.send_receive()
    ticket = resp.ap_img4_ticket
    open(a.out, "wb").write(ticket)
    print(f"wrote {a.out} ({len(ticket)} bytes)")

asyncio.run(main())
