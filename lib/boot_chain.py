#!/usr/bin/env python3
"""Boot chain for the dual-boot setup ramdisk and OS B, sent to a device in pwned DFU.
usbliter8ctl boot iBSS.raw -> iBEC.img4 + go -> firmware... -> ramdisk -> devicetree -> rsepfirmware
-> kernel -> bootx.  Unlike `irecovery -c`, every command is sent with a control transfer whose STALL
(= iBoot rejected the command) is detected; the chain stops before bootx on any failure."""
import os, re, subprocess, sys, time
import usb.core

HERE = os.path.dirname(os.path.abspath(__file__))
JB = os.path.dirname(HERE)
sys.path.insert(0, HERE)
import osbcfg
from ibss_handoff import boot_ibss
OSBJB = '--osbjb' in sys.argv   # OS B + jailbreak ramdisk (jbinit as PID 1, jb=md0)
OSB = '--osb' in sys.argv or OSBJB
RESUME = '--resume' in sys.argv   # OS B normal boot instead of the setup ramdisk
SETUP = not OSB
C = osbcfg.work('osbjb' if OSBJB else 'osb' if OSB else 'chain')
CTL = os.environ.get('USBLITER8CTL') or os.path.join(JB, 'tools/usbliter8ctl')
FIRMWARE = [('ANE.img4', 0), ('AOP.img4', 0), ('AVE.img4', 1), ('SPTM.img4', 3), ('TXM.img4', 0),
            ('GFX.img4', 0), ('ISP.img4', 1), ('PMP.img4', 0),
            ('RestoreTrustCache.img4', 0), ('SIO.img4', 0), ('WCH.img4', 0)]
OPTIONAL = {'WCH.img4'}             # wireless-charging firmware: iPads have none

def recovery(timeout=40, hint=''):
    """a Recovery device whose string descriptors answer (a half-torn-down one after `go` does not)"""
    end = time.time() + timeout
    while time.time() < end:
        d = usb.core.find(idVendor=0x05ac, idProduct=0x1281)
        if d:
            try:
                if 'CPID:8030' in (d.serial_number or ''): return d
            except (ValueError, usb.core.USBError):
                pass
            usb.util.dispose_resources(d)
        time.sleep(0.5)
    sys.exit("!! no (healthy) Recovery device" + (f"\n   {hint}" if hint else ""))

def gone(timeout=15):
    end = time.time() + timeout
    while time.time() < end:
        if not usb.core.find(idVendor=0x05ac, idProduct=0x1281): return True
        time.sleep(0.3)
    return False

def upload(name):
    for attempt in range(4):              # libirecovery sometimes can't open the device right after a command
        r = subprocess.run(['irecovery', '-f', os.path.join(C, name)], capture_output=True, text=True)
        if not r.returncode: return
        print(f"   upload {name} attempt {attempt + 1} failed: {r.stderr.strip()[-120:]} - retrying", flush=True)
        time.sleep(2); usb.util.dispose_resources(recovery(30))
    sys.exit(f"!! upload {name} failed: {r.stderr.strip()[-200:]}")

def cmd(c, may_disconnect=False):
    dev = recovery()
    try:
        dev.ctrl_transfer(0x40, 0, 0, 0, c.encode() + b'\0', 30000)
        print(f"   {c:20s} ok", flush=True)
    except usb.core.USBError as e:
        if may_disconnect:
            print(f"   {c:20s} (USB gone: {e}) - expected", flush=True); return
        sys.exit(f"!! '{c}' rejected by iBoot ({e}) - stopping before bootx")
    finally:
        usb.util.dispose_resources(dev)

def send(name, c, pause=0):
    print(f" - {name}", flush=True)
    upload(name); cmd(c)
    if pause: time.sleep(pause)

def main():
    if SETUP and not os.path.isfile(os.path.join(C, 'RestoreLogo.img4')):
        sys.exit('!! setup logo missing; rebuild the setup chain from its IPSW before booting')
    out = subprocess.run(['irecovery', '-q'], capture_output=True, text=True).stdout
    if RESUME:                           # iBEC already up (an earlier run died after [2]): continue from firmware
        if 'NONC:' not in out or 'PWND' in out: sys.exit("--resume needs the device sitting in iBEC")
        print("[resume] iBEC already up - skipping [1]/[2]", flush=True)
        return stages_from_firmware()
    if 'PWND: usbliter8' not in out: sys.exit("device not in pwned DFU")
    print("[1] iBSS (raw)", flush=True)
    # this interpreter (.venv), not `python3` from PATH: setup.sh installs pyusb only into .venv, and a PATH
    # python3 without it dies on `import usb` before sending anything
    ecid = re.search(r'(?m)^ECID:\s*(0x[0-9a-fA-F]+)', out)
    if not ecid:
        sys.exit('!! could not read the pwned iPhone ECID; stopping before iBSS')
    try:
        boot_ibss([sys.executable, '-u', CTL, 'boot', os.path.join(C, 'iBSS.raw')],
                  ecid[1], osbcfg.work('ibss-handoff.log'))
    except RuntimeError as exc:
        sys.exit(f'!! {exc}')
    time.sleep(3)
    print("[2] iBEC + go", flush=True)
    upload('iBEC.img4')
    # `irecovery -c go` (libirecovery ignores the status-stage timeout of the
    # hand-off), then leave the device alone for 2 s instead of polling it while iBSS tears USB down
    handoff = subprocess.run(['irecovery', '-c', 'go'], capture_output=True, text=True)
    if handoff.returncode:
        sys.exit(f"!! could not send go: {(handoff.stderr or handoff.stdout).strip()[-200:]}")
    time.sleep(2)
    disconnected = gone()
    usb.util.dispose_resources(recovery(60)); time.sleep(2)
    print("   Recovery responds after go; USB disconnect " +
          ("observed" if disconnected else "not observed"), flush=True)
    d = recovery()
    color = 'bgcolor 0 191 255' if SETUP else 'bgcolor 0 0 0'
    try:
        d.ctrl_transfer(0x40, 0, 0, 0, color.encode() + b'\0', 30000)
        print(f"   {color}      ok", flush=True)
    except usb.core.USBError as e:
        print(f"   bgcolor rejected ({e}) - continuing", flush=True)
    finally:
        usb.util.dispose_resources(d)    # release the handle, or irecovery -f can't open the device
    stages_from_firmware()

def stages_from_firmware():
    if not OSB and os.path.isfile(os.path.join(C, 'RestoreLogo.img4')):
        send('RestoreLogo.img4', 'setpicture 0x1')
    print("[3] firmware", flush=True)
    for name, pause in FIRMWARE:
        if name in OPTIONAL and not os.path.exists(os.path.join(C, name)):
            print(f" - {name} (not on this board)", flush=True); continue
        send(name, 'firmware', pause)
    if OSB and not OSBJB:
        time.sleep(2)
    else:
        print("[4] ramdisk", flush=True)
        send('RestoreRamdisk.img4', 'ramdisk', 2)
    print("[5] devicetree, SEP, kernel", flush=True)
    send('DeviceTree.img4', 'devicetree')
    send('SEP.img4', 'rsepfirmware')
    print(" - Kernelcache.img4", flush=True); upload('Kernelcache.img4')
    print("[6] bootx", flush=True)
    usb.util.dispose_resources(recovery(10))
    bootx = subprocess.run(['irecovery', '-c', 'bootx'], capture_output=True, text=True)
    if bootx.returncode:
        print(f"   bootx command returned {bootx.returncode}: "
              f"{(bootx.stderr or bootx.stdout).strip()[-200:]}", flush=True)
    time.sleep(10)
    d = usb.core.find(idVendor=0x05ac, idProduct=0x1281)
    if d:
        try:
            back = 'CPID:8030' in (d.serial_number or '')
        except (ValueError, usb.core.USBError):
            back = False
        usb.util.dispose_resources(d)
        if back: sys.exit("!! bootx returned to the Recovery prompt - iBoot rejected the boot (see UART hash lines)")
    print("[+] iBEC left Recovery after bootx; " +
          ("2nd Data boot is not yet verified" if OSB else "ramdisk boot is not yet verified"), flush=True)

if __name__ == '__main__':
    main()
