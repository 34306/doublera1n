# doublera1n: jailbreak your iPhone 11/SE2 by using a new data volume

> [!CAUTION]
> CURRENTLY SUPPORTS iOS: 27.0-27.2 ON MAIN OS

doublera1n runs the phone's own stock System volume (sealed, untouched) with a separated data volume, as `/private/var`. It is booted from pwned DFU (usbliter8) with a patched kernel/iBoot and comes with a rootless jailbreak.

Stock iOS still here. A normal reboot on jailbreak data volume send you to stock iOS, to boot into the jailbreak state again, put the phone into pwned DFU and run `boot.sh`.

This resolve 2 problems I faced while using CFW: storage (which dualboot eats a lot) and cfw (which reboot turns your device into recovery mode).

But this is not a great solution, since SEP is disable for 2nd data partition, you can't login into iCloud on this, but luckily, FairPlay still works, which means application works well.

<p align="center">
  <img src="demo.jpg" width="360" alt="iPhone 11 Pro on iOS 27.2 booted into 2nd Data: App Store signed in, Sileo and Filza on the home screen, windowed apps">
</p>

## Quick start
```
git clone https://github.com/34306/doublera1n.git
cd doublera1n
./boot.sh
```
That's it. Plug the iPhone in booted into iOS (its version is read automatically), then put it into pwned DFU when it asks. The first time `boot.sh` installs 2nd Data (it asks for pwned DFU once more for the first boot), every time after it just boots 2nd Data.

Updated stock iOS? Plug the iPhone in booted into the new iOS and run `./boot.sh`: 2nd Data is rebuilt for the new build and DataB (apps, data, jailbreak) is kept. *(developing feature, not device-tested yet)*

On first use it runs `./setup.sh` by itself, which installs the Homebrew tools (libimobiledevice, libirecovery, ldid, libusb, ipsw) and creates `.venv` from `requirements.txt`. `.venv/` is machine-local, run `./setup.sh` again any time to repair it (if needed).

Prefer a menu? `./dualboot.sh` (↑/↓ select, Enter run):

| Menu | What it does |
|---|---|
| Start | same as `./boot.sh`: installs 2nd Data the first time, boots it after |
| SSH into 2nd Data | `ssh root@` through iproxy (pinned to the phone's UDID) |
| Re-apply fixes | pushes every userland fix again over SSH (2nd Data running) |
| Remove 2nd Data | deletes DataB and our files in Preboot, back to a single stock OS |
| Dualboot: 2nd iOS | **developing feature**: another iOS 27.x on its own volumes, see below |
| More | pick the iOS version by hand, status / check the Mac, run `setup.sh` again |

> [!WARNING]
> When setting up 2nd Data, if the iPhone asks **iPhone Partially Set Up**, choose **Continue with Partial Setup**. Do NOT choose **Erase and Start Over**.

I also fixed a lot of problems such as Wifi did not auto connect when reboot, deep sleep panic the device, SEP-less panic stuff, etc. You can check patches i did in the repo as well.

## Dualboot: a 2nd iOS (developing feature)
> [!NOTE]
> **Developing feature.** The code is in, but it has not been booted on a device yet. Expect bugs.

Besides 2nd Data (stock System + DataB), you can add a second iOS 27.x build on its own volumes:
- `OS2System`: the system files of that build, `OS2Data`: its `/private/var`
- its cryptex content (dyld shared cache) in `Preboot:/Cryptexes/ob/os2/<build>`

Stock iOS and DataB are not touched, and a normal reboot still goes to stock iOS. 2nd Data has to be installed and running (the files are copied over SSH). You need about 22 GB free on the phone and about 30 GB on the Mac (IPSW + decrypted images).

```
./dualboot.py os2 install --build <build>   # 2nd Data running
./dualboot.py os2 boot                      # pwned DFU
./dualboot.py os2 remove                    # 2nd Data running
```
"Remove 2nd Data" refuses while a 2nd iOS is installed (both use the same folder in Preboot): remove the 2nd iOS first.

## Requirements
- A Mac (support both Apple silicon and Intel) with Homebrew. `setup.sh` installs libimobiledevice, libirecovery, ldid, libusb, [ipsw](https://github.com/blacktop/ipsw) and creates `.venv`.
- A usbliter8 board (RP2350) for pwned DFU. I'd recommend using the board i put the image below.
- A13: iPhone SE 2 (iPhone12,8, d79ap), iPad 9 Wi-Fi / Cellular (iPad12,1 j181ap / iPad12,2 j182ap), for iPad 9: added support but untested.
- Any iOS 27.x build of that iPhone. 2nd Data always runs the build installed on the phone (i might be extend to iOS 26 soon?).

## Untested iOS version

Every patch site is found again in the IPSW of the build you pick. If Apple changes a patched function too much, wait for me until I update and support it. Only iPhone 11 Pro on 27.2 (24B119) has booted so far, Issues, PR are welcome if it broken for you.

**Pre-check** (`lib/precheck.py`) runs before anything touches the phone: it pulls only BuildManifest, kernelcache, TXM, iBSS, iBEC and DeviceTree (~70 MB) with `ipsw extract --remote`, builds the profile, applies every patch and checks TSS. Release builds come from ipsw.me, betas and RCs from AppleDB. If your build is on neither, give the IPSW yourself (file or URL).

```
./dualboot.py versions                                   # local profiles + Apple's builds
./dualboot.py select --auto                              # read the build from the iPhone (USB)
./dualboot.py select --build 24B5110a                    # any build, betas included
./dualboot.py precheck --build <build> --ipsw <file|URL> # an IPSW you fetched yourself
```

TSS: if Apple doesn't sign the build anymore (old builds, betas), the newest signed build's ticket is used for the setup chain, the patched iBoot doesn't check AP images. Once installed, 2nd Data uses the ticket installed on the phone (read over UART), this UART require you to have this kind of board:

![B4 PICO DFU board (RP2350, Lightning plug + USB-C): pwned DFU and UART over the Lightning port](pico_uart.jpg)

## Credits
- [usbliter8-fun by wh1te4ever](https://github.com/wh1te4ever/usbliter8-fun)
- [usbliter8]() (got deleted)
- [Liter8 by Xplo8E](https://github.com/Xplo8E/Liter8)
- [lycorine by hrtowii](https://github.com/hrtowii/lycorine-public)

## License
doublera1n is MIT, see [LICENSE](LICENSE). Some parts keep their own license.

## Waveshare RP2350-USB-A

![Waveshare RP2350-USB-A](https://www.waveshare.com/media/catalog/product/cache/1/image/800x800/9df78eab33525d08d6e5fb8d27136e95/r/p/rp2350-usb-a-1_1.jpg)

Confirmed on **iPhone 11 (`n104ap`), iOS 27.2.1 (`24B156`)**: setup, jailbroken boot, Sileo provisioning and USB pairing completed successfully. Use the [Waveshare RP2350-USB-A](https://www.waveshare.com/wiki/RP2350-USB-A) and a Lightning-to-USB-A data cable.

1. Download [usbliter8.waveshare_rp2350_usb_a.uf2](https://github.com/JoshAtticus/usbliter8/releases/download/rp2350/usbliter8.waveshare_rp2350_usb_a.uf2) from the [RP2350 firmware release](https://github.com/JoshAtticus/usbliter8/releases/tag/rp2350).
2. Hold the board's **BOOT** button while connecting its USB-C port to the Mac. Release BOOT when a USB drive appears, then copy the `.uf2` file onto that drive. The board restarts, briefly blinks orange, then stays **orange: ready**. Flashing is only needed once.
3. Connect the iPhone directly to the Mac, unlock it and accept Trust. In this repository, run `./boot.sh`. Mac dependencies and firmware downloads are handled automatically.
4. When asked for pwned DFU, leave that command running. In another terminal in this repository, run `./boot.sh --dfu-guide`. It enters Recovery and guides the button timing into DFU.
5. Keep the board powered through USB-C. Connect the DFU iPhone to its USB-A port. **Blue** means the exploit is running; **steady green** means it succeeded. If it turns red, reset the board and retry from DFU.
6. Move the iPhone's cable back to the Mac. The running command continues automatically over USB.
7. The first installation asks for pwned DFU a second time. Force-restart the iPhone into stock iOS, reset the board to orange, and repeat steps 4–6. Keep the original command running until it prints **DONE**, then finish Setup on the phone.

Reset or unplug/reconnect the board before each exploit attempt; you do not need to copy the firmware again. The [usbliter8 instructions](https://github.com/JoshAtticus/usbliter8#exploiting) describe the LED states. A normal iPhone reboot returns to stock iOS. To boot the jailbreak again, enter DFU, use the board until it turns green, reconnect to the Mac and run `./boot.sh`.

The original setup read its completion log and installed APTicket through the iPhone's UART. This board exposes exploit logs instead. The setup ramdisk now starts USB communication through CoreFoundation and IOKit, runs the original installer, and returns its real log and ticket directly to the Mac. The Mac checks the result and device identity before continuing. We also corrected the iBSS handoff, built iBSS and iBEC separately, left display initialization to iBEC on iPhone 11, placed boot arguments in verified padding, and loaded the restore trust cache.

This is the default `./boot.sh` workflow. **`--dfu-guide` is the only added CLI option.** The signed USB relay is included; users do not need to compile it. The original commands and menu remain available.

Downloads, extracted firmware, tickets, SSH keys and logs now live in **`dualboot-work/` inside the repository**, ignored by Git. `DUALBOOT_HOME` still overrides that location.

**SSH:** new installations initialize **`root` / `alpine`** once. Existing passwords are preserved, and key login through `./boot.sh ssh` still works. For a manual USB connection, run `iproxy 2222 22` on the Mac, then `ssh -p 2222 root@localhost` in another terminal. Change the shared default password with `passwd root` before allowing network access. The tool now stops the SSH forwards it starts when its command exits; a manually started `iproxy` stays under your control.
