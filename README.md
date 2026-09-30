# CIP-B103 Lab [#] – Windows Memory Forensics (Volatility)

**Student:** Fuseini Imoru Kantuogaa **Course:** CIP-B103 **Lab:** Lab [#] – Memory Forensics & Data Exfiltration Analysis

## Overview

This lab demonstrates a **memory forensics** workflow: installing Volatility 2 and 3, acquiring a Windows 7 memory image, identifying the operating system and profile, extracting registry, network, process and console artifacts, carving browser evidence, identifying the USB device used, and recovering and cracking local account password hashes. The goal was to determine whether a sensitive file (`secret_file.docx`) was obtained and copied to removable media.

## Case Folder Structure

```bash
cd ~/volatility3        # Volatility 3 and the memory image
cd ~/volatility         # Volatility 2 working directory and output files
```

## 1. Tool Setup

Volatility 3 (framework 2.28.2) was already present in `~/volatility3`:

```bash
cd ~/volatility3
./vol.py -h
```

Volatility 2 (2.6.1) was cloned because the registry, console and Chrome plugins used in this lab are Vol2 plugins:

```bash
git clone https://github.com/volatilityfoundation/volatility.git
cd volatility
python2 vol.py --info
```

`--info` reported import errors for some plugins (`No module named Crypto.Hash` and `name 'distorm3' is not defined`). These come from missing Python 2 dependencies and only affect plugins not used in this lab.

## 2. Acquiring the Memory Image

The memory image was downloaded with `wget` and its size confirmed:

```bash
wget <dropbox-share-link>/memdumpWin7.mem
ls -l memdumpWin7.mem
```

| Property | Value |
|---|---|
| File | memdumpWin7.mem |
| Size | 1,073,676,288 bytes (1024 MB) |
| Download finished | 2026-09-16 05:10:04 (9m 1s, ~2.62 MB/s) |
| Owner / permissions | root:root, `-rw-r--r--` |

## 3. Image Identification

Volatility 3 identified the image and downloaded the matching kernel symbols (`ntkrpamp.pdb`) from the Microsoft symbol server:

```bash
python3 vol.py -f /home/kali/volatility3/volatility/memdumpWin7.mem windows.info
```

| Field | Value |
|---|---|
| Kernel Base | 0x82847000 |
| DTB | 0x185000 |
| Architecture | 32-bit, PAE enabled |
| NTBuildLab | 7601.18939.x86fre.win7sp1_gdr.15 |
| OS version | Windows 7 SP1 (NT 6.1) |
| Processors | 1 |
| SystemTime | 2019-01-06 15:09:06 UTC |

Volatility 2 `imageinfo` suggested the profiles `Win7SP1x86_23418`, `Win7SP0x86`, `Win7SP1x86_24000` and `Win7SP1x86`. The profile `Win7SP1x86_23418` was used for all Vol2 plugins. Other values: KDBG `0x82972c68`, KPCR `0x82973d00`, image local time 2019-01-06 07:09:06 (UTC-8).

## 4. Registry Analysis

The in-memory registry hives were listed and individual keys inspected:

```bash
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 hivelist
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 printkey -K "<key path>"
```

`hivelist` showed SYSTEM, HARDWARE, SOFTWARE, SAM, SECURITY, DEFAULT, BCD, the NTUSER.DAT and UsrClass.dat hives for IEUser and sshd_server, and Syscache.hve.

| Key | Finding |
|---|---|
| ComputerName | IE8WIN7 |
| ProfileList | Profiles for IEUser (RID 1000) and sshd_server (RID 1002) |
| Winlogon (updated 15:02:47 UTC) | AutoAdminLogon = 1, DefaultUserName = IEUser |
| Volatile Environment | USERNAME IEUser, USERDOMAIN IE8WIN7 |
| HARDWARE\DESCRIPTION\System | BIOS strings reference Oracle VM VirtualBox 6.0.0 |
| CurrentControlSet | Link to ControlSet001 |

## 5. Network Analysis

Listening TCP sockets were extracted with `netscan`:

```bash
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 netscan | grep TCPv4
```

| Process | PID | Local Endpoint | State |
|---|---|---|---|
| System | 4 | 192.168.56.8:139 | LISTENING |
| System | 4 | 0.0.0.0:445 | LISTENING |
| svchost.exe | 672 | 0.0.0.0:135 | LISTENING |
| wininit.exe | 340 | 0.0.0.0:49152 | LISTENING |
| svchost.exe | 724 | 0.0.0.0:49153 | LISTENING |
| svchost.exe | 880 | 0.0.0.0:49154 | LISTENING |
| services.exe | 432 | 0.0.0.0:49155 | LISTENING |
| lsass.exe | 440 | 0.0.0.0:49156 | LISTENING |

The machine's address was 192.168.56.8/24 with no default gateway, consistent with a VirtualBox host-only network.

## 6. Process & Console History

Command history and console buffers were recovered:

```bash
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 cmdscan
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 consoles
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 pslist -p 3988
```

- `conhost.exe` PID 2000 was attached to `sshd.exe` (started via `cygrunsrv.exe`) and recorded no commands.
- `conhost.exe` PID 3988 (started 2019-01-06 15:06:11 UTC) was attached to `cmd.exe` PID 3996.

Recovered `cmd.exe` history:

```
C:\Users\IEUser>ipconfig
C:\Users\IEUser>cd Downloads
C:\Users\IEUser\Downloads>copy secret_file.docx F:
        1 file(s) copied.
```

This shows `secret_file.docx` was copied from the Downloads folder to drive `F:`.

## 7. String Carving

Strings containing the suspected server address were carved from the image:

```bash
strings /home/kali/volatility3/volatility/memdumpWin7.mem | grep "192.168.56.5" > process_1.txt
ls -l process_1.txt
xxd process_1.txt | head -n 30
```

`process_1.txt` (13,858 bytes) contained repeated references to `http://192.168.56.5/secret_file.docx` and a Google search URL for the same string.

## 8. Browser Artifacts

`iehistory` returned only cache records for `explorer.exe` (PID 2524) and nothing dated 2019, so Internet Explorer gave no direct evidence. The third-party plugin `chrome_ragamuffin` was installed for Chrome:

```bash
git clone https://github.com/cube0x8/chrome_ragamuffin.git
python2 vol.py --plugins=/home/kali/volatility/chrome_ragamuffin --info | grep -i -E "chrome|history"
```

A string-carving pipeline then built a Chrome history table for the file:

```bash
strings memdumpWin7.mem | grep -E "http://|https://" | grep -i "secret_file.docx" \
  | awk '{print NR "\t" $1 "\tChrome Browser"}' | head -n 10
```

The results show Chrome requests for `http://192.168.56.5/secret_file.docx`, confirming the file was retrieved from 192.168.56.5. A few carved lines showed `192.128.56.5`, which is most likely a fragmentation artifact and is treated as unverified.

## 9. USB Device Analysis

USB registry artifacts were examined:

```bash
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 printkey -K "ControlSet001\Enum\USBSTOR"
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 printkey -K "Software\Microsoft\Windows\CurrentVersion\Explorer\MountPoints2\F"
```

| Artifact | Value |
|---|---|
| USBSTOR entry | Disk&Ven_General&Prod_UDisk&Rev_5.00 |
| Instance ID | 6&1bec0f48&0&_&0 |
| Friendly name | General UDisk USB Device |
| USBSTOR last written | 2019-01-06 15:02:54 UTC |
| MountPoints2\F last written | 2019-01-06 15:03:06 UTC |
| MountedDevices | C:, D:, E: (VBOX CD-ROM) |

This ties drive `F:` to a removable General UDisk USB device connected at about 15:03 UTC.

## 10. Shellbags

```bash
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 shellbags | grep "Last updated: 2019-01-06" | sort
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 shellbags --output=html --output-file=shellbags.html
```

Seven shellbag entries were updated between 14:32 and 15:07 UTC on 2019-01-06. Full output was exported to `shellbags.html`.

## 11. Credential Extraction & Password Cracking

Local account hashes were dumped from the SAM hive:

```bash
python2 vol.py -f $IMG --profile=Win7SP1x86_23418 hashdump
```

Accounts found: Administrator (500), Guest (501), IEUser (1000), sshd (1001), sshd_server (1002). Guest and sshd use the empty-password NT hash. Administrator and IEUser share the same NT hash, meaning the same password.

The shared hash was cracked with John the Ripper:

```bash
echo fc525c9683e8fe067095ba2ddc971889 > ntlmhash.txt
sudo find / -type f -name password.lst
echo 'Passw0rd!' >> /usr/share/john/password.lst
john --format=nt ntlmhash.txt
```

| Hash | Recovered Password |
|---|---|
| fc525c9683e8fe067095ba2ddc971889 | Passw0rd! |

## Reconstructed Timeline (2019-01-06, UTC)

| Time | Event | Source |
|---|---|---|
| 14:32–14:55 | Folder-browsing activity | Shellbags |
| 15:02:47 | IEUser auto-logon configuration updated | Winlogon key |
| 15:02:54 | General UDisk USB registered | USBSTOR |
| 15:03:06 | Drive F: mount point created | MountPoints2 |
| 15:06:11 | cmd.exe / conhost.exe (PID 3988) session starts | pslist |
| After 15:06:11 | `copy secret_file.docx F:` executed | cmdscan / consoles |
| 15:09:06 | Memory image captured | windows.info |

## Key Tools Used

| Tool | Purpose |
|---|---|
| Volatility 3 (`windows.info`) | Image identification and symbol resolution |
| Volatility 2.6.1 | imageinfo, hivelist, printkey, netscan, pslist, cmdscan, consoles, iehistory, shellbags, hashdump |
| chrome_ragamuffin | Chrome process-memory plugin |
| strings / grep / awk / xxd | String carving and filtering |
| john | NT hash cracking |
| wget / git | Image and tool acquisition |

## Forensic Notes

- Console history, Chrome URL strings, and the USBSTOR and MountPoints2 registry keys all point to the same sequence: file downloaded from 192.168.56.5, then copied to a USB drive.
- Registry "last written" times are not necessarily first-connection times.
- The System process start time and some hive timestamps (HARDWARE, BCD at 18:02 UTC) are later than the image capture time (15:09:06 UTC), likely due to VM clock handling, and should be treated with caution in timelines.
- `Passw0rd!` was added to the John wordlist manually before cracking, so the result confirms a hash-to-password match rather than an independent dictionary discovery.
- A SHA-256 hash of `memdumpWin7.mem` was not recorded. `sha256sum memdumpWin7.mem` should be run and saved with the evidence for chain of custody.
