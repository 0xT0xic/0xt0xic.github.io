---
title: "TryHackMe - Security Footage"
date: 2025-05-17 00:00:00 +0800
categories: [TryHackMe]
tags: [Hacking, CTF, Pentesting, TryHackMe, THM, Medium, Analysis, Wireshark, Python3, DFIR, Blue]
author: 0xT0xic
image:
    path: https://i.ibb.co/QvXRTjXx/footage3.png
---

Security Footage is a medium-difficulty TryHackMe challenge focused on basic digital forensics. The objective is to analyze a .pcap file and recover a camera stream that was transmitted using MJPEG, which is essentially a series of JPEG images.

## Analyzing the PCAP File

After downloading the provided files, we find a file named security-footage-xxxxx.pcap. This file is opened using Wireshark, a network traffic analysis tool.

<img src="https://i.ibb.co/WNnWBkVJ/1.png" alt="Footage" width="700">

Within the capture, we notice a single HTTP GET request sent to IP 192.168.1.100 on port 8081. Alongside this, there are a large number of TCP packets in the capture.

<img src="https://i.ibb.co/zVYsWYvs/2.png" alt="Footage" width="700">

## Following the TCP Stream

By right-clicking on one of the TCP packets and selecting Follow TCP Stream, we can view the content being transmitted. The stream reveals a sequence of JPEG images, which indicates that a security camera is streaming video in MJPEG format from the source 192.168.1.100:8081.

<img src="https://i.ibb.co/QRNkLws/3.png" alt="Footage" width="1000">

## Recovering JPEG Files

To extract the transmitted JPEG images from the capture, we use a digital forensics tool called foremost. This tool scans files and extracts content based on file headers.

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
        <pre><code class="language-bash">foremost -i security-footage-xxxxx.pcap -o recovered_files</code></pre>
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

This creates a directory named recovered_files, which contains a subdirectory jpg/ where the recovered JPEG images are stored.

<img src="https://i.ibb.co/ZRYXjCg9/4.png" alt="Footage" width="650">

## Locating the Flag

After extracting the images, we review them manually. Instead of going through all images from the beginning, it's more efficient to focus on the later files (around image 1500–2000), where the flag becomes clearly visible.

<img src="https://i.ibb.co/BVTBxw25/5.png" alt="Footage" width="650">

In conlusion the analysis and file carving process led to the successful recovery of the security footage.