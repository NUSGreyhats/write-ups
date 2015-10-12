---
title: ASIS CTF Finals 2015 - Big Lie (Forensics 100)
homedisplay: featimg
author: quanyang
description: ASIS CTF Finals 2015 Forensics 100. Big Lie.
tags: [CTF, Forensics, ASIS, PCAP]
category: [CTF, Forensics, PCAP]
--- 

# Big Lie
**Points:**100
**Category:** Forensics
Find the [flag]({{ site.url | append: site.baseurl }}/resources/asis/biglie.pcap).
MD5: c3037269053e61e10a2a2457051519c8

---

We are given a pcap file and asked to find the flag. So, I opened up the pcap file with wireshark and entered some filter to it.

So, I am looking for http requests that contains the asis word.
`http.request.uri contains asis` 

![]({{site.url|append: site.baseurl}}/img/res/asis/biglie/wireshark.png){: height="500px" width="auto"}

So, there's this weird piwik.php call, and there seems to be a pastebin url in the get request.
`http://0bin.asis.io/paste/Vyk5W274#1L8OT3oT7Xr0ryJlS5ASprAqgsQysKeebbSK90gGyQo`
![]({{site.url|append: site.baseurl}}/img/res/asis/biglie/interesting.png){: height="200px" width="auto"}

Looking at similar conversations, I found 3 such conversations.

The first one is:
`http://0bin.asis.io/paste/TINcoc0f#-krvZ7lGwZ4e2JQ8n+3dfsMBqyN6Xk6SUzY7i0JKbpo`
![]({{site.url|append: site.baseurl}}/img/res/asis/biglie/first.png){: height="200px" width="auto"}

The second one is:
`http://0bin.asis.io/paste/Vyk5W274#1L8OT3oT7Xr0ryJlS5ASprAqgsQysKeebbSK90gGyQo`
![]({{site.url|append: site.baseurl}}/img/res/asis/biglie/second.png){: height="200px" width="auto"}

The third one which gave us our flag is:
`http://0bin.asis.io/paste/1ThAoKv4#Zz-nHPnr0vGGg3s/7/RWD2pnZPZl580x9Y2G3IUehfc`
![]({{site.url|append: site.baseurl}}/img/res/asis/biglie/preflag.png){: height="200px" width="auto"}

Throwing this into sublime to resize gives me:
![]({{site.url|append: site.baseurl}}/img/res/asis/biglie/flag.png){: height="200px" width="auto"}

And we have our flag: **ASIS{e29a3ef6f1d71d04c5f107eb3c64bbbb}**