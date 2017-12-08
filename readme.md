# ROP - Return Oriented Programming 
> source: https://crypto.stanford.edu/~blynn/rop/

## shell.c
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
    -  
- Problems:
    - I started this with Mac OS, but did not work so I switched to Ubuntu. 

objdump - displays information from object files
to do this on mac osx, i had to brew install binutils, then instead of objdump, use gobjdump to avoid conflicts with the utilities distributed by apple


#CDECL Calling Convention
- Due to this convention for x86 systems, if we input a really long string, we overflow the name buffer, and overwrite the return address. 

- Now we enter the shelcode followed by the right bytes and the program will unwittingly run it when trying to return from the main function.

#The Three Trials of Code Injection
- Stack smashing is harder now due to countermeasures. From Ubuntu 12.04, here are three countermeasures:
    1. GCC Stack-Smashing Protector (SSP) aka ProPolice. 
        - the compiler rearranges the stack layout to make buffer overflows less dangerous and inserts runtime stack integrity checks.
    2. Executable Space Protection (ESP) (NX)
        - attempting to execute code in the stack causes a segmentation fault. 
        - additional alias:
            - Data Execution Prevention (DEP) on Windows
            - Write XOR Execute (W^X) on BSD
            - Never Execute (NX) on 64bit Linux
    3. Address Space Layout Randomization (ASLR)
        - the location of the stack is randomized every run
        - so even though we overwrite the return address, we have no idea what to put there

- To get around the countermeasures, we cheat by disabling them:
    - disable SSP
    - disable ESP
        - had to install execstack
        - sudo apt install execstack
    - disable ASLR

- setarch 
    - changes the reported architecture in new program environment and set personality flags
