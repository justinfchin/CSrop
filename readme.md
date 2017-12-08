# ROP - Return Oriented Programming 
- source: https://crypto.stanford.edu/~blynn/rop/

## shell.c
- Goal:
    - An inline shell with c.
    '''c
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
    '''
- Problem:
    - I started this with Mac OS, but didn't work so I switched to Ubuntu. 
- GIF:
    -  

1. We how to circumvent executable space protection using ROP. Note that we use 64 bit system calls so that we can refer to memory addresses that are both 32 and 64 bits. 

No matter where our code winds up, the call-pop trick will load teh RDI register with the address of the /bin/sh string

Note that 0x86 is little-endian, 0xdeadbeef will show up as EF BE AD DE followed by 4 zero bytes. 

No matter where our code winds up, the call-pop trick will load the RDI register with the address of the /bin/sh string

needle0 and needle1 labels are used to aid searches later on 

the 2nd and 3rd arguments to execve are supposed to point to NULL terminated arrays of pointers to strings(argv[] and envp[]). However, our system is forgiving, running 'bin/sh' with NULL argv and envp succeeds


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
