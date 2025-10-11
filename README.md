# Introduction

Microsoft Warbird, or just Warbird, is an obfuscation framework or some kind of packer developed by Microsoft to protect important Windows internals like licensing, DRM, and core security features like Code Integrity (CI). This code protection system is built into Windows to make reversing key components like ci.dll, clipsp.sys, and peauth.sys much harder. It dynamically encrypts and decrypts kernel-mode code at runtime, making static analysis on some part of the software impossible. What’s even more interesting is that **Warbird works even on systems with Hypervisor-Enforced Code Integrity (HVCI) and Virtualization-Based Security (VBS), where dynamic code (kernel memory that can change between writable to executable and vice versa) execution in the kernel is supposed to be impossible**. This research examines how Warbird encrypts and decrypts kernel code and how it "bypasses" HVCI and VBS. At the end of this research, I hope atleast one of these 2 things :

1. Find out how MS break their own rules by allowing dynamic codes (warbird) in a HVCI protected kernel
2. Find out how to execute my own dynamic code on VTL0 kernel with HVCI enabled

In this research, all of the binaries that will be analyzed are from Windows 11 version 24H2 (build 26100.6584).

## clipsp.sys

Our analysis starts at `clipsp.sys`, a kernel driver that is part of the Windows client licensing service. This driver is protected by Warbird. First, before we begin to reverse engineer the inner working of Warbird inside `clipsp.sys`, lets take a look at the "outer" of the PE itself using [PE-bear](https://github.com/hasherezade/pe-bear). If we check on the sections of the PE binary, we can already see some clues/signatures about the presence of Warbird. There are some peculiar sections that are not common on normal PEs, and look at the name of them, `PAGEwx`? `wx` means writable executable? Very interesting indeed.

![Sections](image-8.png)

Next, lets start to reverse engineer the Warbird routines inside `clipsp.sys`. Because we dont have any symbol on this driver, lets start our analysis on the exported routine `ClipSpInitialize`.

![ClipSpInitialize](image.png)

Here, we can see that it firsts check if the `WarbirdMutex` is initialized, if its not then it initialize it using `KeInitializeEvent`. After that, it tries to decrypt PAGEwx1 and PAGEwx3 warbird-packed section, before it executes a code that resides in the PAGEwx1 section. And after it executed the function inside PAGEwx1, it re-encrypts the PAGEwx1 and PAGEwx3 section. We will focus with the `WarbirdDecryptSection` and `WarbirdReencryptSection` function.

![WarbirdDecryptSection](image-1.png)

![WarbirdReencryptSection](image-2.png)

As you might notice, these function actually is just a wrapper function for the same function, `WarbirdEncryptDecryptSection`. These 2 function locks the `WarbirdMutex` mutex, and check for the decryption count stored at `DecryptionData2` structure, if the decryption count is is one then the `WarbirdEncryptDecryptSection` re-encrypt it, and if the decryption count is 0 then the `WarbirdEncryptDecryptSection` decrypts it. This is a way for making the warbird encryption and decryption works in a multithreaded case (where multiple threads are using the instructions inside the warbird-packed sections and are trying to decrypt/reencrypt the section at the same time). Next, lets take a look at how `WarbirdEncryptDecryptSection` works.

![WarbirdEncryptDecryptSection](image-3.png)

```c
struct _PAGEWX_PREPARATION_INFO
{
  DWORD64 NewMdlVa;
  DWORD64 NewMdlLength;
  DWORD64 MdlVaToMappingOffset;
  DWORD IsEncrypt;
  DWORD Unknown5;
  DWORD64 PAGEwxN;
  DWORD64 NewMdl;
  DWORD64 Mdl;
  DWORD IsNewMdlLocked;
  DWORD Unknown9;
  DWORD64 MdlVaOrSectionVa;
  DWORD64 LockedMappedMdlVa;
  DWORD64 MdlLength;
  DWORD64 PAGEwxIndex;
};
```

It first initializes a structure that I call `PAGEWX_PREPARATION_INFO` which contains information like the PAGEwx number and index, MDLs created while encrypting/decrypting the section, current operation (is it encrypt/decrypt), important pointers, and etc. After that, `WarbirdEncryptDecryptSection` will call `WarbirdPrepareSectionForModification`, this function will create the main MDL for the encrypted PAGEwx section, and then use `MmChangeImageProtection` to change the encrypted PAGEwx section to writable (RW). The MmChangeImageProtection is supplied with 4 parameter, first parameter is the PAGEwx main MDL, second parameter is a hash (or atleast partial, more on this later), third parameter is the total size of the hash supplied, and the fourth is the protection flag. MmChangeImageProtection is an undocumented function that, I think, only `clipsp.sys` imports, so we can deduce that MS created this function JUST for kernel-mode warbird. We will talk about `MmChangeImageProtection` further later in this analysis.

![WarbirdPrepareSectionForModification](image-4.png)

After successfully prepared the PAGEwx section for modification, the `WarbirdEncryptDecryptSection` continue with a encryption/decryption loop with a Feistel cipher that they implement. Each loop started with the creation of a writable MDL mapping with a specific starting VA from the Decryption Data 1 of the PAGEwx section, and after that the execution is passed to either `WarbirdFeistelEncrypt` or `WarbirdFeistelDecrypt`. I wont be talking about the specifics in their Feistel cipher encryption or decryption implementation.

![feistel encrypt/decrypt](image-5.png)

And at last, we have arrived to the end of the Warbird encryption/decryption routine. It first cleans any remaining writable MDL mapping thats used for the Feistel encryption/decryption operation, and then it calls `WarbirdFinishSectionModification`. This is the function that will do the job of changing the section from writable to executable in a decryption routine.

![end of routine](image-6.png)

So, here we can see what `WarbirdFinishSectionModification` does. If its an encryption routine, it will try to lock the section and unlock it immediately, to be honest I have no idea why they does this and it is even more bizzare when they lock it once and they unlock it twice. Anyway, lets focus our attention on when its a decryption routine. Here, we can see that it calls `MmChangeImageProtection` again, but the difference between this call and the previous call on `WarbirdPrepareSectionForModification` is the fourth parameter is set to 1 instead of 2, I think this indicates that it want to change the protection to executable. And after the `MmChangeImageProtection` call, it cleans up the PAGEwx main MDL and cleans up the `PAGEWX_PREPARATION_INFO` data. 

![WarbirdFinishSectionModification](image-7.png)

On the next part of the analysis, we will deep dive into `MmChangeImageProtection`, how it works, and how it interoperates with the VTL1.

## ntoskrnl.exe - MmChangeImageProtection
