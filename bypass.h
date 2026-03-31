#ifndef HOOK_H
#define HOOK_H

#include <unistd.h>
#include <sys/mman.h>
#include <cstring>
#include <cstdio>

// Silent memory write
inline bool WriteMemory(void* addr, const void* data, size_t size) {
    if (!addr || size == 0) return false;
    uintptr_t page = (uintptr_t)addr & ~(sysconf(_SC_PAGE_SIZE) - 1);
    if (mprotect((void*)page, sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_WRITE | PROT_EXEC) == -1) return false;
    memcpy(addr, data, size);
    mprotect((void*)page, sysconf(_SC_PAGE_SIZE), PROT_READ | PROT_EXEC);
    return true;
}

// Silent get base
inline uintptr_t GetModuleBase(const char* moduleName) {
    char path[512];
    snprintf(path, sizeof(path), "/proc/self/maps");
    FILE* fp = fopen(path, "r");
    if (!fp) return 0;
    uintptr_t base = 0;
    char line[1024];
    while (fgets(line, sizeof(line), fp)) {
        if (strstr(line, moduleName)) {
            sscanf(line, "%lx", &base);
            break;
        }
    }
    fclose(fp);
    return base;
}

// Silent patch helper
inline void PatchOffset(uintptr_t base, uintptr_t offset, const char* patch, size_t len) {
    if (base == 0) return;
    uintptr_t target = base + offset;
    WriteMemory((void*)target, patch, len);
}
//@xvaluex

// Single bypass function - waits safely, applies minimal & lower-risk patches
inline void ApplyBypass() {
    uintptr_t ue4Base = 0;
    uintptr_t anogsBase = 0;
    int attempts = 0;
    const int max_attempts = 600;  // ~60 seconds max wait - helps avoid early/partial load crashes

    while ((ue4Base == 0 || anogsBase == 0) && attempts < max_attempts) {
        if (ue4Base == 0) ue4Base = GetModuleBase("libUE4.so");
        if (anogsBase == 0) anogsBase = GetModuleBase("libanogs.so");
        usleep(100000);  // 100 ms interval
        attempts++;
    }

    // Apply to libanogs.so - only safer / more common lower-mid offsets
    if (anogsBase) {
        // Common surviving RET patches (mostly 0x1Cxxxx to 0x2Fxxxx range)
        PatchOffset(anogsBase, 0x1C1430, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1434, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1438, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1444, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1448, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C144C, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1450, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1454, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C16DC, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C16E4, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C16F0, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1634, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1638, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x1C1758, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);

        PatchOffset(anogsBase, 0x213368, "\xC0\x03\x5F\xD6", 4);
        PatchOffset(anogsBase, 0x228168, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x244088, "\xC0\x03\x5F\xD6", 4);
        PatchOffset(anogsBase, 0x27F9E8, "\x00\x0F\x07\x60", 4);
        PatchOffset(anogsBase, 0x29BF24, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);

        PatchOffset(anogsBase, 0x2EA95C, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2EA974, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2E8BB0, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2ED128, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2F9138, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);

        PatchOffset(anogsBase, 0x2FE7D0, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FE80C, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FE810, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FE824, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FE844, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FE85C, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FE984, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FEA18, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FEA28, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FEA30, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FEABC, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FEAC4, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FEBD4, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x2FEBD8, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);

        PatchOffset(anogsBase, 0x3130F4, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x330494, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x3390A0, "\x00\x0F\x07\x60", 4);
        PatchOffset(anogsBase, 0x361D0C, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x3820D4, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x382140, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x382144, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x387A3C, "\xC0\x03\x5F\xD6", 4);
        PatchOffset(anogsBase, 0x39F56C, "\x00\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(anogsBase, 0x3AA054, "\xC0\x03\x5F\xD6", 4);
        PatchOffset(anogsBase, 0x3AFE80, "\xC0\x03\x5F\xD6", 4);
    }

    // Minimal UE4 patches (only the two you had - often still referenced for skins)
    if (ue4Base) {
        PatchOffset(ue4Base, 0x3DD5DEA, "\x20\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
        PatchOffset(ue4Base, 0x3B802DB, "\x20\x00\x80\xD2\xC0\x03\x5F\xD6", 8);
    }
}

#endif // HOOK_H
