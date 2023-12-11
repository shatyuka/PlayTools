//
//  PlayLoader.m
//  PlayTools
//

#include <errno.h>
#include <sys/sysctl.h>

#import "PlayLoader.h"
#import <PlayTools/PlayTools-Swift.h>
#import <sys/utsname.h>
#import "NSObject+Swizzle.h"

// Get device model from playcover .plist
// With a null terminator
#define DEVICE_MODEL [[[PlaySettings shared] deviceModel] cStringUsingEncoding:NSUTF8StringEncoding]
#define OEM_ID [[[PlaySettings shared] oemID] cStringUsingEncoding:NSUTF8StringEncoding]
#define PLATFORM_IOS 2

// Define dyld_get_active_platform function for interpose
int dyld_get_active_platform(void);
int pt_dyld_get_active_platform(void) { return PLATFORM_IOS; }

// Change the machine output by uname to match expected output on iOS
static int pt_uname(struct utsname *uts) {
    uname(uts);
    strncpy(uts->machine, DEVICE_MODEL, strlen(DEVICE_MODEL) + 1);
    return 0;
}


// Update output of sysctl for key values hw.machine, hw.product and hw.target to match iOS output
// This spoofs the device type to apps allowing us to report as any iOS device
static int pt_sysctl(int *name, u_int types, void *buf, size_t *size, void *arg0, size_t arg1) {
    if (name[0] == CTL_HW && (name[1] == HW_MACHINE || name[0] == HW_PRODUCT)) {
        if (NULL == buf) {
            *size = strlen(DEVICE_MODEL) + 1;
        } else {
            if (*size > strlen(DEVICE_MODEL)) {
                strcpy(buf, DEVICE_MODEL);
            } else {
                return ENOMEM;
            }
        }
        return 0;
    } else if (name[0] == CTL_HW && (name[1] == HW_TARGET)) {
        if (NULL == buf) {
            *size = strlen(OEM_ID) + 1;
        } else {
            if (*size > strlen(OEM_ID)) {
                strcpy(buf, OEM_ID);
            } else {
                return ENOMEM;
            }
        }
        return 0;
    }

    return sysctl(name, types, buf, size, arg0, arg1);
}

static int pt_sysctlbyname(const char *name, void *oldp, size_t *oldlenp, void *newp, size_t newlen) {
    if ((strcmp(name, "hw.machine") == 0) || (strcmp(name, "hw.product") == 0) || (strcmp(name, "hw.model") == 0)) {
        if (oldp == NULL) {
            int ret = sysctlbyname(name, oldp, oldlenp, newp, newlen);
            // We don't want to accidentally decrease it because the real sysctl call will ENOMEM
            // as model are much longer on Macs (eg. MacBookAir10,1)
            if (*oldlenp < strlen(DEVICE_MODEL) + 1) {
                *oldlenp = strlen(DEVICE_MODEL) + 1;
            }
            return ret;
        }
        else if (oldp != NULL) {
            int ret = sysctlbyname(name, oldp, oldlenp, newp, newlen);
            const char *machine = DEVICE_MODEL;
            strncpy((char *)oldp, machine, strlen(machine));
            *oldlenp = strlen(machine) + 1;
            return ret;
        } else {
            int ret = sysctlbyname(name, oldp, oldlenp, newp, newlen);
            return ret;
        }
    } else if ((strcmp(name, "hw.target") == 0)) {
        if (oldp == NULL) {
            int ret = sysctlbyname(name, oldp, oldlenp, newp, newlen);
            if (*oldlenp < strlen(OEM_ID) + 1) {
                *oldlenp = strlen(OEM_ID) + 1;
            }
            return ret;
        } else if (oldp != NULL) {
            int ret = sysctlbyname(name, oldp, oldlenp, newp, newlen);
            const char *machine = OEM_ID;
            strncpy((char *)oldp, machine, strlen(machine));
            *oldlenp = strlen(machine) + 1;
            return ret;
        } else {
            int ret = sysctlbyname(name, oldp, oldlenp, newp, newlen);
            return ret;
        }
    } else {
        return sysctlbyname(name, oldp, oldlenp, newp, newlen);
    }
}

// Interpose the functions create the wrapper
DYLD_INTERPOSE(pt_dyld_get_active_platform, dyld_get_active_platform)
DYLD_INTERPOSE(pt_uname, uname)
DYLD_INTERPOSE(pt_sysctlbyname, sysctlbyname)
DYLD_INTERPOSE(pt_sysctl, sysctl)

// Interpose Apple Keychain functions (SecItemCopyMatching, SecItemAdd, SecItemUpdate, SecItemDelete)
// This allows us to intercept keychain requests and return our own data

// Use the implementations from PlayKeychain
static OSStatus pt_SecItemCopyMatching(CFDictionaryRef query, CFTypeRef *result) {
    OSStatus retval;
    if ([[PlaySettings shared] playChain]) {
        retval = [PlayKeychain copyMatching:(__bridge NSDictionary * _Nonnull)(query) result:result];
    } else {
        retval = SecItemCopyMatching(query, result);
    }
    if (result != NULL) {
        if ([[PlaySettings shared] playChainDebugging]) {
            [PlayKeychain debugLogger:[NSString stringWithFormat:@"SecItemCopyMatching: %@", query]];
            [PlayKeychain debugLogger:[NSString stringWithFormat:@"SecItemCopyMatching result: %@", *result]];
        }
    }
    return retval;
}

static OSStatus pt_SecItemAdd(CFDictionaryRef attributes, CFTypeRef *result) {
    OSStatus retval;
    if ([[PlaySettings shared] playChain]) {
        retval = [PlayKeychain add:(__bridge NSDictionary * _Nonnull)(attributes) result:result];
    } else {
        retval = SecItemAdd(attributes, result);
    }
    if (result != NULL) {
        if ([[PlaySettings shared] playChainDebugging]) {
            [PlayKeychain debugLogger: [NSString stringWithFormat:@"SecItemAdd: %@", attributes]];
            [PlayKeychain debugLogger: [NSString stringWithFormat:@"SecItemAdd result: %@", *result]];
        }
    }
    return retval;
}

static OSStatus pt_SecItemUpdate(CFDictionaryRef query, CFDictionaryRef attributesToUpdate) {
    OSStatus retval;
    if ([[PlaySettings shared] playChain]) {
        retval = [PlayKeychain update:(__bridge NSDictionary * _Nonnull)(query) attributesToUpdate:(__bridge NSDictionary * _Nonnull)(attributesToUpdate)];
    } else {
        retval = SecItemUpdate(query, attributesToUpdate);
    }
    if (attributesToUpdate != NULL) {
        if ([[PlaySettings shared] playChainDebugging]) {
            [PlayKeychain debugLogger: [NSString stringWithFormat:@"SecItemUpdate: %@", query]];
            [PlayKeychain debugLogger: [NSString stringWithFormat:@"SecItemUpdate attributesToUpdate: %@", attributesToUpdate]];
        }
    }
    return retval;

}

static OSStatus pt_SecItemDelete(CFDictionaryRef query) {
    OSStatus retval;
    if ([[PlaySettings shared] playChain]) {
        retval = [PlayKeychain delete:(__bridge NSDictionary * _Nonnull)(query)];
    } else {
        retval = SecItemDelete(query);
    }
    if ([[PlaySettings shared] playChainDebugging]) {
        [PlayKeychain debugLogger: [NSString stringWithFormat:@"SecItemDelete: %@", query]];
    }
    return retval;
}

DYLD_INTERPOSE(pt_SecItemCopyMatching, SecItemCopyMatching)
DYLD_INTERPOSE(pt_SecItemAdd, SecItemAdd)
DYLD_INTERPOSE(pt_SecItemUpdate, SecItemUpdate)
DYLD_INTERPOSE(pt_SecItemDelete, SecItemDelete)

#define max(a, b) ((a) > (b) ? (a) : (b))

void bad_char(const unsigned char* str, int size, int badchar[256]) {
    int i;
    // Initializing all occurrences as -1
    for (i = 0; i < 256; i++) badchar[i] = -1;

    // Fill the actual value of last occurrence
    // of a character
    for (i = 0; i < size; i++) badchar[str[i]] = i;
}

const unsigned char* bmsearch(const unsigned char* txt, int n, const unsigned char* pat, int m) {
    int badchar[256];

    /* Fill the bad character array by calling
    the preprocessing function bad_char()
    for given pattern */
    bad_char(pat, m, badchar);

    int s = 0;
    while (s <= (n - m)) {
        int j = m - 1;
        /* Keep reducing index j of pattern while
        characters of pattern and text are
        matching at this shift s */
        while (j >= 0 && pat[j] == txt[s + j]) j--;

        /* If the pattern is present at current
        shift, then index j will become -1 after
        the above loop */
        if (j < 0) {
            return txt + s;
        } else {
            s += max(1, j - badchar[txt[s + j]]);
        }
    }
    return 0;
}

uint32_t getbits(uint32_t inst, int a, int b) {
    return (inst >> a) & (~(~0 << (b - a + 1)));
}

uint32_t sign_extend(unsigned int number, int numbits){
    if (number & (1 << (numbits - 1)))
        return number | ~((1 << numbits) - 1);
    return number;
}

@implementation PlayLoader

+(void)patch_genshin_layout {
    vm_region_basic_info_data_64_t info;
    memset(&info, 0, sizeof(info));
    mach_msg_type_number_t cnt = VM_REGION_BASIC_INFO_COUNT_64;
    uintptr_t base = 0, region_size = 0;
    mach_port_t obj;
    vm_region_64(mach_task_self(), &base, &region_size, VM_REGION_BASIC_INFO_64, (vm_region_info_64_t)&info, &cnt, &obj);
    if (!base) return;
    // NSLog(@"shatyuka: got base: %p, size: 0x%lx", (void*)base, region_size);

    /*
     08 48 00 51  SUB W8, W0, #0x12
     1F 0D 00 71  CMP W8, #3
     */
    const uint8_t* pattern1 = (const uint8_t*)"\x08\x48\x00\x51\x1F\x0D\x00\x71";
    const uint8_t* found1 = bmsearch((const uint8_t*)base, (int)region_size, pattern1, sizeof(pattern1));
    if (!found1) return;
    // NSLog(@"shatyuka: found1: %p", found1);

    /*
     20 04 80 52  MOV W0, #0x21
     C0 03 5F D6  RET
     */
    const uint8_t* pattern2 = (const uint8_t*)"\x20\x04\x80\x52\xC0\x03\x5F\xD6";
    const uint8_t* found2 = bmsearch((const uint8_t*)base, (int)region_size, pattern2, sizeof(pattern2));
    if (!found2) return;
    // NSLog(@"shatyuka: found2: %p", found2);

    uint32_t inst_adrp = *(uint32_t*)(found1 - 0x18);
    uint32_t inst_add = *(uint32_t*)(found1 - 0x18 + 4);
    uint32_t inst_ldr = *(uint32_t*)(found1 - 0x18 + 8);
    if ((inst_adrp & 0x9F000000) != 0x90000000 ||
        (inst_add & 0xFFC00000) != 0x91000000 ||
        (inst_ldr & 0xFFC00000) != 0xF9400000) {
        // NSLog(@"shatyuka: invalid opcode: %08x %08x %08x", inst_adrp, inst_add, inst_ldr);
        return;
    }

    uint32_t adrp_immlo = getbits(inst_adrp, 29, 30);
    uint32_t adrp_immhi = getbits(inst_adrp, 5, 23);
    uintptr_t adrl_base = (((uintptr_t)found1 - 0x18) & ~0xFFF) + sign_extend(((adrp_immhi << 2) | adrp_immlo) << 12, 32);
    uintptr_t adrl_offset = getbits(inst_add, 10, 21);
    uintptr_t add_offset = (uintptr_t)getbits(inst_ldr, 10, 21) << 3;
    // NSLog(@"shatyuka: adrl_base: %p", (void*)adrl_base);
    // NSLog(@"shatyuka: adrl_offset: 0x%lx", adrl_offset);
    // NSLog(@"shatyuka: add_offset: 0x%lx", add_offset);

    *(const uint8_t**)(adrl_base + adrl_offset + add_offset) = found2;
}

static void __attribute__((constructor)) initialize(void) {
    [PlayCover launch];
}

@end
