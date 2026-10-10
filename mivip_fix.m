// mivip_fix.dylib — MiPlayer VIP unlock
// Patches 4 isVip check functions to always return true.
// Swift private functions: vm_protect(VM_PROT_COPY) + memcpy
// ObjC methods: method_setImplementation

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <mach-o/dyld.h>
#include <mach/mach.h>
#include <string.h>
#include <stdint.h>

// MOV W0, #1 ; RET
static const uint8_t kPatch[8] = { 0x20,0x00,0x80,0x52, 0xC0,0x03,0x5F,0xD6 };

static void patch_offset(uintptr_t base, uintptr_t off) {
    uintptr_t addr = base + off;
    uintptr_t page = addr & ~(uintptr_t)(PAGE_SIZE - 1);

    kern_return_t kr = vm_protect(mach_task_self(), page, PAGE_SIZE, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) {
        NSLog(@"[mivip] vm_protect failed off=0x%lx kr=%d", off, kr);
        return;
    }
    memcpy((void *)addr, kPatch, sizeof(kPatch));
    vm_protect(mach_task_self(), page, PAGE_SIZE, FALSE,
               VM_PROT_READ | VM_PROT_EXECUTE);
    __builtin___clear_cache((char *)addr, (char *)(addr + sizeof(kPatch)));
    NSLog(@"[mivip] patched off=0x%lx", off);
}

static BOOL hook_isVip_true(id self, SEL _cmd) { return YES; }

__attribute__((constructor))
static void mivip_init(void) {
    // Find MiPlayer image base
    uintptr_t base = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        const char *bn = strrchr(name, '/');
        if (bn && strcmp(bn + 1, "MiPlayer") == 0) {
            base = (uintptr_t)_dyld_get_image_header(i);
            break;
        }
    }
    if (!base) { NSLog(@"[mivip] MiPlayer image not found"); return; }
    NSLog(@"[mivip] base=%p", (void *)base);

    // Patch Swift private VIP functions
    patch_offset(base, 0xB29498); // MiSubscriptionCenter.isVip (main callers)
    patch_offset(base, 0xB3046C); // MiSubscriptionCenter.isVip (witness table / settings)

    // ObjC method swizzle
    // +[_TtC8MiPlayer18MiVipManagerBridge isVip]
    Class bridge = NSClassFromString(@"_TtC8MiPlayer18MiVipManagerBridge");
    if (bridge) {
        Method m = class_getClassMethod(bridge, @selector(isVip));
        if (m) method_setImplementation(m, (IMP)hook_isVip_true);
    }
    // -[MiMainControlModel isVip]
    Class model = NSClassFromString(@"MiMainControlModel");
    if (model) {
        Method m = class_getInstanceMethod(model, @selector(isVip));
        if (m) method_setImplementation(m, (IMP)hook_isVip_true);
    }

    NSLog(@"[mivip] done");
}
