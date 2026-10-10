// mivip_fix.dylib — MiPlayer VIP unlock (version-resilient)
//
// ObjC methods: swizzled by name (stable across updates)
// Swift private functions (isVip variants): found at runtime by tracing BL
//   chain from +[MiVipManagerBridge isVip] — no hardcoded offsets

#import <Foundation/Foundation.h>
#import <objc/runtime.h>
#include <mach-o/dyld.h>
#include <mach-o/loader.h>
#include <mach/mach.h>
#include <libkern/OSCacheControl.h>
#include <string.h>
#include <stdint.h>

static const uint8_t kPatch[8] = { 0x20,0x00,0x80,0x52, 0xC0,0x03,0x5F,0xD6 };

// ---- Runtime helpers --------------------------------------------------------

// Find __TEXT,__text bounds for the MiPlayer image
static uintptr_t g_text_lo = 0, g_text_hi = 0;
static intptr_t  g_slide   = 0;

static void find_text_bounds(uint32_t img_idx) {
    const struct mach_header *mh = _dyld_get_image_header(img_idx);
    g_slide = _dyld_get_image_vmaddr_slide(img_idx);
    if (!mh || mh->magic != MH_MAGIC_64) return;
    const struct mach_header_64 *mh64 = (const struct mach_header_64 *)mh;
    const struct load_command *lc = (const struct load_command *)(mh64 + 1);
    for (uint32_t j = 0; j < mh64->ncmds; j++, lc = (const struct load_command *)((char *)lc + lc->cmdsize)) {
        if (lc->cmd != LC_SEGMENT_64) continue;
        const struct segment_command_64 *seg = (const struct segment_command_64 *)lc;
        if (strncmp(seg->segname, "__TEXT", 6)) continue;
        const struct section_64 *sec = (const struct section_64 *)(seg + 1);
        for (uint32_t k = 0; k < seg->nsects; k++, sec++) {
            if (strncmp(sec->sectname, "__text", 6)) continue;
            g_text_lo = (uintptr_t)(sec->addr + g_slide);
            g_text_hi = g_text_lo + sec->size;
            return;
        }
    }
}

// Decode a BL instruction at `p`, return target address (0 if not BL)
static uintptr_t bl_target(const uint32_t *p) {
    uint32_t insn = *p;
    if ((insn & 0xFC000000) != 0x94000000) return 0; // not BL
    int64_t imm = (int64_t)((insn & 0x03FFFFFF) << 2);
    if (imm & (1LL << 27)) imm |= ~((1LL << 28) - 1LL);
    return (uintptr_t)p + (uintptr_t)imm;
}

// Find the Nth BL in `fn` whose target is inside MiPlayer __text.
// n is 1-based. max_insns limits search depth.
static uintptr_t nth_internal_bl(uintptr_t fn, int n, int max_insns) {
    const uint32_t *p = (const uint32_t *)fn;
    int found = 0;
    for (int i = 0; i < max_insns; i++) {
        uintptr_t t = bl_target(p + i);
        if (!t) continue;
        if (t >= g_text_lo && t < g_text_hi) {
            if (++found == n) return t;
        }
    }
    return 0;
}

// Patch a code address using vm_protect(VM_PROT_COPY)
static void patch_addr(uintptr_t addr) {
    if (!addr) { NSLog(@"[mivip] skip null addr"); return; }
    uintptr_t page = addr & ~(uintptr_t)(PAGE_SIZE - 1);
    kern_return_t kr = vm_protect(mach_task_self(), page, PAGE_SIZE, FALSE,
                                  VM_PROT_READ | VM_PROT_WRITE | VM_PROT_COPY);
    if (kr != KERN_SUCCESS) { NSLog(@"[mivip] vm_protect failed %p kr=%d", (void*)addr, kr); return; }
    memcpy((void *)addr, kPatch, sizeof(kPatch));
    vm_protect(mach_task_self(), page, PAGE_SIZE, FALSE, VM_PROT_READ | VM_PROT_EXECUTE);
    sys_icache_invalidate((void *)addr, sizeof(kPatch));
    NSLog(@"[mivip] patched %p", (void *)addr);
}

// ---- ObjC hooks -------------------------------------------------------------

static BOOL hook_isVip(id self, SEL _cmd) { return YES; }

// Block MiWebPaywallVC from presenting
typedef void (*PresentVC_t)(id, SEL, id, BOOL, id);
static PresentVC_t orig_presentVC;

static void hook_presentVC(id self, SEL _cmd, id vc, BOOL animated, id completion) {
    static Class paywallClass;
    static dispatch_once_t once;
    dispatch_once(&once, ^{
        paywallClass = NSClassFromString(@"_TtC14MiSubscription14MiWebPaywallVC");
    });
    if (paywallClass && [vc isKindOfClass:paywallClass]) {
        NSLog(@"[mivip] blocked MiWebPaywallVC");
        if (completion) ((void(^)(void))completion)();
        return;
    }
    orig_presentVC(self, _cmd, vc, animated, completion);
}

// ---- Constructor ------------------------------------------------------------

__attribute__((constructor))
static void mivip_init(void) {
    // Locate MiPlayer image
    uint32_t img_idx = UINT32_MAX;
    uintptr_t img_base = 0;
    for (uint32_t i = 0; i < _dyld_image_count(); i++) {
        const char *name = _dyld_get_image_name(i);
        if (!name) continue;
        const char *bn = strrchr(name, '/');
        if (bn && strcmp(bn + 1, "MiPlayer") == 0) {
            img_idx = i;
            img_base = (uintptr_t)_dyld_get_image_header(i);
            break;
        }
    }
    if (img_idx == UINT32_MAX) { NSLog(@"[mivip] image not found"); return; }
    find_text_bounds(img_idx);
    NSLog(@"[mivip] base=%p text=[%p,%p)", (void*)img_base, (void*)g_text_lo, (void*)g_text_hi);

    // ---- Swizzle presentViewController to block paywall --------------------
    {
        Class vcClass = objc_getClass("UIViewController");
        SEL sel = @selector(presentViewController:animated:completion:);
        Method m = class_getInstanceMethod(vcClass, sel);
        orig_presentVC = (PresentVC_t)method_setImplementation(m, (IMP)hook_presentVC);
    }

    // ---- ObjC swizzle (stable by selector name) ----------------------------
    Class bridge = NSClassFromString(@"_TtC8MiPlayer18MiVipManagerBridge");
    if (bridge) {
        Method m = class_getClassMethod(bridge, @selector(isVip));
        if (m) method_setImplementation(m, (IMP)hook_isVip);
    }
    Class model = NSClassFromString(@"MiMainControlModel");
    if (model) {
        Method m = class_getInstanceMethod(model, @selector(isVip));
        if (m) method_setImplementation(m, (IMP)hook_isVip);
    }

    // ---- Swift private function tracing ------------------------------------
    // Chain: +[MiVipManagerBridge isVip]
    //   → 1st internal BL: sub_B25DFC (get subscription center singleton)
    //   → 2nd internal BL: sub_B29498 (isVip check)  ← patch this
    if (!bridge) { NSLog(@"[mivip] bridge class not found, skip swift patch"); return; }
    Method bm = class_getClassMethod(bridge, @selector(isVip));
    if (!bm) { NSLog(@"[mivip] isVip method not found"); return; }
    uintptr_t bridge_imp = (uintptr_t)method_getImplementation(bm);

    uintptr_t sub_b29498 = nth_internal_bl(bridge_imp, 2, 48);
    NSLog(@"[mivip] sub_b29498 candidate: %p", (void*)sub_b29498);
    patch_addr(sub_b29498);

    // sub_b29498's 1st internal BL = sub_b2b774 (the real sub-check)
    // Scan __text for other short functions (<= 0x40 bytes) whose 1st internal BL
    // is also sub_b2b774 → these are isVip witness table copies (e.g. sub_b3046c)
    if (!sub_b29498) { NSLog(@"[mivip] could not find sub_b29498"); return; }
    uintptr_t sub_b2b774 = nth_internal_bl(sub_b29498, 1, 24);
    if (!sub_b2b774) { NSLog(@"[mivip] could not find sub_b2b774"); return; }
    NSLog(@"[mivip] sub_b2b774: %p — scanning for witness copies", (void*)sub_b2b774);

    // Scan entire __text for functions with same signature
    int extra = 0;
    for (uintptr_t addr = g_text_lo; addr < g_text_hi - 16; addr += 4) {
        // Only scan 4-byte aligned candidates
        uintptr_t first_internal_bl = nth_internal_bl(addr, 1, 16);
        if (first_internal_bl != sub_b2b774) continue;
        if (addr == sub_b29498) continue; // skip already patched
        // Confirm it's a small function (second internal BL within 24 insns)
        uintptr_t second_bl = nth_internal_bl(addr, 2, 24);
        if (!second_bl || second_bl >= g_text_lo) {
            patch_addr(addr);
            extra++;
            if (extra >= 4) break; // safety limit
        }
    }
    NSLog(@"[mivip] patched %d extra witness copies", extra);
    NSLog(@"[mivip] done");
}
