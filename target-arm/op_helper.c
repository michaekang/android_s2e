/*
 *  ARM helper routines
 *
 *  Copyright (c) 2005-2007 CodeSourcery, LLC
 *
 * This library is free software; you can redistribute it and/or
 * modify it under the terms of the GNU Lesser General Public
 * License as published by the Free Software Foundation; either
 * version 2 of the License, or (at your option) any later version.
 *
 * This library is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU
 * Lesser General Public License for more details.
 *
 * You should have received a copy of the GNU Lesser General Public
 * License along with this library; if not, see <http://www.gnu.org/licenses/>.
 */
#include "exec.h"
#include "helper.h"
#include <assert.h>
#include "host-utils.h"
#ifdef CONFIG_TRACE
#include "trace.h"
#endif
/** Global variable that determines whether to make
    symbolic I/O memory addresses concrete */
extern int g_s2e_concretize_io_addresses;

/** Global variable that determines whether to make
    symbolic I/O writes concrete */
extern int g_s2e_concretize_io_writes;

#include <string.h>

#ifdef S2E_LLVM_LIB
	int semihosting_enabled = 0;
	int tracing = 0;
#else
	extern int semihosting_enabled;
#endif

#define SIGNBIT (uint32_t)0x80000000
#define SIGNBIT64 ((uint64_t)1 << 63)
//#ifdef CONFIG_S2E
#ifdef S2E_LLVM_LIB
void klee_make_symbolic(void *addr, unsigned nbytes, const char *name);
uint8_t klee_int8(const char *name);
uint16_t klee_int16(const char *name);
uint32_t klee_int32(const char *name);
void uint32_to_string(uint32_t n, char *str);
void trace_port(char *buf, const char *prefix, uint32_t port, uint32_t pc);

uint8_t klee_int8(const char *name) {
    uint8_t ret;
    klee_make_symbolic(&ret, sizeof(ret), name);
    return ret;
}

uint16_t klee_int16(const char *name) {
    uint16_t ret;
    klee_make_symbolic(&ret, sizeof(ret), name);
    return ret;
}

uint32_t klee_int32(const char *name) {
    uint32_t ret;
    klee_make_symbolic(&ret, sizeof(ret), name);
    return ret;
}

//Helpers to avoid relying on sprintf that does not work properly
static char hextable[] = {'0', '1', '2', '3', '4', '5', '6', '7', '8', '9', 'a', 'b',
'c', 'd', 'e', 'f'};
void uint32_to_string(uint32_t n, char *str)
{
  str[0] = hextable[(n >> 28)];
  str[1] = hextable[((n >> 24) & 0xF)];
  str[2] = hextable[((n >> 20) & 0xF)];
  str[3] = hextable[((n >> 16) & 0xF)];
  str[4] = hextable[((n >> 12) & 0xF)];
  str[5] = hextable[((n >> 8) & 0xF)];
  str[6] = hextable[((n >> 4) & 0xF)];
  str[7] = hextable[((n >> 0) & 0xF)];
}

void trace_port(char *buf, const char *prefix, uint32_t port, uint32_t pc)
{
    while(*prefix) {
        *buf = *prefix;
        ++buf; ++prefix;
    }

    uint32_to_string(port, buf);
    buf+=8;
    *buf = '_';
    buf++;
    uint32_to_string(pc, buf);
    buf+=8;
    *buf = 0;
}

#endif

#ifndef S2E_LLVM_LIB
#ifdef CONFIG_S2E
struct CPUARMState* env = 0;
#endif
#endif

void raise_exception(int tt)
{
    env->exception_index = tt;
    cpu_loop_exit();
}

uint32_t HELPER(neon_tbl)(uint32_t ireg, uint32_t def,
                          uint32_t rn, uint32_t maxindex)
{
    uint32_t val;
    uint32_t tmp;
    int index;
    int shift;
    uint64_t *table;
    table = (uint64_t *)&env->vfp.regs[rn];
    val = 0;
    for (shift = 0; shift < 32; shift += 8) {
        index = (ireg >> shift) & 0xff;
        if (index < maxindex) {
            tmp = (table[index >> 3] >> ((index & 7) << 3)) & 0xff;
            val |= tmp << shift;
        } else {
            val |= def & (0xff << shift);
        }
    }
    return val;
}

#if !defined(CONFIG_USER_ONLY)

#define MMUSUFFIX _mmu

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

#if defined(CONFIG_S2E) && !defined(S2E_LLVM_LIB) 
#undef MMUSUFFIX
#define MMUSUFFIX _mmu_s2e_trace
#define _raw _raw_s2e_trace

#define SHIFT 0
#include "softmmu_template.h"

#define SHIFT 1
#include "softmmu_template.h"

#define SHIFT 2
#include "softmmu_template.h"

#define SHIFT 3
#include "softmmu_template.h"

#undef _raw
#endif

#ifdef CONFIG_S2E
#include <s2e/s2e_qemu.h>
#endif

#ifndef CONFIG_S2E
/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill (target_ulong addr, int is_write, int mmu_idx, void *retaddr)
{
    TranslationBlock *tb;
    CPUState *saved_env;
    unsigned long pc;
    int ret;

    /* XXX: hack to restore env in all cases, even if not called from
       generated code */
    saved_env = env;
    env = cpu_single_env;
#ifdef CONFIG_S2E
    s2e_on_tlb_miss(g_s2e, g_s2e_state, addr, is_write);
    ret = cpu_arm_handle_mmu_fault(env, page_addr,
                                   is_write, mmu_idx, 1);
#else
    ret = cpu_arm_handle_mmu_fault(env, addr, is_write, mmu_idx, 1);
#endif

    if (unlikely(ret)) {
#ifdef CONFIG_S2E
        /* In S2E we pass page address instead of addr to cpu_arm_handle_mmu_fault,
           since the latter can be symbolic while the former is always concrete.
           To compensate, we reset fault address here. */
        if(env->exception_index == EXCP_PREFETCH_ABORT || env->exception_index == EXCP_DATA_ABORT) {
            assert(1 && "handle coprocessor exception properly");
        }
        if(use_icount)
            cpu_restore_icount(env);
#endif

        if (retaddr) {
            /* now we have a real cpu fault */
            pc = (unsigned long)retaddr;
            tb = tb_find_pc(pc);
            if (tb) {
                /* the PC is inside the translated code. It means that we have
                   a virtual CPU fault */
                cpu_restore_state(tb, env, pc);
            }
        }

#ifdef CONFIG_S2E
s2e_on_page_fault(g_s2e, g_s2e_state, addr, is_write);
#endif

        raise_exception(env->exception_index);
    }
    env = saved_env;
}
#else
/* try to fill the TLB and return an exception if error. If retaddr is
   NULL, it means that the function was called in C code (i.e. not
   from generated code or from helper.c) */
/* XXX: fix it to restore all registers */
void tlb_fill(target_ulong addr, target_ulong page_addr, int is_write, int mmu_idx,
              void *retaddr)
{
    TranslationBlock *tb;
    CPUState *saved_env;
    unsigned long pc;
    int ret;

    /* XXX: hack to restore env in all cases, even if not called from
       generated code */
	saved_env = env;
    if(env != cpu_single_env)
    	env = cpu_single_env;
#ifdef CONFIG_S2E
    s2e_on_tlb_miss(g_s2e, g_s2e_state, addr, is_write);
    ret = cpu_arm_handle_mmu_fault(env, page_addr,
                                   is_write, mmu_idx, 1);
#else
    ret = cpu_arm_handle_mmu_fault(env, addr, is_write, mmu_idx, 1);
#endif

    if (unlikely(ret)) {

#ifdef CONFIG_S2E
        /* In S2E we pass page address instead of addr to cpu_arm_handle_mmu_fault,
           since the latter can be symbolic while the former is always concrete.
           To compensate, we reset fault address here. */
        if(env->exception_index == EXCP_PREFETCH_ABORT || env->exception_index == EXCP_DATA_ABORT) {
            assert(1 && "handle coprocessor exception properly");
        }
        if(use_icount)
            cpu_restore_icount(env);
#endif

        if (retaddr) {
            /* now we have a real cpu fault */
            pc = (unsigned long)retaddr;
            tb = tb_find_pc(pc);
            if (tb) {
                /* the PC is inside the translated code. It means that we have
                   a virtual CPU fault */
                cpu_restore_state(tb, env, pc);
            }
        }

#ifdef CONFIG_S2E
s2e_on_page_fault(g_s2e, g_s2e_state, addr, is_write);
#endif

        raise_exception(env->exception_index);
    }

    if(saved_env != env)
    	env = saved_env;
}
#endif

#if defined(CONFIG_S2E) && defined(S2E_LLVM_LIB)
static inline int bank_number (int mode)
{
    switch (mode) {
    case ARM_CPU_MODE_USR:
    case ARM_CPU_MODE_SYS:
        return 0;
    case ARM_CPU_MODE_SVC:
        return 1;
    case ARM_CPU_MODE_ABT:
        return 2;
    case ARM_CPU_MODE_UND:
        return 3;
    case ARM_CPU_MODE_IRQ:
        return 4;
    case ARM_CPU_MODE_FIQ:
        return 5;
    }
    cpu_abort(cpu_single_env, "Bad mode %x\n", mode);
    return -1;
}

uint32_t cpsr_read(CPUARMState *env)
{
            int ZF;
            ZF = (RR_cpu(env,ZF) == 0);
            return env->uncached_cpsr | (RR_cpu(env,NF) & 0x80000000) | (ZF << 30) |
                (RR_cpu(env,CF) << 29) | ((RR_cpu(env,VF) & 0x80000000) >> 3) | (env->QF << 27)
                | (env->thumb << 5) | ((env->condexec_bits & 3) << 25)
                | ((env->condexec_bits & 0xfc) << 8)
                | (env->GE << 16);

// For DEBUG purposes
//          int ZF;
//          target_ulong NF,CF,VF,QF, thumb, condex1, condex2, GE;
//          ZF = (RR_cpu(env,ZF) == 0);
//          NF = (RR_cpu(env,NF) & 0x80000000);
//          CF = (RR_cpu(env,CF) << 29);
//          VF = ((RR_cpu(env,VF) & 0x80000000) >> 3);
//          QF = (env->QF << 27);
//          thumb = (env->thumb << 5);
//          condex1 = ((env->condexec_bits & 3) << 25);
//          condex2 = ((env->condexec_bits & 0xfc) << 8);
//          GE = (env->GE << 16);
//          return env->uncached_cpsr | NF | (ZF << 30) |
//              CF | VF | QF
//              | thumb | condex1
//              | condex2
//              | GE;
}

void cpsr_write(CPUARMState *env, uint32_t val, uint32_t mask)
{
    if (mask & CPSR_NZCV) {
        WR_cpu(env,ZF,((~val) & CPSR_Z));
        WR_cpu(env,NF,val);
        WR_cpu(env,CF,((val >> 29) & 1));
        WR_cpu(env,VF,((val << 3) & 0x80000000));
    }
    if (mask & CPSR_Q)
        env->QF = ((val & CPSR_Q) != 0);
    if (mask & CPSR_T)
        env->thumb = ((val & CPSR_T) != 0);
    if (mask & CPSR_IT_0_1) {
        env->condexec_bits &= ~3;
        env->condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env->condexec_bits &= 3;
        env->condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & CPSR_GE) {
        env->GE = (val >> 16) & 0xf;
    }

    if ((env->uncached_cpsr ^ val) & mask & CPSR_M) {
        switch_mode(env, val & CPSR_M);
    }
    mask &= ~CACHED_CPSR_BITS;
    env->uncached_cpsr = (env->uncached_cpsr & ~mask) | (val & mask);
}
void switch_mode(CPUState *env, int mode)
{
    int old_mode;
    int i;

    old_mode = env->uncached_cpsr & CPSR_M;
    if (mode == old_mode)
        return;

    if (old_mode == ARM_CPU_MODE_FIQ) {
        //memcpy (env->fiq_regs, env->regs + 8, 5 * sizeof(uint32_t));
        WR_cpu(env,fiq_regs[0],RR_cpu(env,regs[8]));
        WR_cpu(env,fiq_regs[1],RR_cpu(env,regs[9]));
        WR_cpu(env,fiq_regs[2],RR_cpu(env,regs[10]));
        WR_cpu(env,fiq_regs[3],RR_cpu(env,regs[11]));
        WR_cpu(env,fiq_regs[4],RR_cpu(env,regs[12]));
            
        //memcpy (env->regs + 8, env->usr_regs, 5 * sizeof(uint32_t));
        WR_cpu(env,regs[8],RR_cpu(env,usr_regs[0]));
        WR_cpu(env,regs[9],RR_cpu(env,usr_regs[1]));
        WR_cpu(env,regs[10],RR_cpu(env,usr_regs[2]));
        WR_cpu(env,regs[11],RR_cpu(env,usr_regs[3]));
        WR_cpu(env,regs[12],RR_cpu(env,usr_regs[4]));

    } else if (mode == ARM_CPU_MODE_FIQ) {
        //memcpy (env->usr_regs, env->regs + 8, 5 * sizeof(uint32_t));
        WR_cpu(env,usr_regs[0],RR_cpu(env,regs[8]));
        WR_cpu(env,usr_regs[1],RR_cpu(env,regs[9]));
        WR_cpu(env,usr_regs[2],RR_cpu(env,regs[10]));
        WR_cpu(env,usr_regs[3],RR_cpu(env,regs[11]));
        WR_cpu(env,usr_regs[4],RR_cpu(env,regs[12]));

        //memcpy (env->regs + 8, env->fiq_regs, 5 * sizeof(uint32_t));
        WR_cpu(env,regs[8],RR_cpu(env,fiq_regs[0]));
        WR_cpu(env,regs[9],RR_cpu(env,fiq_regs[1]));
        WR_cpu(env,regs[10],RR_cpu(env,fiq_regs[2]));
        WR_cpu(env,regs[11],RR_cpu(env,fiq_regs[3]));
        WR_cpu(env,regs[12],RR_cpu(env,fiq_regs[4]));
    }

    i = bank_number(old_mode);
    WR_cpu(env,banked_r13[i], RR_cpu(env,regs[13]));
    WR_cpu(env,banked_r14[i], RR_cpu(env,regs[14]));
    WR_cpu(env,banked_spsr[i], RR_cpu(env,spsr));

    i = bank_number(mode);
    WR_cpu(env,regs[13],RR_cpu(env,banked_r13[i]));
    WR_cpu(env,regs[14],RR_cpu(env,banked_r14[i]));
    WR_cpu(env,spsr,RR_cpu(env,banked_spsr[i]));
}



static void v7m_push(CPUARMState *env, uint32_t val)
{
        WR_cpu(env,regs[13],(RR_cpu(env,regs[13]) - 4));
        stl_phys(RR_cpu(env,regs[13]), val);
}
static uint32_t v7m_pop(CPUARMState *env)
{
    uint32_t val;
    val = ldl_phys(RR_cpu(env,regs[13]));
    WR_cpu(env,regs[13],(RR_cpu(env,regs[13]) + 4));
    return val;
}

/* Switch to V7M main or process stack pointer.  */
static void switch_v7m_sp(CPUARMState *env, int process)
{
    uint32_t tmp;
    if (env->v7m.current_sp != process) {
        tmp = env->v7m.other_sp;
        env->v7m.other_sp = RR_cpu(env,regs[13]);
        WR_cpu(env,regs[13],tmp);
        env->v7m.current_sp = process;
    }
}

static void do_v7m_exception_exit(CPUARMState *env)
{
    uint32_t type;
    uint32_t xpsr;

    type = env->regs[15];
    if (env->v7m.exception != 0)
        armv7m_nvic_complete_irq(env->nvic, env->v7m.exception);

    /* Switch to the target stack.  */
    switch_v7m_sp(env, (type & 4) != 0);
    /* Pop registers.  */
    WR_cpu(env,regs[0],v7m_pop(env));
    WR_cpu(env,regs[1],v7m_pop(env));
    WR_cpu(env,regs[2],v7m_pop(env));
    WR_cpu(env,regs[3],v7m_pop(env));
    WR_cpu(env,regs[12],v7m_pop(env));
    WR_cpu(env,regs[14],v7m_pop(env));
    xpsr = v7m_pop(env);
    xpsr_write(env, xpsr, 0xfffffdff);
    /* Undo stack alignment.  */
    if (xpsr & 0x200)
        WR_cpu(env,regs[13],(RR_cpu(env,regs[13]) | 4));
    /* ??? The exception return type specifies Thread/Handler mode.  However
       this is also implied by the xPSR value. Not sure what to do
       if there is a mismatch.  */
    /* ??? Likewise for mismatches between the CONTROL register and the stack
       pointer.  */
}

static void do_interrupt_v7m(CPUARMState *env)
{
    uint32_t xpsr = xpsr_read(env);
    uint32_t lr;
    uint32_t addr;

    lr = 0xfffffff1;
    if (env->v7m.current_sp)
        lr |= 4;
    if (env->v7m.exception == 0)
        lr |= 8;

    /* For exceptions we just mark as pending on the NVIC, and let that
       handle it.  */
    /* TODO: Need to escalate if the current priority is higher than the
       one we're raising.  */
    switch (env->exception_index) {
    case EXCP_UDEF:
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_USAGE);
        return;
    case EXCP_SWI:
        env->regs[15] += 2;
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_SVC);
        return;
    case EXCP_PREFETCH_ABORT:
    case EXCP_DATA_ABORT:
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_MEM);
        return;
    case EXCP_BKPT:
        if (semihosting_enabled) {
            int nr;
            nr = lduw_code(env->regs[15]) & 0xff;
            if (nr == 0xab) {
                env->regs[15] += 2;
                WR_cpu(env,regs[0],do_arm_semihosting(env));
                return;
            }
        }
        armv7m_nvic_set_pending(env->nvic, ARMV7M_EXCP_DEBUG);
        return;
    case EXCP_IRQ:
        env->v7m.exception = armv7m_nvic_acknowledge_irq(env->nvic);
        break;
    case EXCP_EXCEPTION_EXIT:
        do_v7m_exception_exit(env);
        return;
    default:
        cpu_abort(env, "Unhandled exception 0x%x\n", env->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }

    /* Align stack pointer.  */
    /* ??? Should only do this if Configuration Control Register
       STACKALIGN bit is set.  */
    if (RR_cpu(env,regs[13]) & 4) {
        WR_cpu(env,regs[13],(RR_cpu(env,regs[13]) - 4));
        xpsr |= 0x200;
    }
    /* Switch to the handler mode.  */
    v7m_push(env, xpsr);
    v7m_push(env, env->regs[15]);
    v7m_push(env, RR_cpu(env,regs[14]));
    v7m_push(env, RR_cpu(env,regs[12]));
    v7m_push(env, RR_cpu(env,regs[3]));
    v7m_push(env, RR_cpu(env,regs[2]));
    v7m_push(env, RR_cpu(env,regs[1]));
    v7m_push(env, RR_cpu(env,regs[0]));
    switch_v7m_sp(env, 0);
    env->uncached_cpsr &= ~CPSR_IT;
    WR_cpu(env,regs[14],lr);
    addr = ldl_phys(env->v7m.vecbase + env->v7m.exception * 4);
    env->regs[15] = addr & 0xfffffffe;
    env->thumb = addr & 1;
}

void do_interrupt(CPUARMState *env)
{
    uint32_t addr;
    uint32_t mask;
    int new_mode;
    uint32_t offset;

#ifdef CONFIG_TRACE
    if (tracing) {
        trace_exception(env->regs[15]);
    }
#endif

    if (IS_M(env)) {
        do_interrupt_v7m(env);
        return;
    }
    /* TODO: Vectored interrupt controller.  */
    switch (env->exception_index) {
    case EXCP_UDEF:
        new_mode = ARM_CPU_MODE_UND;
        addr = 0x04;
        mask = CPSR_I;
        if (env->thumb)
            offset = 2;
        else
            offset = 4;
        break;
    case EXCP_SWI:
        if (semihosting_enabled) {
            /* Check for semihosting interrupt.  */
            if (env->thumb) {
                mask = lduw_code(env->regs[15] - 2) & 0xff;
            } else {
                mask = ldl_code(env->regs[15] - 4) & 0xffffff;
            }
            /* Only intercept calls from privileged modes, to provide some
               semblance of security.  */
            if (((mask == 0x123456 && !env->thumb)
                    || (mask == 0xab && env->thumb))
                  && (env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR) {
                WR_cpu(env,regs[0],do_arm_semihosting(env));
                return;
            }
        }
        new_mode = ARM_CPU_MODE_SVC;
        addr = 0x08;
        mask = CPSR_I;
        /* The PC already points to the next instruction.  */
        offset = 0;
        break;
    case EXCP_BKPT:
        /* See if this is a semihosting syscall.  */
        if (env->thumb && semihosting_enabled) {
            mask = lduw_code(env->regs[15]) & 0xff;
            if (mask == 0xab
                  && (env->uncached_cpsr & CPSR_M) != ARM_CPU_MODE_USR) {
                env->regs[15] += 2;
                WR_cpu(env,regs[0],do_arm_semihosting(env));
                return;
            }
        }
        /* Fall through to prefetch abort.  */
    case EXCP_PREFETCH_ABORT:
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x0c;
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_DATA_ABORT:
        new_mode = ARM_CPU_MODE_ABT;
        addr = 0x10;
        mask = CPSR_A | CPSR_I;
        offset = 8;
        break;
    case EXCP_IRQ:
        new_mode = ARM_CPU_MODE_IRQ;
        addr = 0x18;
        /* Disable IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I;
        offset = 4;
        break;
    case EXCP_FIQ:
        new_mode = ARM_CPU_MODE_FIQ;
        addr = 0x1c;
        /* Disable FIQ, IRQ and imprecise data aborts.  */
        mask = CPSR_A | CPSR_I | CPSR_F;
        offset = 4;
        break;
    default:
        cpu_abort(env, "Unhandled exception 0x%x\n", env->exception_index);
        return; /* Never happens.  Keep compiler happy.  */
    }
    /* High vectors.  */
    if (env->cp15.c1_sys & (1 << 13)) {
        addr += 0xffff0000;
    }
    switch_mode (env, new_mode);
    WR_cpu(env,spsr,cpsr_read(env));
    /* Clear IT bits.  */
    env->condexec_bits = 0;
    /* Switch to the new mode, and switch to Arm mode.  */
    /* ??? Thumb interrupt handlers not implemented.  */
    env->uncached_cpsr = (env->uncached_cpsr & ~CPSR_M) | new_mode;
    env->uncached_cpsr |= mask;
    env->thumb = 0;

    WR_cpu(env,regs[14],(env->regs[15] + offset));
    env->regs[15] = addr;
    env->interrupt_request |= CPU_INTERRUPT_EXITTB;
}

uint64_t HELPER(do_interrupt)(void){
    do_interrupt(env);
    return 0;
}
#endif 

void HELPER(set_cp)(CPUState *env, uint32_t insn, uint32_t val)
{
    int cp_num = (insn >> 8) & 0xf;
    int cp_info = (insn >> 5) & 7;
    int src = (insn >> 16) & 0xf;
    int operand = insn & 0xf;

    if (env->cp[cp_num].cp_write)
        env->cp[cp_num].cp_write(env->cp[cp_num].opaque,
                                 cp_info, src, operand, val, GETPC());
        }

uint32_t HELPER(get_cp)(CPUState *env, uint32_t insn)
{
    int cp_num = (insn >> 8) & 0xf;
    int cp_info = (insn >> 5) & 7;
    int dest = (insn >> 16) & 0xf;
    int operand = insn & 0xf;

    if (env->cp[cp_num].cp_read)
        return env->cp[cp_num].cp_read(env->cp[cp_num].opaque,
                                       cp_info, dest, operand, GETPC());
        return 0;
}

#else

void HELPER(set_cp)(CPUState *env, uint32_t insn, uint32_t val)
{
    int op1 = (insn >> 8) & 0xf;
    cpu_abort(env, "cp%i insn %08x\n", op1, insn);
    return;
}

uint32_t HELPER(get_cp)(CPUState *env, uint32_t insn)
{
    int op1 = (insn >> 8) & 0xf;
    cpu_abort(env, "cp%i insn %08x\n", op1, insn);
    return 0;
}

#endif
#ifdef CONFIG_S2E
#include <s2e/s2e_qemu.h>
#endif

/* FIXME: Pass an axplicit pointer to QF to CPUState, and move saturating
   instructions into helper.c  */
uint32_t HELPER(add_setq)(uint32_t a, uint32_t b)
{
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT))
        env->QF = 1;
    return res;
}

uint32_t HELPER(add_saturate)(uint32_t a, uint32_t b)
{
    uint32_t res = a + b;
    if (((res ^ a) & SIGNBIT) && !((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t)a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(sub_saturate)(uint32_t a, uint32_t b)
{
    uint32_t res = a - b;
    if (((res ^ a) & SIGNBIT) && ((a ^ b) & SIGNBIT)) {
        env->QF = 1;
        res = ~(((int32_t)a >> 31) ^ SIGNBIT);
    }
    return res;
}

uint32_t HELPER(double_saturate)(int32_t val)
{
    uint32_t res;
    if (val >= 0x40000000) {
        res = ~SIGNBIT;
        env->QF = 1;
    } else if (val <= (int32_t)0xc0000000) {
        res = SIGNBIT;
        env->QF = 1;
    } else {
        res = val << 1;
    }
    return res;
}

uint32_t HELPER(add_usaturate)(uint32_t a, uint32_t b)
{
    uint32_t res = a + b;
    if (res < a) {
        env->QF = 1;
        res = ~0;
    }
    return res;
}

uint32_t HELPER(sub_usaturate)(uint32_t a, uint32_t b)
{
    uint32_t res = a - b;
    if (res > a) {
        env->QF = 1;
        res = 0;
    }
    return res;
}

/* Signed saturation.  */
static inline uint32_t do_ssat(int32_t val, int shift)
{
    int32_t top;
    uint32_t mask;

    top = val >> shift;
    mask = (1u << shift) - 1;
    if (top > 0) {
        env->QF = 1;
        return mask;
    } else if (top < -1) {
        env->QF = 1;
        return ~mask;
    }
    return val;
}

/* Unsigned saturation.  */
static inline uint32_t do_usat(int32_t val, int shift)
{
    uint32_t max;

    max = (1u << shift) - 1;
    if (val < 0) {
        env->QF = 1;
        return 0;
    } else if (val > max) {
        env->QF = 1;
        return max;
    }
    return val;
}

/* Signed saturate.  */
uint32_t HELPER(ssat)(uint32_t x, uint32_t shift)
{
    return do_ssat(x, shift);
}

/* Dual halfword signed saturate.  */
uint32_t HELPER(ssat16)(uint32_t x, uint32_t shift)
{
    uint32_t res;

    res = (uint16_t)do_ssat((int16_t)x, shift);
    res |= do_ssat(((int32_t)x) >> 16, shift) << 16;
    return res;
}

/* Unsigned saturate.  */
uint32_t HELPER(usat)(uint32_t x, uint32_t shift)
{
    return do_usat(x, shift);
}

/* Dual halfword unsigned saturate.  */
uint32_t HELPER(usat16)(uint32_t x, uint32_t shift)
{
    uint32_t res;

    res = (uint16_t)do_usat((int16_t)x, shift);
    res |= do_usat(((int32_t)x) >> 16, shift) << 16;
    return res;
}

void HELPER(wfi)(void)
{
    env->exception_index = EXCP_HLT;
    env->halted = 1;
    cpu_loop_exit();
}

void HELPER(exception)(uint32_t excp)
{
    env->exception_index = excp;
    cpu_loop_exit();
}
#ifdef CONFIG_S2E

/*
 * S2E: just a helper for switching execution mode during state restore
 */

void switch_mode_concrete(CPUState *env, int mode)
{
    int old_mode;

    old_mode = env->uncached_cpsr & CPSR_M;
    if (mode == old_mode)
        return;

    if (old_mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->fiq_regs, env->regs + 8, 5 * sizeof(uint32_t));
    	memcpy (env->regs + 8, env->usr_regs, 5 * sizeof(uint32_t));

    } else if (mode == ARM_CPU_MODE_FIQ) {
        memcpy (env->usr_regs, env->regs + 8, 5 * sizeof(uint32_t));
        memcpy (env->regs + 8, env->fiq_regs, 5 * sizeof(uint32_t));
    }
}

void cpsr_write_concrete(CPUARMState *env, uint32_t val, uint32_t mask)
{

    if (mask & CPSR_NZCV) {
        env->ZF = (~val) & CPSR_Z;
        env->NF = val;
        env->CF = (val >> 29) & 1;
        env->VF = (val << 3) & 0x80000000;
    }
    if (mask & CPSR_Q)
        env->QF = ((val & CPSR_Q) != 0);
    if (mask & CPSR_T)
        env->thumb = ((val & CPSR_T) != 0);
    if (mask & CPSR_IT_0_1) {
        env->condexec_bits &= ~3;
        env->condexec_bits |= (val >> 25) & 3;
    }
    if (mask & CPSR_IT_2_7) {
        env->condexec_bits &= 3;
        env->condexec_bits |= (val >> 8) & 0xfc;
    }
    if (mask & CPSR_GE) {
        env->GE = (val >> 16) & 0xf;
    }

    if ((env->uncached_cpsr ^ val) & mask & CPSR_M) {
        switch_mode_concrete(env, val & CPSR_M);
    }
    mask &= ~CACHED_CPSR_BITS;
    env->uncached_cpsr = (env->uncached_cpsr & ~mask) | (val & mask);
}

/*
 * S2E: just a helper for dumping concrete cpustate
 */

uint32_t cpsr_read_concrete(CPUARMState *env)
{

    int ZF;
    ZF = (env->ZF == 0);
    return env->uncached_cpsr | (env->NF & 0x80000000) | (ZF << 30) |
        (env->CF << 29) | ((env->VF & 0x80000000) >> 3) | (env->QF << 27)
        | (env->thumb << 5) | ((env->condexec_bits & 3) << 25)
        | ((env->condexec_bits & 0xfc) << 8)
        | (env->GE << 16);

}
#endif

uint32_t HELPER(cpsr_read)(void)
{
    return cpsr_read(env) & ~CPSR_EXEC;
}

void HELPER(cpsr_write)(uint32_t val, uint32_t mask)
{
    cpsr_write(env, val, mask);
}

/* Access to user mode registers from privileged modes.  */
uint32_t HELPER(get_user_reg)(uint32_t regno)
{
    uint32_t val;

    if (regno == 13) {
        val = env->banked_r13[0];
    } else if (regno == 14) {
        val = env->banked_r14[0];
    } else if (regno >= 8
               && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        val = env->usr_regs[regno - 8];
    } else {
        val = env->regs[regno];
    }
    return val;
}

void HELPER(set_user_reg)(uint32_t regno, uint32_t val)
{
    if (regno == 13) {
        env->banked_r13[0] = val;
    } else if (regno == 14) {
        env->banked_r14[0] = val;
    } else if (regno >= 8
               && (env->uncached_cpsr & 0x1f) == ARM_CPU_MODE_FIQ) {
        env->usr_regs[regno - 8] = val;
    } else {
        env->regs[regno] = val;
    }
}

/* ??? Flag setting arithmetic is awkward because we need to do comparisons.
   The only way to do that in TCG is a conditional branch, which clobbers
   all our temporaries.  For now implement these as helper functions.  */

uint32_t HELPER (add_cc)(uint32_t a, uint32_t b)
{
    uint32_t result;
    result = a + b;
    env->NF = env->ZF = result;
    env->CF = result < a;
    env->VF = (a ^ b ^ -1) & (a ^ result);
    return result;
}

uint32_t HELPER(adc_cc)(uint32_t a, uint32_t b)
{
    uint32_t result;
    if (!env->CF) {
        result = a + b;
        env->CF = result < a;
    } else {
        result = a + b + 1;
        env->CF = result <= a;
    }
    env->VF = (a ^ b ^ -1) & (a ^ result);
    env->NF = env->ZF = result;
    return result;
}

uint32_t HELPER(sub_cc)(uint32_t a, uint32_t b)
{
    uint32_t result;
    result = a - b;
    WR_cpu(env,NF, result);
    WR_cpu(env,ZF, result);
    WR_cpu(env,CF, (a >= b));
    WR_cpu(env,VF , ((a ^ b) & (a ^ result)));
    return result;
}

uint32_t HELPER(sbc_cc)(uint32_t a, uint32_t b)
{
    uint32_t result;
    if (!RR_cpu(env,CF)) {
        result = a - b - 1;
        WR_cpu(env,CF,(a > b));
    } else {
        result = a - b;
        WR_cpu(env,CF,(a >= b));
    }
    WR_cpu(env,VF,((a ^ b) & (a ^ result)));
    WR_cpu(env,NF,result);
    WR_cpu(env,ZF,result);
    return result;
}

/* Similarly for variable shift instructions.  */

uint32_t HELPER(shl)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return x << shift;
}

uint32_t HELPER(shr)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32)
        return 0;
    return (uint32_t)x >> shift;
}

uint32_t HELPER(sar)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32)
        shift = 31;
    return (int32_t)x >> shift;
}

uint32_t HELPER(shl_cc)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            WR_cpu(env,CF,(x & 1));
        else
            WR_cpu(env,CF,0);
        return 0;
    } else if (shift != 0) {
        WR_cpu(env,CF,((x >> (32 - shift)) & 1));
        return x << shift;
    }
    return x;
}

uint32_t HELPER(shr_cc)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32) {
        if (shift == 32)
            WR_cpu(env,CF, ((x >> 31) & 1));
        else
            WR_cpu(env,CF ,0);
        return 0;
    } else if (shift != 0) {
        WR_cpu(env,CF,((x >> (shift - 1)) & 1));
        return x >> shift;
    }
    return x;
}

uint32_t HELPER(sar_cc)(uint32_t x, uint32_t i)
{
    int shift = i & 0xff;
    if (shift >= 32) {
        WR_cpu(env,CF, ((x >> 31) & 1));
        return (int32_t)x >> 31;
    } else if (shift != 0) {
        WR_cpu(env,CF,((x >> (shift - 1)) & 1));
        return (int32_t)x >> shift;
    }
    return x;
}

uint32_t HELPER(ror_cc)(uint32_t x, uint32_t i)
{
    int shift1, shift;
    shift1 = i & 0xff;
    shift = shift1 & 0x1f;
    if (shift == 0) {
        if (shift1 != 0)
            WR_cpu(env,CF, ((x >> 31) & 1));
        return x;
    } else {
        WR_cpu(env,CF, ((x >> (shift - 1)) & 1));
        return ((uint32_t)x >> shift) | (x << (32 - shift));
    }
}

void HELPER(neon_vldst_all)(uint32_t insn)
{
#if defined(CONFIG_USER_ONLY)
#define LDB(addr) ldub(addr)
#define LDW(addr) lduw(addr)
#define LDL(addr) ldl(addr)
#define LDQ(addr) ldq(addr)
#define STB(addr, val) stb(addr, val)
#define STW(addr, val) stw(addr, val)
#define STL(addr, val) stl(addr, val)
#define STQ(addr, val) stq(addr, val)
#else
    int user = cpu_mmu_index(env);
#define LDB(addr) slow_ldb_mmu(addr, user, GETPC())
#define LDW(addr) slow_ldw_mmu(addr, user, GETPC())
#define LDL(addr) slow_ldl_mmu(addr, user, GETPC())
#define LDQ(addr) slow_ldq_mmu(addr, user, GETPC())
#define STB(addr, val) slow_stb_mmu(addr, val, user, GETPC())
#define STW(addr, val) slow_stw_mmu(addr, val, user, GETPC())
#define STL(addr, val) slow_stl_mmu(addr, val, user, GETPC())
#define STQ(addr, val) slow_stq_mmu(addr, val, user, GETPC())
#endif
    static const struct {
        int nregs;
        int interleave;
        int spacing;
    } neon_ls_element_type[11] = {
        {4, 4, 1},
        {4, 4, 2},
        {4, 1, 1},
        {4, 2, 1},
        {3, 3, 1},
        {3, 3, 2},
        {3, 1, 1},
        {1, 1, 1},
        {2, 2, 1},
        {2, 2, 2},
        {2, 1, 1}
    };

    const int op = (insn >> 8) & 0xf;
    const int size = (insn >> 6) & 3;
    int rd = ((insn >> 12) & 0x0f) | ((insn >> 18) & 0x10);
    const int rn = (insn >> 16) & 0xf;
    const int load = (insn & (1 << 21)) != 0;
    const int nregs = neon_ls_element_type[op].nregs;
    const int interleave = neon_ls_element_type[op].interleave;
    const int spacing = neon_ls_element_type[op].spacing;
    uint32_t addr = env->regs[rn];
    const int stride = (1 << size) * interleave;
    int i, reg;
    uint64_t tmp64;

    for (reg = 0; reg < nregs; reg++) {
        if (interleave > 2 || (interleave == 2 && nregs == 2)) {
            addr = env->regs[rn] + (1 << size) * reg;
        } else if (interleave == 2 && nregs == 4 && reg == 2) {
            addr = env->regs[rn] + (1 << size);
        }
        switch (size) {
            case 3:
                if (load) {
                    env->vfp.regs[rd] = make_float64(LDQ(addr));
                } else {
                    STQ(addr, float64_val(env->vfp.regs[rd]));
                }
                addr += stride;
                break;
            case 2:
                if (load) {
                    tmp64 = (uint32_t)LDL(addr);
                    addr += stride;
                    tmp64 |= (uint64_t)LDL(addr) << 32;
                    addr += stride;
                    env->vfp.regs[rd] = make_float64(tmp64);
                } else {
                    tmp64 = float64_val(env->vfp.regs[rd]);
                    STL(addr, tmp64);
                    addr += stride;
                    STL(addr, tmp64 >> 32);
                    addr += stride;
                }
                break;
            case 1:
                if (load) {
                    tmp64 = 0ull;
                    for (i = 0; i < 4; i++, addr += stride) {
                        tmp64 |= (uint64_t)LDW(addr) << (i * 16);
                    }
                    env->vfp.regs[rd] = make_float64(tmp64);
                } else {
                    tmp64 = float64_val(env->vfp.regs[rd]);
                    for (i = 0; i < 4; i++, addr += stride, tmp64 >>= 16) {
                        STW(addr, tmp64);
                    }
                }
                break;
            case 0:
                if (load) {
                    tmp64 = 0ull;
                    for (i = 0; i < 8; i++, addr += stride) {
                        tmp64 |= (uint64_t)LDB(addr) << (i * 8);
                    }
                    env->vfp.regs[rd] = make_float64(tmp64);
                } else {
                    tmp64 = float64_val(env->vfp.regs[rd]);
                    for (i = 0; i < 8; i++, addr += stride, tmp64 >>= 8) {
                        STB(addr, tmp64);
                    }
                }
                break;
        }
        rd += spacing;
    }
#undef LDB
#undef LDW
#undef LDL
#undef LDQ
#undef STB
#undef STW
#undef STL
#undef STQ
}
