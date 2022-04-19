/*
 *  x86 FPU, MMX/3DNow!/SSE/SSE2/SSE3/SSSE3/SSE4/PNI helpers
 *
 *  Copyright (c) 2003 Fabrice Bellard
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

#include <math.h>
#include "cpu.h"
#include "exec/helper-proto.h"
#include "fpu/softfloat.h"
#include "fpu/softfloat-macros.h"
#include "qemu/aes.h"
#include "qemu/host-utils.h"
#include "exec/cpu_ldst.h"

#define FPU_RC_MASK         0xc00
#define FPU_RC_NEAR         0x000
#define FPU_RC_DOWN         0x400
#define FPU_RC_UP           0x800
#define FPU_RC_CHOP         0xc00

#define MAXTAN 9223372036854775808.0

/* the following deal with x86 long double-precision numbers */
#define MAXEXPD 0x7fff
#define EXPBIAS 16383
#define EXPD(fp)        (fp.l.upper & 0x7fff)
#define SIGND(fp)       ((fp.l.upper) & 0x8000)
#define MANTD(fp)       (fp.l.lower)
#define BIASEXPONENT(fp) fp.l.upper = (fp.l.upper & ~(0x7fff)) | EXPBIAS

#define FPUS_IE (1 << 0)
#define FPUS_DE (1 << 1)
#define FPUS_ZE (1 << 2)
#define FPUS_OE (1 << 3)
#define FPUS_UE (1 << 4)
#define FPUS_PE (1 << 5)
#define FPUS_SF (1 << 6)
#define FPUS_SE (1 << 7)
#define FPUS_B  (1 << 15)

#define FPUC_EM 0x3f

#define floatx80_lg2 make_floatx80(0x3ffd, 0x9a209a84fbcff799LL)
#define floatx80_l2e make_floatx80(0x3fff, 0xb8aa3b295c17f0bcLL)
#define floatx80_l2t make_floatx80(0x4000, 0xd49a784bcd1b8afeLL)

static inline void fpush(CPUX86State *env)
{
    env->fpstt = (env->fpstt - 1) & 7;
    env->fptags[env->fpstt] = 0; /* validate stack entry */
}

static inline void fpop(CPUX86State *env)
{
    env->fptags[env->fpstt] = 1; /* invalidate stack entry */
    env->fpstt = (env->fpstt + 1) & 7;
}

static inline floatx80 helper_fldt(CPUX86State *env, target_ulong ptr)
{
    CPU_LDoubleU temp;

    temp.l.lower = cpu_ldq_data(env, ptr);
    temp.l.upper = cpu_lduw_data(env, ptr + 8);
    return temp.d;
}

static inline void helper_fstt(CPUX86State *env, floatx80 f, target_ulong ptr)
{
    CPU_LDoubleU temp;

    temp.d = f;
    cpu_stq_data(env, ptr, temp.l.lower);
    cpu_stw_data(env, ptr + 8, temp.l.upper);
}

/* x87 FPU helpers */

static inline double floatx80_to_double(CPUX86State *env, floatx80 a)
{
    union {
        float64 f64;
        double d;
    } u;

    u.f64 = floatx80_to_float64(a, &env->fp_status);
    return u.d;
}

static inline floatx80 double_to_floatx80(CPUX86State *env, double a)
{
    union {
        float64 f64;
        double d;
    } u;

    u.d = a;
    return float64_to_floatx80(u.f64, &env->fp_status);
}

static void fpu_set_exception(CPUX86State *env, int mask)
{
    env->fpus |= mask;
    if (env->fpus & (~env->fpuc & FPUC_EM)) {
        env->fpus |= FPUS_SE | FPUS_B;
    }
}

static inline uint8_t save_exception_flags(CPUX86State *env)
{
    uint8_t old_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);
    return old_flags;
}

static void merge_exception_flags(CPUX86State *env, uint8_t old_flags)
{
    uint8_t new_flags = get_float_exception_flags(&env->fp_status);
    float_raise(old_flags, &env->fp_status);
    fpu_set_exception(env,
                      ((new_flags & float_flag_invalid ? FPUS_IE : 0) |
                       (new_flags & float_flag_divbyzero ? FPUS_ZE : 0) |
                       (new_flags & float_flag_overflow ? FPUS_OE : 0) |
                       (new_flags & float_flag_underflow ? FPUS_UE : 0) |
                       (new_flags & float_flag_inexact ? FPUS_PE : 0) |
                       (new_flags & float_flag_input_denormal ? FPUS_DE : 0)));
}

static inline floatx80 helper_fdiv(CPUX86State *env, floatx80 a, floatx80 b)
{
    if (floatx80_is_zero(b)) {
        fpu_set_exception(env, FPUS_ZE);
    }
    return floatx80_div(a, b, &env->fp_status);
}

static void fpu_raise_exception(CPUX86State *env)
{
    if (env->cr[0] & CR0_NE_MASK) {
        raise_exception(env, EXCP10_COPR);
    }
#if !defined(CONFIG_USER_ONLY)
    else {
        cpu_set_ferr(env);
    }
#endif
}

void helper_flds_FT0(CPUX86State *env, uint32_t val)
{
    union {
        float32 f;
        uint32_t i;
    } u;

    u.i = val;
    FT0 = float32_to_floatx80(u.f, &env->fp_status);
}

void helper_fldl_FT0(CPUX86State *env, uint64_t val)
{
    union {
        float64 f;
        uint64_t i;
    } u;

    u.i = val;
    FT0 = float64_to_floatx80(u.f, &env->fp_status);
}

void helper_fildl_FT0(CPUX86State *env, int32_t val)
{
    FT0 = int32_to_floatx80(val, &env->fp_status);
}

void helper_flds_ST0(CPUX86State *env, uint32_t val)
{
    int new_fpstt;
    union {
        float32 f;
        uint32_t i;
    } u;

    new_fpstt = (env->fpstt - 1) & 7;
    u.i = val;
    env->fpregs[new_fpstt].d = float32_to_floatx80(u.f, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fldl_ST0(CPUX86State *env, uint64_t val)
{
    int new_fpstt;
    union {
        float64 f;
        uint64_t i;
    } u;

    new_fpstt = (env->fpstt - 1) & 7;
    u.i = val;
    env->fpregs[new_fpstt].d = float64_to_floatx80(u.f, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fildl_ST0(CPUX86State *env, int32_t val)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = int32_to_floatx80(val, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fildll_ST0(CPUX86State *env, int64_t val)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = int64_to_floatx80(val, &env->fp_status);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

uint32_t helper_fsts_ST0(CPUX86State *env)
{
    union {
        float32 f;
        uint32_t i;
    } u;

    u.f = floatx80_to_float32(ST0, &env->fp_status);
    return u.i;
}

uint64_t helper_fstl_ST0(CPUX86State *env)
{
    union {
        float64 f;
        uint64_t i;
    } u;

    u.f = floatx80_to_float64(ST0, &env->fp_status);
    return u.i;
}

int32_t helper_fist_ST0(CPUX86State *env)
{
    int32_t val;

    val = floatx80_to_int32(ST0, &env->fp_status);
    if (val != (int16_t)val) {
        val = -32768;
    }
    return val;
}

int32_t helper_fistl_ST0(CPUX86State *env)
{
    int32_t val;
    signed char old_exp_flags;

    old_exp_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);

    val = floatx80_to_int32(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x80000000;
    }
    set_float_exception_flags(get_float_exception_flags(&env->fp_status)
                                | old_exp_flags, &env->fp_status);
    return val;
}

int64_t helper_fistll_ST0(CPUX86State *env)
{
    int64_t val;
    signed char old_exp_flags;

    old_exp_flags = get_float_exception_flags(&env->fp_status);
    set_float_exception_flags(0, &env->fp_status);

    val = floatx80_to_int32(ST0, &env->fp_status);
    if (get_float_exception_flags(&env->fp_status) & float_flag_invalid) {
        val = 0x8000000000000000ULL;
    }
    set_float_exception_flags(get_float_exception_flags(&env->fp_status)
                                | old_exp_flags, &env->fp_status);
    return val;
}

int32_t helper_fistt_ST0(CPUX86State *env)
{
    int32_t val;

    val = floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
    if (val != (int16_t)val) {
        val = -32768;
    }
    return val;
}

int32_t helper_fisttl_ST0(CPUX86State *env)
{
    int32_t val;

    val = floatx80_to_int32_round_to_zero(ST0, &env->fp_status);
    return val;
}

int64_t helper_fisttll_ST0(CPUX86State *env)
{
    int64_t val;

    val = floatx80_to_int64_round_to_zero(ST0, &env->fp_status);
    return val;
}

void helper_fldt_ST0(CPUX86State *env, target_ulong ptr)
{
    int new_fpstt;

    new_fpstt = (env->fpstt - 1) & 7;
    env->fpregs[new_fpstt].d = helper_fldt(env, ptr);
    env->fpstt = new_fpstt;
    env->fptags[new_fpstt] = 0; /* validate stack entry */
}

void helper_fstt_ST0(CPUX86State *env, target_ulong ptr)
{
    helper_fstt(env, ST0, ptr);
}

void helper_fpush(CPUX86State *env)
{
    fpush(env);
}

void helper_fpop(CPUX86State *env)
{
    fpop(env);
}

void helper_fdecstp(CPUX86State *env)
{
    env->fpstt = (env->fpstt - 1) & 7;
    env->fpus &= ~0x4700;
}

void helper_fincstp(CPUX86State *env)
{
    env->fpstt = (env->fpstt + 1) & 7;
    env->fpus &= ~0x4700;
}

/* FPU move */

void helper_ffree_STN(CPUX86State *env, int st_index)
{
    env->fptags[(env->fpstt + st_index) & 7] = 1;
}

void helper_fmov_ST0_FT0(CPUX86State *env)
{
    ST0 = FT0;
}

void helper_fmov_FT0_STN(CPUX86State *env, int st_index)
{
    FT0 = ST(st_index);
}

void helper_fmov_ST0_STN(CPUX86State *env, int st_index)
{
    ST0 = ST(st_index);
}

void helper_fmov_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = ST0;
}

void helper_fxchg_ST0_STN(CPUX86State *env, int st_index)
{
    floatx80 tmp;

    tmp = ST(st_index);
    ST(st_index) = ST0;
    ST0 = tmp;
}

/* FPU operations */

static const int fcom_ccval[4] = {0x0100, 0x4000, 0x0000, 0x4500};

void helper_fcom_ST0_FT0(CPUX86State *env)
{
    int ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    env->fpus = (env->fpus & ~0x4500) | fcom_ccval[ret + 1];
}

void helper_fucom_ST0_FT0(CPUX86State *env)
{
    int ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    env->fpus = (env->fpus & ~0x4500) | fcom_ccval[ret + 1];
}

static const int fcomi_ccval[4] = {CC_C, CC_Z, 0, CC_Z | CC_P | CC_C};

void helper_fcomi_ST0_FT0(CPUX86State *env)
{
    int eflags;
    int ret;

    ret = floatx80_compare(ST0, FT0, &env->fp_status);
    eflags = cpu_cc_compute_all(env, CC_OP);
    eflags = (eflags & ~(CC_Z | CC_P | CC_C)) | fcomi_ccval[ret + 1];
    CC_SRC = eflags;
}

void helper_fucomi_ST0_FT0(CPUX86State *env)
{
    int eflags;
    int ret;

    ret = floatx80_compare_quiet(ST0, FT0, &env->fp_status);
    eflags = cpu_cc_compute_all(env, CC_OP);
    eflags = (eflags & ~(CC_Z | CC_P | CC_C)) | fcomi_ccval[ret + 1];
    CC_SRC = eflags;
}

void helper_fadd_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_add(ST0, FT0, &env->fp_status);
}

void helper_fmul_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_mul(ST0, FT0, &env->fp_status);
}

void helper_fsub_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_sub(ST0, FT0, &env->fp_status);
}

void helper_fsubr_ST0_FT0(CPUX86State *env)
{
    ST0 = floatx80_sub(FT0, ST0, &env->fp_status);
}

void helper_fdiv_ST0_FT0(CPUX86State *env)
{
    ST0 = helper_fdiv(env, ST0, FT0);
}

void helper_fdivr_ST0_FT0(CPUX86State *env)
{
    ST0 = helper_fdiv(env, FT0, ST0);
}

/* fp operations between STN and ST0 */

void helper_fadd_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_add(ST(st_index), ST0, &env->fp_status);
}

void helper_fmul_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_mul(ST(st_index), ST0, &env->fp_status);
}

void helper_fsub_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_sub(ST(st_index), ST0, &env->fp_status);
}

void helper_fsubr_STN_ST0(CPUX86State *env, int st_index)
{
    ST(st_index) = floatx80_sub(ST0, ST(st_index), &env->fp_status);
}

void helper_fdiv_STN_ST0(CPUX86State *env, int st_index)
{
    floatx80 *p;

    p = &ST(st_index);
    *p = helper_fdiv(env, *p, ST0);
}

void helper_fdivr_STN_ST0(CPUX86State *env, int st_index)
{
    floatx80 *p;

    p = &ST(st_index);
    *p = helper_fdiv(env, ST0, *p);
}

/* misc FPU operations */
void helper_fchs_ST0(CPUX86State *env)
{
    ST0 = floatx80_chs(ST0);
}

void helper_fabs_ST0(CPUX86State *env)
{
    ST0 = floatx80_abs(ST0);
}

void helper_fld1_ST0(CPUX86State *env)
{
    ST0 = floatx80_one;
}

void helper_fldl2t_ST0(CPUX86State *env)
{
    ST0 = floatx80_l2t;
}

void helper_fldl2e_ST0(CPUX86State *env)
{
    ST0 = floatx80_l2e;
}

void helper_fldpi_ST0(CPUX86State *env)
{
    ST0 = floatx80_pi;
}

void helper_fldlg2_ST0(CPUX86State *env)
{
    ST0 = floatx80_lg2;
}

void helper_fldln2_ST0(CPUX86State *env)
{
    ST0 = floatx80_ln2;
}

void helper_fldz_ST0(CPUX86State *env)
{
    ST0 = floatx80_zero;
}

void helper_fldz_FT0(CPUX86State *env)
{
    FT0 = floatx80_zero;
}

uint32_t helper_fnstsw(CPUX86State *env)
{
    return (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
}

uint32_t helper_fnstcw(CPUX86State *env)
{
    return env->fpuc;
}

void update_fp_status(CPUX86State *env)
{
    int rnd_type;

    /* set rounding mode */
    switch (env->fpuc & FPU_RC_MASK) {
    default:
    case FPU_RC_NEAR:
        rnd_type = float_round_nearest_even;
        break;
    case FPU_RC_DOWN:
        rnd_type = float_round_down;
        break;
    case FPU_RC_UP:
        rnd_type = float_round_up;
        break;
    case FPU_RC_CHOP:
        rnd_type = float_round_to_zero;
        break;
    }
    set_float_rounding_mode(rnd_type, &env->fp_status);
    switch ((env->fpuc >> 8) & 3) {
    case 0:
        rnd_type = 32;
        break;
    case 2:
        rnd_type = 64;
        break;
    case 3:
    default:
        rnd_type = 80;
        break;
    }
    set_floatx80_rounding_precision(rnd_type, &env->fp_status);
}

void helper_fldcw(CPUX86State *env, uint32_t val)
{
    cpu_set_fpuc(env, val);
}

void helper_fclex(CPUX86State *env)
{
    env->fpus &= 0x7f00;
}

void helper_fwait(CPUX86State *env)
{
    if (env->fpus & FPUS_SE) {
        fpu_raise_exception(env);
    }
}

void helper_fninit(CPUX86State *env)
{
    env->fpus = 0;
    env->fpstt = 0;
    cpu_set_fpuc(env, 0x37f);
    env->fptags[0] = 1;
    env->fptags[1] = 1;
    env->fptags[2] = 1;
    env->fptags[3] = 1;
    env->fptags[4] = 1;
    env->fptags[5] = 1;
    env->fptags[6] = 1;
    env->fptags[7] = 1;
}

/* BCD ops */

void helper_fbld_ST0(CPUX86State *env, target_ulong ptr)
{
    floatx80 tmp;
    uint64_t val;
    unsigned int v;
    int i;

    val = 0;
    for (i = 8; i >= 0; i--) {
        v = cpu_ldub_data(env, ptr + i);
        val = (val * 100) + ((v >> 4) * 10) + (v & 0xf);
    }
    tmp = int64_to_floatx80(val, &env->fp_status);
    if (cpu_ldub_data(env, ptr + 9) & 0x80) {
        tmp = floatx80_chs(tmp);
    }
    fpush(env);
    ST0 = tmp;
}

void helper_fbst_ST0(CPUX86State *env, target_ulong ptr)
{
    int v;
    target_ulong mem_ref, mem_end;
    int64_t val;

    val = floatx80_to_int64(ST0, &env->fp_status);
    mem_ref = ptr;
    mem_end = mem_ref + 9;
    if (val < 0) {
        cpu_stb_data(env, mem_end, 0x80);
        val = -val;
    } else {
        cpu_stb_data(env, mem_end, 0x00);
    }
    while (mem_ref < mem_end) {
        if (val == 0) {
            break;
        }
        v = val % 100;
        val = val / 100;
        v = ((v / 10) << 4) | (v % 10);
        cpu_stb_data(env, mem_ref++, v);
    }
    while (mem_ref < mem_end) {
        cpu_stb_data(env, mem_ref++, 0);
    }
}

void helper_f2xm1(CPUX86State *env)
{
    double val = floatx80_to_double(env, ST0);

    val = pow(2.0, val) - 1.0;
    ST0 = double_to_floatx80(env, val);
}

/* 128-bit significand of log2(e).  */
#define log2_e_sig_high 0xb8aa3b295c17f0bbULL
#define log2_e_sig_low 0xbe87fed0691d3e89ULL

/*
 * Polynomial coefficients for an approximation to log2((1+x)/(1-x)),
 * with only odd powers of x used, for x in the interval [2*sqrt(2)-3,
 * 3-2*sqrt(2)], which corresponds to logarithms of numbers in the
 * interval [sqrt(2)/2, sqrt(2)].
 */
#define fyl2x_coeff_0 make_floatx80(0x4000, 0xb8aa3b295c17f0bcULL)
#define fyl2x_coeff_0_low make_floatx80(0xbfbf, 0x834972fe2d7bab1bULL)
#define fyl2x_coeff_1 make_floatx80(0x3ffe, 0xf6384ee1d01febb8ULL)
#define fyl2x_coeff_2 make_floatx80(0x3ffe, 0x93bb62877cdfa2e3ULL)
#define fyl2x_coeff_3 make_floatx80(0x3ffd, 0xd30bb153d808f269ULL)
#define fyl2x_coeff_4 make_floatx80(0x3ffd, 0xa42589eaf451499eULL)
#define fyl2x_coeff_5 make_floatx80(0x3ffd, 0x864d42c0f8f17517ULL)
#define fyl2x_coeff_6 make_floatx80(0x3ffc, 0xe3476578adf26272ULL)
#define fyl2x_coeff_7 make_floatx80(0x3ffc, 0xc506c5f874e6d80fULL)
#define fyl2x_coeff_8 make_floatx80(0x3ffc, 0xac5cf50cc57d6372ULL)
#define fyl2x_coeff_9 make_floatx80(0x3ffc, 0xb1ed0066d971a103ULL)

/*
 * Compute an approximation of log2(1+arg), where 1+arg is in the
 * interval [sqrt(2)/2, sqrt(2)].  It is assumed that when this
 * function is called, rounding precision is set to 80 and the
 * round-to-nearest mode is in effect.  arg must not be exactly zero,
 * and must not be so close to zero that underflow might occur.
 */
static void helper_fyl2x_common(CPUX86State *env, floatx80 arg, int32_t *exp,
                                uint64_t *sig0, uint64_t *sig1)
{
    uint64_t arg0_sig = extractFloatx80Frac(arg);
    int32_t arg0_exp = extractFloatx80Exp(arg);
    bool arg0_sign = extractFloatx80Sign(arg);
    bool asign;
    int32_t dexp, texp, aexp;
    uint64_t dsig0, dsig1, tsig0, tsig1, rsig0, rsig1, rsig2;
    uint64_t msig0, msig1, msig2, t2sig0, t2sig1, t2sig2, t2sig3;
    uint64_t asig0, asig1, asig2, asig3, bsig0, bsig1;
    floatx80 t2, accum;

    /*
     * Compute an approximation of arg/(2+arg), with extra precision,
     * as the argument to a polynomial approximation.  The extra
     * precision is only needed for the first term of the
     * approximation, with subsequent terms being significantly
     * smaller; the approximation only uses odd exponents, and the
     * square of arg/(2+arg) is at most 17-12*sqrt(2) = 0.029....
     */
    if (arg0_sign) {
        dexp = 0x3fff;
        shift128RightJamming(arg0_sig, 0, dexp - arg0_exp, &dsig0, &dsig1);
        sub128(0, 0, dsig0, dsig1, &dsig0, &dsig1);
    } else {
        dexp = 0x4000;
        shift128RightJamming(arg0_sig, 0, dexp - arg0_exp, &dsig0, &dsig1);
        dsig0 |= 0x8000000000000000ULL;
    }
    texp = arg0_exp - dexp + 0x3ffe;
    rsig0 = arg0_sig;
    rsig1 = 0;
    rsig2 = 0;
    if (dsig0 <= rsig0) {
        shift128Right(rsig0, rsig1, 1, &rsig0, &rsig1);
        ++texp;
    }
    tsig0 = estimateDiv128To64(rsig0, rsig1, dsig0);
    mul128By64To192(dsig0, dsig1, tsig0, &msig0, &msig1, &msig2);
    sub192(rsig0, rsig1, rsig2, msig0, msig1, msig2,
           &rsig0, &rsig1, &rsig2);
    while ((int64_t) rsig0 < 0) {
        --tsig0;
        add192(rsig0, rsig1, rsig2, 0, dsig0, dsig1,
               &rsig0, &rsig1, &rsig2);
    }
    tsig1 = estimateDiv128To64(rsig1, rsig2, dsig0);
    /*
     * No need to correct any estimation error in tsig1; even with
     * such error, it is accurate enough.  Now compute the square of
     * that approximation.
     */
    mul128To256(tsig0, tsig1, tsig0, tsig1,
                &t2sig0, &t2sig1, &t2sig2, &t2sig3);
    t2 = normalizeRoundAndPackFloatx80(floatx80_precision_x, false,
                                       texp + texp - 0x3ffe,
                                       t2sig0, t2sig1, &env->fp_status);

    /* Compute the lower parts of the polynomial expansion.  */
    accum = floatx80_mul(fyl2x_coeff_9, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_8, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_7, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_6, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_5, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_4, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_3, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_2, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_1, accum, &env->fp_status);
    accum = floatx80_mul(accum, t2, &env->fp_status);
    accum = floatx80_add(fyl2x_coeff_0_low, accum, &env->fp_status);

    /*
     * The full polynomial expansion is fyl2x_coeff_0 + accum (where
     * accum has much lower magnitude, and so, in particular, carry
     * out of the addition is not possible), multiplied by t.  (This
     * expansion is only accurate to about 70 bits, not 128 bits.)
     */
    aexp = extractFloatx80Exp(fyl2x_coeff_0);
    asign = extractFloatx80Sign(fyl2x_coeff_0);
    shift128RightJamming(extractFloatx80Frac(accum), 0,
                         aexp - extractFloatx80Exp(accum),
                         &asig0, &asig1);
    bsig0 = extractFloatx80Frac(fyl2x_coeff_0);
    bsig1 = 0;
    if (asign == extractFloatx80Sign(accum)) {
        add128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
    } else {
        sub128(bsig0, bsig1, asig0, asig1, &asig0, &asig1);
    }
    /* Multiply by t to compute the required result.  */
    mul128To256(asig0, asig1, tsig0, tsig1,
                &asig0, &asig1, &asig2, &asig3);
    aexp += texp - 0x3ffe;
    *exp = aexp;
    *sig0 = asig0;
    *sig1 = asig1;
}

void helper_fyl2x(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    uint64_t arg0_sig = extractFloatx80Frac(ST0);
    int32_t arg0_exp = extractFloatx80Exp(ST0);
    bool arg0_sign = extractFloatx80Sign(ST0);
    uint64_t arg1_sig = extractFloatx80Frac(ST1);
    int32_t arg1_exp = extractFloatx80Exp(ST1);
    bool arg1_sign = extractFloatx80Sign(ST1);

    if (floatx80_is_signaling_nan(ST0)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_silence_nan(ST0);
    } else if (floatx80_is_signaling_nan(ST1)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_silence_nan(ST1);
    } else if (floatx80_invalid_encoding(ST0) ||
               floatx80_invalid_encoding(ST1)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_any_nan(ST0)) {
        ST1 = ST0;
    } else if (floatx80_is_any_nan(ST1)) {
        /* Pass this NaN through.  */
    } else if (arg0_sign && !floatx80_is_zero(ST0)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_infinity(ST1)) {
        FloatRelation cmp = floatx80_compare(ST0, floatx80_one,
                                             &env->fp_status);
        switch (cmp) {
        case float_relation_less:
            ST1 = floatx80_chs(ST1);
            break;
        case float_relation_greater:
            /* Result is infinity of the same sign as ST1.  */
            break;
        default:
            float_raise(float_flag_invalid, &env->fp_status);
            ST1 = floatx80_default_nan(&env->fp_status);
            break;
        }
    } else if (floatx80_is_infinity(ST0)) {
        if (floatx80_is_zero(ST1)) {
            float_raise(float_flag_invalid, &env->fp_status);
            ST1 = floatx80_default_nan(&env->fp_status);
        } else if (arg1_sign) {
            ST1 = floatx80_chs(ST0);
        } else {
            ST1 = ST0;
        }
    } else if (floatx80_is_zero(ST0)) {
        if (floatx80_is_zero(ST1)) {
            float_raise(float_flag_invalid, &env->fp_status);
            ST1 = floatx80_default_nan(&env->fp_status);
        } else {
            /* Result is infinity with opposite sign to ST1.  */
            float_raise(float_flag_divbyzero, &env->fp_status);
            ST1 = make_floatx80(arg1_sign ? 0x7fff : 0xffff,
                                0x8000000000000000ULL);
        }
    } else if (floatx80_is_zero(ST1)) {
        if (floatx80_lt(ST0, floatx80_one, &env->fp_status)) {
            ST1 = floatx80_chs(ST1);
        }
        /* Otherwise, ST1 is already the correct result.  */
    } else if (floatx80_eq(ST0, floatx80_one, &env->fp_status)) {
        if (arg1_sign) {
            ST1 = floatx80_chs(floatx80_zero);
        } else {
            ST1 = floatx80_zero;
        }
    } else {
        int32_t int_exp;
        floatx80 arg0_m1;
        FloatRoundMode save_mode = env->fp_status.float_rounding_mode;
        FloatX80RoundPrec save_prec =
            env->fp_status.floatx80_rounding_precision;
        env->fp_status.float_rounding_mode = float_round_nearest_even;
        env->fp_status.floatx80_rounding_precision = floatx80_precision_x;

        if (arg0_exp == 0) {
            normalizeFloatx80Subnormal(arg0_sig, &arg0_exp, &arg0_sig);
        }
        if (arg1_exp == 0) {
            normalizeFloatx80Subnormal(arg1_sig, &arg1_exp, &arg1_sig);
        }
        int_exp = arg0_exp - 0x3fff;
        if (arg0_sig > 0xb504f333f9de6484ULL) {
            ++int_exp;
        }
        arg0_m1 = floatx80_sub(floatx80_scalbn(ST0, -int_exp,
                                               &env->fp_status),
                               floatx80_one, &env->fp_status);
        if (floatx80_is_zero(arg0_m1)) {
            /* Exact power of 2; multiply by ST1.  */
            env->fp_status.float_rounding_mode = save_mode;
            ST1 = floatx80_mul(int32_to_floatx80(int_exp, &env->fp_status),
                               ST1, &env->fp_status);
        } else {
            bool asign = extractFloatx80Sign(arg0_m1);
            int32_t aexp;
            uint64_t asig0, asig1, asig2;
            helper_fyl2x_common(env, arg0_m1, &aexp, &asig0, &asig1);
            if (int_exp != 0) {
                bool isign = (int_exp < 0);
                int32_t iexp;
                uint64_t isig;
                int shift;
                int_exp = isign ? -int_exp : int_exp;
                shift = clz32(int_exp) + 32;
                isig = int_exp;
                isig <<= shift;
                iexp = 0x403e - shift;
                shift128RightJamming(asig0, asig1, iexp - aexp,
                                     &asig0, &asig1);
                if (asign == isign) {
                    add128(isig, 0, asig0, asig1, &asig0, &asig1);
                } else {
                    sub128(isig, 0, asig0, asig1, &asig0, &asig1);
                }
                aexp = iexp;
                asign = isign;
            }
            /*
             * Multiply by the second argument to compute the required
             * result.
             */
            if (arg1_exp == 0) {
                normalizeFloatx80Subnormal(arg1_sig, &arg1_exp, &arg1_sig);
            }
            mul128By64To192(asig0, asig1, arg1_sig, &asig0, &asig1, &asig2);
            aexp += arg1_exp - 0x3ffe;
            /* This result is inexact.  */
            asig1 |= 1;
            env->fp_status.float_rounding_mode = save_mode;
            ST1 = normalizeRoundAndPackFloatx80(floatx80_precision_x,
                                                asign ^ arg1_sign, aexp,
                                                asig0, asig1, &env->fp_status);
        }

        env->fp_status.floatx80_rounding_precision = save_prec;
    }
    fpop(env);
    merge_exception_flags(env, old_flags);
}

void helper_fptan(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        fptemp = tan(fptemp);
        ST0 = double_to_floatx80(env, fptemp);
        fpush(env);
        ST0 = floatx80_one;
        env->fpus &= ~0x400; /* C2 <-- 0 */
        /* the above code is for |arg| < 2**52 only */
    }
}

void helper_fpatan(CPUX86State *env)
{
    double fptemp, fpsrcop;

    fpsrcop = floatx80_to_double(env, ST1);
    fptemp = floatx80_to_double(env, ST0);
    ST1 = double_to_floatx80(env, atan2(fpsrcop, fptemp));
    fpop(env);
}

void helper_fxtract(CPUX86State *env)
{
    CPU_LDoubleU temp;

    temp.d = ST0;

    if (floatx80_is_zero(ST0)) {
        /* Easy way to generate -inf and raising division by 0 exception */
        ST0 = floatx80_div(floatx80_chs(floatx80_one), floatx80_zero,
                           &env->fp_status);
        fpush(env);
        ST0 = temp.d;
    } else {
        int expdif;

        expdif = EXPD(temp) - EXPBIAS;
        /* DP exponent bias */
        ST0 = int32_to_floatx80(expdif, &env->fp_status);
        fpush(env);
        BIASEXPONENT(temp);
        ST0 = temp.d;
    }
}

void helper_fprem1(CPUX86State *env)
{
    double st0, st1, dblq, fpsrcop, fptemp;
    CPU_LDoubleU fpsrcop1, fptemp1;
    int expdif;
    signed long long int q;

    st0 = floatx80_to_double(env, ST0);
    st1 = floatx80_to_double(env, ST1);

    if (isinf(st0) || isnan(st0) || isnan(st1) || (st1 == 0.0)) {
        ST0 = double_to_floatx80(env, 0.0 / 0.0); /* NaN */
        env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
        return;
    }

    fpsrcop = st0;
    fptemp = st1;
    fpsrcop1.d = ST0;
    fptemp1.d = ST1;
    expdif = EXPD(fpsrcop1) - EXPD(fptemp1);

    if (expdif < 0) {
        /* optimisation? taken from the AMD docs */
        env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
        /* ST0 is unchanged */
        return;
    }

    if (expdif < 53) {
        dblq = fpsrcop / fptemp;
        /* round dblq towards nearest integer */
        dblq = rint(dblq);
        st0 = fpsrcop - fptemp * dblq;

        /* convert dblq to q by truncating towards zero */
        if (dblq < 0.0) {
            q = (signed long long int)(-dblq);
        } else {
            q = (signed long long int)dblq;
        }

        env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
        /* (C0,C3,C1) <-- (q2,q1,q0) */
        env->fpus |= (q & 0x4) << (8 - 2);  /* (C0) <-- q2 */
        env->fpus |= (q & 0x2) << (14 - 1); /* (C3) <-- q1 */
        env->fpus |= (q & 0x1) << (9 - 0);  /* (C1) <-- q0 */
    } else {
        env->fpus |= 0x400;  /* C2 <-- 1 */
        fptemp = pow(2.0, expdif - 50);
        fpsrcop = (st0 / st1) / fptemp;
        /* fpsrcop = integer obtained by chopping */
        fpsrcop = (fpsrcop < 0.0) ?
                  -(floor(fabs(fpsrcop))) : floor(fpsrcop);
        st0 -= (st1 * fpsrcop * fptemp);
    }
    ST0 = double_to_floatx80(env, st0);
}

void helper_fprem(CPUX86State *env)
{
    double st0, st1, dblq, fpsrcop, fptemp;
    CPU_LDoubleU fpsrcop1, fptemp1;
    int expdif;
    signed long long int q;

    st0 = floatx80_to_double(env, ST0);
    st1 = floatx80_to_double(env, ST1);

    if (isinf(st0) || isnan(st0) || isnan(st1) || (st1 == 0.0)) {
        ST0 = double_to_floatx80(env, 0.0 / 0.0); /* NaN */
        env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
        return;
    }

    fpsrcop = st0;
    fptemp = st1;
    fpsrcop1.d = ST0;
    fptemp1.d = ST1;
    expdif = EXPD(fpsrcop1) - EXPD(fptemp1);

    if (expdif < 0) {
        /* optimisation? taken from the AMD docs */
        env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
        /* ST0 is unchanged */
        return;
    }

    if (expdif < 53) {
        dblq = fpsrcop / fptemp; /* ST0 / ST1 */
        /* round dblq towards zero */
        dblq = (dblq < 0.0) ? ceil(dblq) : floor(dblq);
        st0 = fpsrcop - fptemp * dblq; /* fpsrcop is ST0 */

        /* convert dblq to q by truncating towards zero */
        if (dblq < 0.0) {
            q = (signed long long int)(-dblq);
        } else {
            q = (signed long long int)dblq;
        }

        env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
        /* (C0,C3,C1) <-- (q2,q1,q0) */
        env->fpus |= (q & 0x4) << (8 - 2);  /* (C0) <-- q2 */
        env->fpus |= (q & 0x2) << (14 - 1); /* (C3) <-- q1 */
        env->fpus |= (q & 0x1) << (9 - 0);  /* (C1) <-- q0 */
    } else {
        int N = 32 + (expdif % 32); /* as per AMD docs */

        env->fpus |= 0x400;  /* C2 <-- 1 */
        fptemp = pow(2.0, (double)(expdif - N));
        fpsrcop = (st0 / st1) / fptemp;
        /* fpsrcop = integer obtained by chopping */
        fpsrcop = (fpsrcop < 0.0) ?
                  -(floor(fabs(fpsrcop))) : floor(fpsrcop);
        st0 -= (st1 * fpsrcop * fptemp);
    }
    ST0 = double_to_floatx80(env, st0);
}

void helper_fyl2xp1(CPUX86State *env)
{
    uint8_t old_flags = save_exception_flags(env);
    uint64_t arg0_sig = extractFloatx80Frac(ST0);
    int32_t arg0_exp = extractFloatx80Exp(ST0);
    bool arg0_sign = extractFloatx80Sign(ST0);
    uint64_t arg1_sig = extractFloatx80Frac(ST1);
    int32_t arg1_exp = extractFloatx80Exp(ST1);
    bool arg1_sign = extractFloatx80Sign(ST1);

    if (floatx80_is_signaling_nan(ST0)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_silence_nan(ST0);
    } else if (floatx80_is_signaling_nan(ST1)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_silence_nan(ST1);
    } else if (floatx80_invalid_encoding(ST0) ||
               floatx80_invalid_encoding(ST1)) {
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_any_nan(ST0)) {
        ST1 = ST0;
    } else if (floatx80_is_any_nan(ST1)) {
        /* Pass this NaN through.  */
    } else if (arg0_exp > 0x3ffd ||
               (arg0_exp == 0x3ffd && arg0_sig > (arg0_sign ?
                                                  0x95f619980c4336f7ULL :
                                                  0xd413cccfe7799211ULL))) {
        /*
         * Out of range for the instruction (ST0 must have absolute
         * value less than 1 - sqrt(2)/2 = 0.292..., according to
         * Intel manuals; AMD manuals allow a range from sqrt(2)/2 - 1
         * to sqrt(2) - 1, which we allow here), treat as invalid.
         */
        float_raise(float_flag_invalid, &env->fp_status);
        ST1 = floatx80_default_nan(&env->fp_status);
    } else if (floatx80_is_zero(ST0) || floatx80_is_zero(ST1) ||
               arg1_exp == 0x7fff) {
        /*
         * One argument is zero, or multiplying by infinity; correct
         * result is exact and can be obtained by multiplying the
         * arguments.
         */
        ST1 = floatx80_mul(ST0, ST1, &env->fp_status);
    } else if (arg0_exp < 0x3fb0) {
        /*
         * Multiplying both arguments and an extra-precision version
         * of log2(e) is sufficiently precise.
         */
        uint64_t sig0, sig1, sig2;
        int32_t exp;
        if (arg0_exp == 0) {
            normalizeFloatx80Subnormal(arg0_sig, &arg0_exp, &arg0_sig);
        }
        if (arg1_exp == 0) {
            normalizeFloatx80Subnormal(arg1_sig, &arg1_exp, &arg1_sig);
        }
        mul128By64To192(log2_e_sig_high, log2_e_sig_low, arg0_sig,
                        &sig0, &sig1, &sig2);
        exp = arg0_exp + 1;
        mul128By64To192(sig0, sig1, arg1_sig, &sig0, &sig1, &sig2);
        exp += arg1_exp - 0x3ffe;
        /* This result is inexact.  */
        sig1 |= 1;
        ST1 = normalizeRoundAndPackFloatx80(floatx80_precision_x,
                                            arg0_sign ^ arg1_sign, exp,
                                            sig0, sig1, &env->fp_status);
    } else {
        int32_t aexp;
        uint64_t asig0, asig1, asig2;
        FloatRoundMode save_mode = env->fp_status.float_rounding_mode;
        FloatX80RoundPrec save_prec =
            env->fp_status.floatx80_rounding_precision;
        env->fp_status.float_rounding_mode = float_round_nearest_even;
        env->fp_status.floatx80_rounding_precision = floatx80_precision_x;

        helper_fyl2x_common(env, ST0, &aexp, &asig0, &asig1);
        /*
         * Multiply by the second argument to compute the required
         * result.
         */
        if (arg1_exp == 0) {
            normalizeFloatx80Subnormal(arg1_sig, &arg1_exp, &arg1_sig);
        }
        mul128By64To192(asig0, asig1, arg1_sig, &asig0, &asig1, &asig2);
        aexp += arg1_exp - 0x3ffe;
        /* This result is inexact.  */
        asig1 |= 1;
        env->fp_status.float_rounding_mode = save_mode;
        ST1 = normalizeRoundAndPackFloatx80(floatx80_precision_x,
                                            arg0_sign ^ arg1_sign, aexp,
                                            asig0, asig1, &env->fp_status);
        env->fp_status.floatx80_rounding_precision = save_prec;
    }
    fpop(env);
    merge_exception_flags(env, old_flags);
}

void helper_fsqrt(CPUX86State *env)
{
    if (floatx80_is_neg(ST0)) {
        env->fpus &= ~0x4700;  /* (C3,C2,C1,C0) <-- 0000 */
        env->fpus |= 0x400;
    }
    ST0 = floatx80_sqrt(ST0, &env->fp_status);
}

void helper_fsincos(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, sin(fptemp));
        fpush(env);
        ST0 = double_to_floatx80(env, cos(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**63 only */
    }
}

void helper_frndint(CPUX86State *env)
{
    ST0 = floatx80_round_to_int(ST0, &env->fp_status);
}

void helper_fscale(CPUX86State *env)
{
    if (floatx80_is_any_nan(ST1)) {
        ST0 = ST1;
    } else {
        int n = floatx80_to_int32_round_to_zero(ST1, &env->fp_status);
        ST0 = floatx80_scalbn(ST0, n, &env->fp_status);
    }
}

void helper_fsin(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, sin(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**53 only */
    }
}

void helper_fcos(CPUX86State *env)
{
    double fptemp = floatx80_to_double(env, ST0);

    if ((fptemp > MAXTAN) || (fptemp < -MAXTAN)) {
        env->fpus |= 0x400;
    } else {
        ST0 = double_to_floatx80(env, cos(fptemp));
        env->fpus &= ~0x400;  /* C2 <-- 0 */
        /* the above code is for |arg| < 2**63 only */
    }
}

void helper_fxam_ST0(CPUX86State *env)
{
    CPU_LDoubleU temp;
    int expdif;

    temp.d = ST0;

    env->fpus &= ~0x4700; /* (C3,C2,C1,C0) <-- 0000 */
    if (SIGND(temp)) {
        env->fpus |= 0x200; /* C1 <-- 1 */
    }

    /* XXX: test fptags too */
    expdif = EXPD(temp);
    if (expdif == MAXEXPD) {
        if (MANTD(temp) == 0x8000000000000000ULL) {
            env->fpus |= 0x500; /* Infinity */
        } else {
            env->fpus |= 0x100; /* NaN */
        }
    } else if (expdif == 0) {
        if (MANTD(temp) == 0) {
            env->fpus |=  0x4000; /* Zero */
        } else {
            env->fpus |= 0x4400; /* Denormal */
        }
    } else {
        env->fpus |= 0x400;
    }
}

void helper_fstenv(CPUX86State *env, target_ulong ptr, int data32)
{
    int fpus, fptag, exp, i;
    uint64_t mant;
    CPU_LDoubleU tmp;

    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
    fptag = 0;
    for (i = 7; i >= 0; i--) {
        fptag <<= 2;
        if (env->fptags[i]) {
            fptag |= 3;
        } else {
            tmp.d = env->fpregs[i].d;
            exp = EXPD(tmp);
            mant = MANTD(tmp);
            if (exp == 0 && mant == 0) {
                /* zero */
                fptag |= 1;
            } else if (exp == 0 || exp == MAXEXPD
                       || (mant & (1LL << 63)) == 0) {
                /* NaNs, infinity, denormal */
                fptag |= 2;
            }
        }
    }
    if (data32) {
        /* 32 bit */
        cpu_stl_data(env, ptr, env->fpuc);
        cpu_stl_data(env, ptr + 4, fpus);
        cpu_stl_data(env, ptr + 8, fptag);
        cpu_stl_data(env, ptr + 12, 0); /* fpip */
        cpu_stl_data(env, ptr + 16, 0); /* fpcs */
        cpu_stl_data(env, ptr + 20, 0); /* fpoo */
        cpu_stl_data(env, ptr + 24, 0); /* fpos */
    } else {
        /* 16 bit */
        cpu_stw_data(env, ptr, env->fpuc);
        cpu_stw_data(env, ptr + 2, fpus);
        cpu_stw_data(env, ptr + 4, fptag);
        cpu_stw_data(env, ptr + 6, 0);
        cpu_stw_data(env, ptr + 8, 0);
        cpu_stw_data(env, ptr + 10, 0);
        cpu_stw_data(env, ptr + 12, 0);
    }
}

void helper_fldenv(CPUX86State *env, target_ulong ptr, int data32)
{
    int i, fpus, fptag;

    if (data32) {
        cpu_set_fpuc(env, cpu_lduw_data(env, ptr));
        fpus = cpu_lduw_data(env, ptr + 4);
        fptag = cpu_lduw_data(env, ptr + 8);
    } else {
        cpu_set_fpuc(env, cpu_lduw_data(env, ptr));
        fpus = cpu_lduw_data(env, ptr + 2);
        fptag = cpu_lduw_data(env, ptr + 4);
    }
    env->fpstt = (fpus >> 11) & 7;
    env->fpus = fpus & ~0x3800;
    for (i = 0; i < 8; i++) {
        env->fptags[i] = ((fptag & 3) == 3);
        fptag >>= 2;
    }
}

void helper_fsave(CPUX86State *env, target_ulong ptr, int data32)
{
    floatx80 tmp;
    int i;

    helper_fstenv(env, ptr, data32);

    ptr += (14 << data32);
    for (i = 0; i < 8; i++) {
        tmp = ST(i);
        helper_fstt(env, tmp, ptr);
        ptr += 10;
    }

    /* fninit */
    env->fpus = 0;
    env->fpstt = 0;
    cpu_set_fpuc(env, 0x37f);
    env->fptags[0] = 1;
    env->fptags[1] = 1;
    env->fptags[2] = 1;
    env->fptags[3] = 1;
    env->fptags[4] = 1;
    env->fptags[5] = 1;
    env->fptags[6] = 1;
    env->fptags[7] = 1;
}

void helper_frstor(CPUX86State *env, target_ulong ptr, int data32)
{
    floatx80 tmp;
    int i;

    helper_fldenv(env, ptr, data32);
    ptr += (14 << data32);

    for (i = 0; i < 8; i++) {
        tmp = helper_fldt(env, ptr);
        ST(i) = tmp;
        ptr += 10;
    }
}

#if defined(CONFIG_USER_ONLY)
void cpu_x86_fsave(CPUX86State *env, target_ulong ptr, int data32)
{
    helper_fsave(env, ptr, data32);
}

void cpu_x86_frstor(CPUX86State *env, target_ulong ptr, int data32)
{
    helper_frstor(env, ptr, data32);
}
#endif

void helper_fxsave(CPUX86State *env, target_ulong ptr, int data64)
{
    int fpus, fptag, i, nb_xmm_regs;
    floatx80 tmp;
    target_ulong addr;

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception(env, EXCP0D_GPF);
    }

    fpus = (env->fpus & ~0x3800) | (env->fpstt & 0x7) << 11;
    fptag = 0;
    for (i = 0; i < 8; i++) {
        fptag |= (env->fptags[i] << i);
    }
    cpu_stw_data(env, ptr, env->fpuc);
    cpu_stw_data(env, ptr + 2, fpus);
    cpu_stw_data(env, ptr + 4, fptag ^ 0xff);
#ifdef TARGET_X86_64
    if (data64) {
        cpu_stq_data(env, ptr + 0x08, 0); /* rip */
        cpu_stq_data(env, ptr + 0x10, 0); /* rdp */
    } else
#endif
    {
        cpu_stl_data(env, ptr + 0x08, 0); /* eip */
        cpu_stl_data(env, ptr + 0x0c, 0); /* sel  */
        cpu_stl_data(env, ptr + 0x10, 0); /* dp */
        cpu_stl_data(env, ptr + 0x14, 0); /* sel  */
    }

    addr = ptr + 0x20;
    for (i = 0; i < 8; i++) {
        tmp = ST(i);
        helper_fstt(env, tmp, addr);
        addr += 16;
    }

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        /* XXX: finish it */
        cpu_stl_data(env, ptr + 0x18, env->mxcsr); /* mxcsr */
        cpu_stl_data(env, ptr + 0x1c, 0x0000ffff); /* mxcsr_mask */
        if (env->hflags & HF_CS64_MASK) {
            nb_xmm_regs = 16;
        } else {
            nb_xmm_regs = 8;
        }
        addr = ptr + 0xa0;
        /* Fast FXSAVE leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR)
            || (env->hflags & HF_CPL_MASK)
            || !(env->hflags & HF_LMA_MASK)) {
            for (i = 0; i < nb_xmm_regs; i++) {
                cpu_stq_data(env, addr, env->xmm_regs[i].XMM_Q(0));
                cpu_stq_data(env, addr + 8, env->xmm_regs[i].XMM_Q(1));
                addr += 16;
            }
        }
    }
}

void helper_fxrstor(CPUX86State *env, target_ulong ptr, int data64)
{
    int i, fpus, fptag, nb_xmm_regs;
    floatx80 tmp;
    target_ulong addr;

    /* The operand must be 16 byte aligned */
    if (ptr & 0xf) {
        raise_exception(env, EXCP0D_GPF);
    }

    cpu_set_fpuc(env, cpu_lduw_data(env, ptr));
    fpus = cpu_lduw_data(env, ptr + 2);
    fptag = cpu_lduw_data(env, ptr + 4);
    env->fpstt = (fpus >> 11) & 7;
    env->fpus = fpus & ~0x3800;
    fptag ^= 0xff;
    for (i = 0; i < 8; i++) {
        env->fptags[i] = ((fptag >> i) & 1);
    }

    addr = ptr + 0x20;
    for (i = 0; i < 8; i++) {
        tmp = helper_fldt(env, addr);
        ST(i) = tmp;
        addr += 16;
    }

    if (env->cr[4] & CR4_OSFXSR_MASK) {
        /* XXX: finish it */
        cpu_set_mxcsr(env, cpu_ldl_data(env, ptr + 0x18));
        /* cpu_ldl_data(env, ptr + 0x1c); */
        if (env->hflags & HF_CS64_MASK) {
            nb_xmm_regs = 16;
        } else {
            nb_xmm_regs = 8;
        }
        addr = ptr + 0xa0;
        /* Fast FXRESTORE leaves out the XMM registers */
        if (!(env->efer & MSR_EFER_FFXSR)
            || (env->hflags & HF_CPL_MASK)
            || !(env->hflags & HF_LMA_MASK)) {
            for (i = 0; i < nb_xmm_regs; i++) {
                env->xmm_regs[i].XMM_Q(0) = cpu_ldq_data(env, addr);
                env->xmm_regs[i].XMM_Q(1) = cpu_ldq_data(env, addr + 8);
                addr += 16;
            }
        }
    }
}

void cpu_get_fp80(uint64_t *pmant, uint16_t *pexp, floatx80 f)
{
    CPU_LDoubleU temp;

    temp.d = f;
    *pmant = temp.l.lower;
    *pexp = temp.l.upper;
}

floatx80 cpu_set_fp80(uint64_t mant, uint16_t upper)
{
    CPU_LDoubleU temp;

    temp.l.upper = upper;
    temp.l.lower = mant;
    return temp.d;
}

/* MMX/SSE */
/* XXX: optimize by storing fptt and fptags in the static cpu state */

#define SSE_DAZ             0x0040
#define SSE_RC_MASK         0x6000
#define SSE_RC_NEAR         0x0000
#define SSE_RC_DOWN         0x2000
#define SSE_RC_UP           0x4000
#define SSE_RC_CHOP         0x6000
#define SSE_FZ              0x8000

void cpu_set_mxcsr(CPUX86State *env, uint32_t mxcsr)
{
    int rnd_type;

    env->mxcsr = mxcsr;

    /* set rounding mode */
    switch (mxcsr & SSE_RC_MASK) {
    default:
    case SSE_RC_NEAR:
        rnd_type = float_round_nearest_even;
        break;
    case SSE_RC_DOWN:
        rnd_type = float_round_down;
        break;
    case SSE_RC_UP:
        rnd_type = float_round_up;
        break;
    case SSE_RC_CHOP:
        rnd_type = float_round_to_zero;
        break;
    }
    set_float_rounding_mode(rnd_type, &env->sse_status);

    /* set denormals are zero */
    set_flush_inputs_to_zero((mxcsr & SSE_DAZ) ? 1 : 0, &env->sse_status);

    /* set flush to zero */
    set_flush_to_zero((mxcsr & SSE_FZ) ? 1 : 0, &env->fp_status);
}

void cpu_set_fpuc(CPUX86State *env, uint16_t val)
{
    env->fpuc = val;
    update_fp_status(env);
}

void helper_ldmxcsr(CPUX86State *env, uint32_t val)
{
    cpu_set_mxcsr(env, val);
}

void helper_enter_mmx(CPUX86State *env)
{
    env->fpstt = 0;
    *(uint32_t *)(env->fptags) = 0;
    *(uint32_t *)(env->fptags + 4) = 0;
}

void helper_emms(CPUX86State *env)
{
    /* set to empty state */
    *(uint32_t *)(env->fptags) = 0x01010101;
    *(uint32_t *)(env->fptags + 4) = 0x01010101;
}

/* XXX: suppress */
void helper_movq(CPUX86State *env, void *d, void *s)
{
    *(uint64_t *)d = *(uint64_t *)s;
}

#define SHIFT 0
#include "ops_sse.h"

#define SHIFT 1
#include "ops_sse.h"
