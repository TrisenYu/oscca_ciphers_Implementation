#include <cstdio>
#include <cstring>
#include <cinttypes>
#include <algorithm>

//< ===================================================== 常量声明区域 ===================================================== >

const uint8_t S0[16][16] = {0x3e, 0x72, 0x5b, 0x47, 0xca, 0xe0, 0x00, 0x33, 0x04, 0xd1, 0x54, 0x98, 0x09, 0xb9, 0x6d, 0xcb,
                            0x7b, 0x1b, 0xf9, 0x32, 0xaf, 0x9d, 0x6a, 0xa5, 0xb8, 0x2d, 0xfc, 0x1d, 0x08, 0x53, 0x03, 0x90,
                            0x4d, 0x4e, 0x84, 0x99, 0xe4, 0xce, 0xd9, 0x91, 0xdd, 0xb6, 0x85, 0x48, 0x8b, 0x29, 0x6e, 0xac,
                            0xcd, 0xc1, 0xf8, 0x1e, 0x73, 0x43, 0x69, 0xc6, 0xb5, 0xbd, 0xfd, 0x39, 0x63, 0x20, 0xd4, 0x38,
                            0x76, 0x7d, 0xb2, 0xa7, 0xcf, 0xed, 0x57, 0xc5, 0xf3, 0x2c, 0xbb, 0x14, 0x21, 0x06, 0x55, 0x9b,
                            0xe3, 0xef, 0x5e, 0x31, 0x4f, 0x7f, 0x5a, 0xa4, 0x0d, 0x82, 0x51, 0x49, 0x5f, 0xba, 0x58, 0x1c,
                            0x4a, 0x16, 0xd5, 0x17, 0xa8, 0x92, 0x24, 0x1f, 0x8c, 0xff, 0xd8, 0xae, 0x2e, 0x01, 0xd3, 0xad,
                            0x3b, 0x4b, 0xda, 0x46, 0xeb, 0xc9, 0xde, 0x9a, 0x8f, 0x87, 0xd7, 0x3a, 0x80, 0x6f, 0x2f, 0xc8,
                            0xb1, 0xb4, 0x37, 0xf7, 0x0a, 0x22, 0x13, 0x28, 0x7c, 0xcc, 0x3c, 0x89, 0xc7, 0xc3, 0x96, 0x56,
                            0x07, 0xbf, 0x7e, 0xf0, 0x0b, 0x2b, 0x97, 0x52, 0x35, 0x41, 0x79, 0x61, 0xa6, 0x4c, 0x10, 0xfe,
                            0xbc, 0x26, 0x95, 0x88, 0x8a, 0xb0, 0xa3, 0xfb, 0xc0, 0x18, 0x94, 0xf2, 0xe1, 0xe5, 0xe9, 0x5d,
                            0xd0, 0xdc, 0x11, 0x66, 0x64, 0x5c, 0xec, 0x59, 0x42, 0x75, 0x12, 0xf5, 0x74, 0x9c, 0xaa, 0x23,
                            0x0e, 0x86, 0xab, 0xbe, 0x2a, 0x02, 0xe7, 0x67, 0xe6, 0x44, 0xa2, 0x6c, 0xc2, 0x93, 0x9f, 0xf1,
                            0xf6, 0xfa, 0x36, 0xd2, 0x50, 0x68, 0x9e, 0x62, 0x71, 0x15, 0x3d, 0xd6, 0x40, 0xc4, 0xe2, 0x0f,
                            0x8e, 0x83, 0x77, 0x6b, 0x25, 0x05, 0x3f, 0x0c, 0x30, 0xea, 0x70, 0xb7, 0xa1, 0xe8, 0xa9, 0x65,
                            0x8d, 0x27, 0x1a, 0xdb, 0x81, 0xb3, 0xa0, 0xf4, 0x45, 0x7a, 0x19, 0xdf, 0xee, 0x78, 0x34, 0x60},

              S1[16][16] = {0x55, 0xc2, 0x63, 0x71, 0x3b, 0xc8, 0x47, 0x86, 0x9f, 0x3c, 0xda, 0x5b, 0x29, 0xaa, 0xfd, 0x77,
                            0x8c, 0xc5, 0x94, 0x0c, 0xa6, 0x1a, 0x13, 0x00, 0xe3, 0xa8, 0x16, 0x72, 0x40, 0xf9, 0xf8, 0x42,
                            0x44, 0x26, 0x68, 0x96, 0x81, 0xd9, 0x45, 0x3e, 0x10, 0x76, 0xc6, 0xa7, 0x8b, 0x39, 0x43, 0xe1,
                            0x3a, 0xb5, 0x56, 0x2a, 0xc0, 0x6d, 0xb3, 0x05, 0x22, 0x66, 0xbf, 0xdc, 0x0b, 0xfa, 0x62, 0x48,
                            0xdd, 0x20, 0x11, 0x06, 0x36, 0xc9, 0xc1, 0xcf, 0xf6, 0x27, 0x52, 0xbb, 0x69, 0xf5, 0xd4, 0x87,
                            0x7f, 0x84, 0x4c, 0xd2, 0x9c, 0x57, 0xa4, 0xbc, 0x4f, 0x9a, 0xdf, 0xfe, 0xd6, 0x8d, 0x7a, 0xeb,
                            0x2b, 0x53, 0xd8, 0x5c, 0xa1, 0x14, 0x17, 0xfb, 0x23, 0xd5, 0x7d, 0x30, 0x67, 0x73, 0x08, 0x09,
                            0xee, 0xb7, 0x70, 0x3f, 0x61, 0xb2, 0x19, 0x8e, 0x4e, 0xe5, 0x4b, 0x93, 0x8f, 0x5d, 0xdb, 0xa9,
                            0xad, 0xf1, 0xae, 0x2e, 0xcb, 0x0d, 0xfc, 0xf4, 0x2d, 0x46, 0x6e, 0x1d, 0x97, 0xe8, 0xd1, 0xe9,
                            0x4d, 0x37, 0xa5, 0x75, 0x5e, 0x83, 0x9e, 0xab, 0x82, 0x9d, 0xb9, 0x1c, 0xe0, 0xcd, 0x49, 0x89,
                            0x01, 0xb6, 0xbd, 0x58, 0x24, 0xa2, 0x5f, 0x38, 0x78, 0x99, 0x15, 0x90, 0x50, 0xb8, 0x95, 0xe4,
                            0xd0, 0x91, 0xc7, 0xce, 0xed, 0x0f, 0xb4, 0x6f, 0xa0, 0xcc, 0xf0, 0x02, 0x4a, 0x79, 0xc3, 0xde,
                            0xa3, 0xef, 0xea, 0x51, 0xe6, 0x6b, 0x18, 0xec, 0x1b, 0x2c, 0x80, 0xf7, 0x74, 0xe7, 0xff, 0x21,
                            0x5a, 0x6a, 0x54, 0x1e, 0x41, 0x31, 0x92, 0x35, 0xc4, 0x33, 0x07, 0x0a, 0xba, 0x7e, 0x0e, 0x34,
                            0x88, 0xb1, 0x98, 0x7c, 0xf3, 0x3d, 0x60, 0x6c, 0x7b, 0xca, 0xd3, 0x1f, 0x32, 0x65, 0x04, 0x28,
                            0x64, 0xbe, 0x85, 0x9b, 0x2f, 0x59, 0x8a, 0xd7, 0xb0, 0x25, 0xac, 0xaf, 0x12, 0x03, 0xe2, 0xf2};

const uint16_t d_const[16] = {0x44D7, 0x26BC, 0x626B, 0x135E, 0x5789, 0x35E2, 0x7135, 0x09AF,
                              0x4D78, 0x2F13, 0x6BC4, 0x1AF1, 0x5E26, 0x3C4D, 0x789A, 0x47AC};
const uint32_t mod31 = ~(1 << 31);
const uint64_t mod32 = 1ull << 32;

//< ===================================================== 常量声明区域结束 ===================================================== >//

//< ===================================================== 过程变量声明区域 ===================================================== >//

/** 记得更换密钥。
 * MYKEY:
 *  CASE_1: {0};
 *  CASE_2: {0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF,  0xFF, 0xFF, 0xFF, 0xFF};
 *  CASE_3: {0x3d, 0x4c, 0x4b, 0xe9, 0x6a, 0x82, 0xfd, 0xae, 0xb5, 0x8f, 0x64, 0x1d, 0xb1, 0x7b, 0x45, 0x5b};
 *  CASE_4: {0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29},
 **/
uint8_t MyKey[16] = {0x17, 0x3d, 0x14, 0xba, 0x50, 0x03, 0x73, 0x1d, 0x7a, 0x60, 0x04, 0x94, 0x70, 0xf0, 0x0a, 0x29},
        InitVec[16];

/**
 * MSG:
 * 0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0xbd675d9, 0x005875b2,
 */
uint32_t msg[] = {0x6cf65340, 0x735552ab, 0x0c9752fa, 0x6f9025fe, 0xbd675d9, 0x005875b2};
uint32_t parameter[4], *encrypt, *Z;
uint32_t /* 只用到 (30, 29, ... , 0)，而非 (31, 30, 29, ..., 0) */ Reg[16];

//< ================================================== 过程变量声明区域结束 ================================================== >//

//< ================================================== 辅助函数声明区域 ===================================================== >//

inline uint16_t __H_16bits(uint32_t val) { return (val >> 16) & 0xFFFF; }
inline uint16_t __L_16bits(uint32_t val) { return val & 0xFFFF; }
inline uint16_t __H_2bytes_31(uint32_t val) { return (uint16_t)((val & 0x7FFF8000) >> 15); }
inline uint16_t __L_2bytes_31(uint32_t val) { return val & (uint16_t)0xFFFF; }
inline uint32_t __cyclic_Lshift(uint32_t val, uint32_t _) { return (val >> (32 - _)) | (val << _); }
inline uint32_t __safely_take_31bits(uint32_t val) { return 0x7FFFFFFFu & val; }

/**
 * 2^31 - 1 为模数的域。
 * 取出 31 位寄存器中的高 16 位(30 位到 15 位)，也即 2 个字节。
 * 相与的数是 0x7FFF8000，
 * @param val: 31 位寄存器中的值。
 * @note 0x7FFF8000: 0111 1111 1111 1111 1000 0000 0000 0000
 **/
inline uint32_t PlusMod31(uint64_t a, uint64_t b)
{
    uint64_t c = a + b;
    return (c & 0x7FFFFFFFu) + (c >> 31);
}

/** O(1) 统计二进制数有多少个 1。分治基底：
 * 0x55555555: 0101 0101 0101 0101 0101 0101 0101 0101
 * 0x33333333: 0011 0011 0011 0011 0011 0011 0011 0011
 * 0x0f0f0f0f: 0000 1111 0000 1111 0000 1111 0000 1111
 * 0x0000ffff  0000 0000 0000 0000 1111 1111 1111 1111
 * 然后根据逻辑优化就得。

inline uint32_t bits_counter(uint32_t val)
{

    val = val - ((val >> 1) & 0x55555555);
    val = (val & 0x33333333) + ((val >> 2) & 0x33333333);
    val = (val + (val >> 4)) & 0x0f0f0f0f;
    val = val + (val >> 8);
    val = val + (val >> 16);
    return val & 0x3f;
}
*/

/**
 * 模 2^32 加。
 * @param a: 32 位参数，但以 64 位表示从而确保运算正确。
 * @param b: 与 a 同理。
 */
inline uint32_t PlusMod32(uint64_t a, uint64_t b)
{
    // 模数上的差异引起传入参数的变化。
    uint64_t res = (a + b) % mod32;
    return res & 0xFFFFFFFFu; // 此处必须要截断。
}
uint32_t MulMod31(uint32_t a, uint32_t b)
{
    uint32_t res = 0;
    if (a < b)
        std::swap(a, b);
    while (b)
    {
        if (b & 1)
            res = PlusMod31(res, a);
        b >>= 1;
        a = PlusMod31(a, a);
    }
    return res;
}

//< ================================================== 辅助函数声明区域结束 ================================================== >

/**
 * 初始化 或者使 LSFR 处于工作模式。为适配两参数与两模式下的切换，故先定义 mode。
 * @param mode: 表示传入的模式。为 0 表示初始化 LSFR，否则表示工作模式使能。
 * @param u: 表示传入的 **31** 位输入。
 */
inline void
opInLSFR(uint8_t mode = 0, uint32_t u = 0)
{
    uint32_t LLv = MulMod31((1u << 15), __safely_take_31bits(Reg[15])),
             RLv = MulMod31((1u << 17), __safely_take_31bits(Reg[13])),
             LRv = MulMod31((1u << 21), __safely_take_31bits(Reg[10])),
             RRv = MulMod31((1u << 20), __safely_take_31bits(Reg[4])),

             Lv = PlusMod31(LLv, RLv), Rv = PlusMod31(LRv, RRv),
             v = MulMod31((1u << 8 | 1u), __safely_take_31bits(Reg[0]));

    v = PlusMod31(v, PlusMod31(Lv, Rv));

    for (uint16_t i = 1; i < 16; i++)
        Reg[i - 1] = Reg[i];
    uint32_t tmp;

    tmp = !mode ? PlusMod31(v, __safely_take_31bits(u)) : v;

    if (!tmp)
        tmp = mod31;
    Reg[15] = tmp;
}

inline void
BitsReconstruction(uint32_t *x)
{
    x[0] = ((uint32_t)__H_2bytes_31(Reg[15]) << 16) | (__L_2bytes_31(Reg[14]));
    x[1] = ((uint32_t)__L_2bytes_31(Reg[11]) << 16) | (__H_2bytes_31(Reg[9]));
    x[2] = ((uint32_t)__L_2bytes_31(Reg[7]) << 16) | (__H_2bytes_31(Reg[5]));
    x[3] = ((uint32_t)__L_2bytes_31(Reg[2]) << 16) | (__H_2bytes_31(Reg[0]));
}

// 标准中定义为 L1 的 S 盒变换。
inline uint32_t
Linear_Transform1(uint32_t val)
{
    return val ^ __cyclic_Lshift(val, 2) ^ __cyclic_Lshift(val, 10) ^
           __cyclic_Lshift(val, 18) ^ __cyclic_Lshift(val, 24);
}
// 标准中定义为 L2 的 S 盒变换。
inline uint32_t
Linear_Transform2(uint32_t val)
{
    return val ^ __cyclic_Lshift(val, 8) ^ __cyclic_Lshift(val, 14) ^
           __cyclic_Lshift(val, 22) ^ __cyclic_Lshift(val, 30);
}

inline uint32_t
NonLinearF(uint32_t *x)
{
    static uint32_t R1, R2;
    uint32_t res = PlusMod32((x[0] ^ R1), R2),
             Wtmp1 = PlusMod32(R1, x[1]),
             Wtmp2 = x[2] ^ R2,
             pre_r1_idx = ((uint32_t)(__L_16bits(Wtmp1)) << 16) | (__H_16bits(Wtmp2)),
             pre_r2_idx = ((uint32_t)(__L_16bits(Wtmp2)) << 16) | (__H_16bits(Wtmp1)),
             R1_idx = Linear_Transform1(pre_r1_idx),
             R2_idx = Linear_Transform2(pre_r2_idx);

    // 接下来将拆分下标为 4 个字节，并直接在循环中变换。
    uint8_t IB1[4], IB2[4];
    for (uint8_t i = 0; i < 4; i++)
        IB1[i] = (uint8_t)((R1_idx >> (i << 3)) & 0xFF), IB2[i] = (uint8_t)((R2_idx >> (i << 3)) & 0xFF),
        IB1[i] = (i & 1 ? S0[__H_16bits(IB1[i])][__L_16bits(IB1[i])] : S1[__H_16bits(IB1[i])][__L_16bits(IB1[i])]),
        IB2[i] = (i & 1 ? S0[__H_16bits(IB2[i])][__L_16bits(IB2[i])] : S1[__H_16bits(IB2[i])][__L_16bits(IB2[i])]);

    R1 = 0, R2 = 0;
    for (uint8_t i = 0; i < 4; i++)
    {
        R1 |= (((uint32_t)IB1[i]) << (i << 3));
        R2 |= (((uint32_t)IB2[i]) << (i << 3));
        IB1[i] = IB2[i] = 0;
    }
    return res;
}

/**
 * 密钥载入函数。
 * 初始密钥和初始向量为 16 个 unsigned char。
 * 相当于自定义密码。
 **/
inline void LoadRegister()
{
    for (uint8_t i = 0; i < 16; i++)
        Reg[i] = ((((uint32_t)MyKey[i]) << 23) | (((uint32_t)d_const[i]) << 8) | (InitVec[i])) & 0x7FFFFFFF;
    //<                   逻辑上有 8 位                     逻辑上只有 15               这里有 8 位          >//
}

void ZUCinit()
{
    LoadRegister();
    for (uint16_t i = 0; i < 32; i++)
    {
        BitsReconstruction(parameter);
        uint32_t res = NonLinearF(parameter);
        // 此处获得初始的值。
        opInLSFR(0, res >> 1);
    }
}

/**
 * 初始化过程中使用 parameter 数组来承接比特重组后的数值。
 * @param Len: 工作模式下才使用的、表示待加密明文的以比特位显示时的长度。
 * @param arr: 加密或解密时传入的明文或密文数组。
 * @param ans: 承接结果数组。
 */
void ZUCWorkMode(uint32_t Len, uint32_t *arr, uint32_t *store, uint32_t *ans)
{
    BitsReconstruction(parameter);
    NonLinearF(parameter);
    opInLSFR(1);
    for (uint64_t i = 0; i < Len; i++)
    {
        BitsReconstruction(parameter);
        store[i] = NonLinearF(parameter) ^ parameter[3];
        ans[i] = store[i] ^ arr[i];
        printf("0x%X ", ans[i]); // 按要求输出计算得到的密钥。
        opInLSFR(1);
    }
}

/** 保密性算法初始化。
 * @param counter: 32 位计数器。
 * @param bearer: 5 位标识。
 * @param direction: 1 位方向。
 */
void initConfidentialityIV(uint32_t counter, uint8_t bearer, uint8_t direction)
{
    InitVec[0] = (counter >> 24) & 0xFF, InitVec[1] = (counter >> 16) & 0xFF,
    InitVec[2] = (counter >> 8) & 0xFF, InitVec[3] = counter & 0xFF;

    InitVec[4] = ((bearer & 0x1F) << 3) | ((direction & 0x1) << 2) | 0x0;
    InitVec[5] = InitVec[6] = InitVec[7] = 0;

    for (int i = 8; i < 16; i++)
        InitVec[i] = InitVec[i - 8];
}

/** 完整性算法初始化。
 * @param counter: 32 位计数器。
 * @param bearer: 5 位标识。
 * @param direction: 1 位方向。
 */
/*
void initIntegrityIV(uint32_t counter, uint8_t bearer, uint8_t direction)
{
    InitVec[0] = (counter >> 24) & 0xFF, InitVec[1] = (counter >> 16) & 0xFF,
    InitVec[2] = (counter >> 8) & 0xFF, InitVec[3] = counter & 0xFF;

    InitVec[4] = ((bearer & 0x1F) << 3) | 0x0;
    InitVec[5] = InitVec[6] = InitVec[7] = 0;

    for (int i = 8; i < 16; i++)
        InitVec[i] = InitVec[i - 8];
    InitVec[8] ^= direction << 7,
        InitVec[14] ^= direction << 7;
}
// 标准文档表述极其不利于变现。
// 以下函数具有相当明显的问题。
uint32_t calcMAC(uint32_t len, uint32_t *msg, uint32_t *encrypt)
{
    uint32_t res = 0;
    for (int i = 0; i < len; i++)
    {
        if (bits_counter(msg[i]) & 1)
            res ^= encrypt[i];
    }
    return res;
}
*/

int main()
{
    // 测试保密性实现。
    initConfidentialityIV(0x66035492, 0xf, 0);

    encrypt = (uint32_t *)calloc(0xc1 / 32 + 1, sizeof(uint32_t));
    Z = (uint32_t *)calloc(0xc1 / 32 + 1, sizeof(uint32_t));

    ZUCinit();
    ZUCWorkMode(0xc1 / 32 + 1, msg, Z, encrypt);
    puts("\n------ END OF Confidentiality -----");

    free(Z);
    free(encrypt);
    return 0;
}