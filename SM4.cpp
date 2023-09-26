
/** SM4 算法
 * @brief：编程实现 SM4 算法。显示加密 学号 + 姓名 的结果
 * @cite：中国国家标准化管理委员会.信息安全技术 SM4分组密码算法
 * @htmlinclude: http://c.gb688.cn/bzgk/gb/showGb?type=online&hcno=7803DE42D3BC5E80B0C3E5D8E873D56A,2016-08-29.
 * @date: 作成并通过测试于 2023 年 9 月 24 日 14 时 47 分。
 **/
#include <cstdio>
#include <cstdint>
#include <algorithm>
#include <locale.h>

const uint32_t /* S 盒 */
    SBox[][16] = {
        {0xd6, 0x90, 0xe9, 0xfe, 0xcc, 0xe1, 0x3d, 0xb7, 0x16, 0xb6, 0x14, 0xc2, 0x28, 0xfb, 0x2c, 0x05},
        {0x2b, 0x67, 0x9a, 0x76, 0x2a, 0xbe, 0x04, 0xc3, 0xaa, 0x44, 0x13, 0x26, 0x49, 0x86, 0x06, 0x99},
        {0x9c, 0x42, 0x50, 0xf4, 0x91, 0xef, 0x98, 0x7a, 0x33, 0x54, 0x0b, 0x43, 0xed, 0xcf, 0xac, 0x62},
        {0xe4, 0xb3, 0x1c, 0xa9, 0xc9, 0x08, 0xe8, 0x95, 0x80, 0xdf, 0x94, 0xfa, 0x75, 0x8f, 0x3f, 0xa6},
        {0x47, 0x07, 0xa7, 0xfc, 0xf3, 0x73, 0x17, 0xba, 0x83, 0x59, 0x3c, 0x19, 0xe6, 0x85, 0x4f, 0xa8},
        {0x68, 0x6b, 0x81, 0xb2, 0x71, 0x64, 0xda, 0x8b, 0xf8, 0xeb, 0x0f, 0x4b, 0x70, 0x56, 0x9d, 0x35},
        {0x1e, 0x24, 0x0e, 0x5e, 0x63, 0x58, 0xd1, 0xa2, 0x25, 0x22, 0x7c, 0x3b, 0x01, 0x21, 0x78, 0x87},
        {0xd4, 0x00, 0x46, 0x57, 0x9f, 0xd3, 0x27, 0x52, 0x4c, 0x36, 0x02, 0xe7, 0xa0, 0xc4, 0xc8, 0x9e},
        {0xea, 0xbf, 0x8a, 0xd2, 0x40, 0xc7, 0x38, 0xb5, 0xa3, 0xf7, 0xf2, 0xce, 0xf9, 0x61, 0x15, 0xa1},
        {0xe0, 0xae, 0x5d, 0xa4, 0x9b, 0x34, 0x1a, 0x55, 0xad, 0x93, 0x32, 0x30, 0xf5, 0x8c, 0xb1, 0xe3},
        {0x1d, 0xf6, 0xe2, 0x2e, 0x82, 0x66, 0xca, 0x60, 0xc0, 0x29, 0x23, 0xab, 0x0d, 0x53, 0x4e, 0x6f},
        {0xd5, 0xdb, 0x37, 0x45, 0xde, 0xfd, 0x8e, 0x2f, 0x03, 0xff, 0x6a, 0x72, 0x6d, 0x6c, 0x5b, 0x51},
        {0x8d, 0x1b, 0xaf, 0x92, 0xbb, 0xdd, 0xbc, 0x7f, 0x11, 0xd9, 0x5c, 0x41, 0x1f, 0x10, 0x5a, 0xd8},
        {0x0a, 0xc1, 0x31, 0x88, 0xa5, 0xcd, 0x7b, 0xbd, 0x2d, 0x74, 0xd0, 0x12, 0xb8, 0xe5, 0xb4, 0xb0},
        {0x89, 0x69, 0x97, 0x4a, 0x0c, 0x96, 0x77, 0x7e, 0x65, 0xb9, 0xf1, 0x09, 0xc5, 0x6e, 0xc6, 0x84},
        {0x18, 0xf0, 0x7d, 0xec, 0x3a, 0xdc, 0x4d, 0x20, 0x79, 0xee, 0x5f, 0x3e, 0xd7, 0xcb, 0x39, 0x48}},
    /**
     * @test: 1.十六进制数输入以验证时，某些情况只需要按顺序录入
     *          0x0123456789abcdeffedcba9876543210 =>
     *          0x01234567, 0x89abcdef, 0xfedcba98, 0x76543210
     **/
    myKey[4] = {0xDEADBEEFu, 0xBEAF71CAu, 0x100100B1u, 0x7F869A4Cu}, // 自定义密钥
    FK[] = {0xA3B1BAC6, 0x56AA3350, 0x677D9197, 0xB27022DC};         // 固定参数

uint32_t
    plaintext[64] = {0x12345678u, 0x12345678u, 0x12345678u, 0x12345678u,
                     0x12345678u, 0x00000000u, 0x00000000u, 0x00000000u}, /* {0x01234567u, 0x89abcdefu, 0xfedcba98u, 0x76543210u, 0, 0, 0, 0} */
    res[64] = {0},                                                        // 密文存储数组
    test[64] = {0},                                                       // 解密测试存储数组
    CK[32] = {0},                                                         // 系统参数 和 固定参数
    rkey[32] = {0},                                                       // 轮密钥由密钥算出。
    X[4];                                                                 // 轮转参数存储数组

inline uint8_t __L_4_bits(uint8_t val) { return val & 0x0F; }
inline uint8_t __H_4_bits(uint8_t val) { return (val & 0xF0) >> 4; }
/* 要求循环左移 */
inline uint32_t cyclic_LShift(uint32_t val, uint32_t _) { return ((val >> (32u - _)) | (val << _)); }
inline void initCK()
{
    for (uint32_t i = 0; i < 32u; i++)
        for (uint8_t j = 0; j < 4u; ++j)
            CK[i] |= ((4u * i + j) * 7u % 0x100u) << ((3u - j) << 3u);
}
/* 传入操作数组及其长度。*/
inline void SM4swap(uint32_t *x, uint32_t len)
{
    for (uint32_t i = 0, j = len - 1; i <= j; i++, j--)
        std::swap(x[i], x[j]);
}

/* 线性变换 */
inline void Transform_linear(uint32_t &val, int mode)
{
    val = mode ? val ^ cyclic_LShift(val, 2) ^ cyclic_LShift(val, 10) ^ cyclic_LShift(val, 18) ^ cyclic_LShift(val, 24) : val ^ cyclic_LShift(val, 13) ^ cyclic_LShift(val, 23);
}
inline void Transform_non_linear(uint32_t &val)
{
    uint8_t aa[4];
    for (int i = 3; ~i; i--)
        aa[i] = (val >> (i << 3)) & 0xFF;

    val = 0;
    for (int i = 3; ~i; i--)
        val |= SBox[__H_4_bits(aa[i])][__L_4_bits(aa[i])] << (i << 3);
}

/**
 * T（val） 包含非线性变换和线性变换两个过程。
 * 对输入的 1 个 int 分拆为 4 个字节 a3 a2 a1 a0
 * 施行 S 盒变换。每个字节的高位作为横坐标，列位作为纵坐标以得到最终结果。最后再根据对应模式按位异或。
 * @param val: 指代传入的 32 位数。
 * @param mode：为 1 则加密，为 0 则计算 rk。
 **/
void T_function(uint32_t &val, bool mode)
{
    // 接收单个 int 得到一个 int。
    Transform_non_linear(val);
    Transform_linear(val, mode);
}
/**
 *  接收 4 个 int 和作为轮密钥 rk 的 1 个 int，形成 F 的参数。其中 F = x0 ^ T(x1^x2^x3^rk) 或者 x0 ^ T'(x1^x2^x3^ck)。
 *  模式视情况而定。
 *  因运算对合，加解密以及计算 rk 均可使用此中间函数。
 *  @param x: 指存储数组。
 *  @param plaintext: 明文或密文。因计算 rk 时，可能不需要这一参数。
 *  @param mode: 计算模式。为 0 计算 rk，为 1 加密或解密。
 **/
void MiddelSM4(uint32_t *x, uint32_t *plaintext = nullptr, int mode = 0)
{
    for (int i = 0; i < 4; i++)
        x[i] = mode ? plaintext[i] : FK[i] ^ myKey[i];

    for (int times = 0; times < 32; ++times)
    {
        uint32_t X_new = mode ? rkey[times] : CK[times];
        for (int i = 1; i < 4; ++i)
            X_new ^= x[i];

        T_function(X_new, mode);

        X_new ^= x[0];
        for (int i = 1; i < 4; i++)
            x[i - 1] = x[i];

        x[3] = X_new;
        if (!mode)
            rkey[times] = x[3];
    }
}

void SM4(int offset, uint32_t *__msg, uint32_t *temp, uint32_t *__res)
{
    MiddelSM4(temp, __msg + offset, 1);
    SM4swap(temp, 4);
    for (int i = offset; i < offset + 4; i++)
        __res[i] = temp[i - offset];
}
void EncryptSM4(int offset) { SM4(offset, plaintext, X, res); }
bool flag = true;
void DecryptSM4(int offset)
{
    if (flag) // 只做一次。
        flag = false, SM4swap(rkey, 32);
    SM4(offset, res, X, test);
}

int main()
{
    // 假定是小端序。
    // 简便起见，此处不打算实现解析函数。
    setlocale(LC_ALL, "chs");

    initCK();
    MiddelSM4(X);

    for (int step = 0; step < 5; step += 4)
        EncryptSM4(step);

    for (int step = 0; step < 5; step += 4)
        DecryptSM4(step);

    // 输出检验。
    wprintf(L"密文：");
    for (int i = 0; i <= 16; i++)
        printf("0x%X ", res[i]);
    puts("");

    wprintf(L"明文（小端序）：");

    for (int i = 0; i <= 16; i++)
        printf("0x%X ", test[i]);
    system("pause");
    return 0;
}