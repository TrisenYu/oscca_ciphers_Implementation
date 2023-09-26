"""
@ref:https://oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
"""

# c++ 太过底层
# 以至于应对比特流都显得非常繁琐。
# 虽然优点在于很快。
# case1: abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd
# case2: abc
IV = 0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e


def cyclic_LShift_32(val: int, __times: int) -> int:
    """循环左移。指定传入的 val 必须是 32 位十六进制数 """
    # 因本身运算符的损失，不得不采用字符串移位
    _in_mem_bin = bin(val)[2:]
    # 需要注意的是，可能长度不是 32 位，这需要补齐
    while len(_in_mem_bin) < 32:
        _in_mem_bin = '0' + _in_mem_bin
    Left = _in_mem_bin[: __times]
    Right = _in_mem_bin[__times:]
    res = Right + Left
    test = int(res, 2)
    return test


def checkInBoolean(val) -> bool:
    return 0 <= val < 16


def funcT(j: int) -> int:
    return 0x79cc4519 if checkInBoolean(j) else 0x7a879d8a


def FFBoolean(val: int, x: int, y: int, z: int) -> int:
    return ((x ^ y) ^ z) if checkInBoolean(val) else ((x & y) | (x & z) | (y & z))


def GGBoolean(val: int, x: int, y: int, z: int) -> int:
    return ((x ^ y) ^ z) if checkInBoolean(val) else ((x & y) | ((~ x) & z))


def P0(_x: int) -> int:
    """ x 必须是 32 位数。"""
    return _x ^ cyclic_LShift_32(_x, 9) ^ cyclic_LShift_32(_x, 17)


def P1(_x: int) -> int:
    """ x 必须是 32 位数。"""
    return _x ^ cyclic_LShift_32(_x, 15) ^ cyclic_LShift_32(_x, 23)


def CompressFunction(_idx: int, _V: int, _B: str) -> int:
    extW, expW = [], []
    __, BitsLen = 1, len(_B)
    while __ < BitsLen:  # 每个 B 有 16 个字。
        __tmp = _B[__ - 1: __ + 31]
        __ += 32
        extW.append(int(__tmp, 2))

    for _ in range(16, 68):
        extW.append(P1(extW[_ - 16] ^ extW[_ - 9] ^ cyclic_LShift_32(extW[_ - 3], 15)) ^
                    cyclic_LShift_32(extW[_ - 13], 7) ^ extW[_ - 6])

    for _ in range(0, 64):
        expW.append(extW[_] ^ extW[_ + 4])
    # 首先需要将 256 比特的 _V 拆成 8 个 32 位数
    # 根本不需要换端序
    A, B = (_V >> 224) & 0xFFFFFFFF, (_V >> 192) & 0xFFFFFFFF
    C, D = (_V >> 160) & 0xFFFFFFFF, (_V >> 128) & 0xFFFFFFFF
    E, F = (_V >> 96) & 0xFFFFFFFF, (_V >> 64) & 0xFFFFFFFF
    G, H = (_V >> 32) & 0xFFFFFFFF, _V & 0xFFFFFFFF

    for _ in range(0, 64):
        ss1 = cyclic_LShift_32((cyclic_LShift_32(A, 12) + E +
                                cyclic_LShift_32(funcT(_), _ if _ <= 32 else _ - 32)) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ cyclic_LShift_32(A, 12)
        TT1, TT2 = (FFBoolean(_, A, B, C) + D + ss2 + expW[_]) & 0xFFFFFFFF, \
                   (GGBoolean(_, E, F, G) + H + ss1 + extW[_]) & 0xFFFFFFFF
        D = C
        C = cyclic_LShift_32(B, 9)
        B = A
        A = TT1
        H = G
        G = cyclic_LShift_32(F, 19)
        F = E
        E = P0(TT2)

    tmp = (A << 224) | (B << 192) | (C << 160) | (D << 128) | (E << 96) | (F << 64) | (G << 32) | H
    return tmp ^ _V


def initPlaintext() -> str:
    """获取明文的二进制编码。并视情况填充。"""
    msg = input()
    _bin = ''
    for c in msg:               # 固定为 unicode 编码。
        print(c, ord(c))
        tmp = bin(ord(c))[2:]
        while len(tmp) % 8 != 0:
            tmp = '0' + tmp
        _bin += tmp

    _bin_length = len(_bin)     # 不会自动补成 8 的倍数

    k_4_0, st = 0, 0
    while True:  # l + k_(0) = 447 + 512k, l > 0
        _tmp = 447 + 512 * st - _bin_length
        if _tmp >= 0:
            k_4_0 = _tmp
            break
        st += 1
    _bin += '1'
    for _ in range(0, k_4_0):
        _bin += '0'

    _remainBits, temp = bin(_bin_length)[2:], ''
    _len = len(_remainBits)
    _lst_check = 64 - _len
    if _lst_check < 0:
        print("[长度过长]")
        exit(0)
    # 需填充至 64 位
    for _ in range(0, _lst_check):
        temp += '0'
    _bin += temp + _remainBits
    return _bin


plaintext_bin = initPlaintext()
dataChunkB, num, Vu, l_ptr, r_limit = [], len(plaintext_bin) // 512, [IV], 1, len(plaintext_bin)
str_tmp = ''

while l_ptr < r_limit:
    str_tmp += plaintext_bin[l_ptr - 1: l_ptr + 511]
    l_ptr += 512
    dataChunkB.append(str_tmp)
    str_tmp = ''


for _ in range(1, num + 1):
    Vu.append(CompressFunction(_ - 1, Vu[_ - 1], dataChunkB[_ - 1]))

print(hex(Vu[num]))
