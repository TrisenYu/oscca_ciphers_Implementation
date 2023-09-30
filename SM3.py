"""
@ref:https://oscca.gov.cn/sca/xxgk/2010-12/17/1002389/files/302a3ada057c4a73830536d03e683110.pdf
    ┌──[case1]: `abcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcdabcd`
    └─> 0xdebe9ff92275b8a138604889c18e5a4d6fdb70e5387e5765293dcba39c0c5732
    
    ┌──[case2]: `abc`
    └─> 0x66c7f0f462eeedd9d1f2d46bdc10e4e24167c4875cf2f7a2297da02b8f4ba8e0
"""
IV = 0x7380166f4914b2b9172442d7da8a0600a96f30bc163138aae38dee4db0fb0e4e


def cyclic_LShift_32(val: int, __times: int) -> int:
    """循环左移。指定传入的 val 必须是 32 位十六进制数 """
    _in_mem_bin = bin(val)[2:]
    while len(_in_mem_bin) < 32:
        _in_mem_bin = '0' + _in_mem_bin

    res = _in_mem_bin[__times:] + _in_mem_bin[: __times]
    return int(res, 2)


def checkInBoolean(val) -> bool:
    return 0 <= val < 16


def funcT(val: int) -> int:
    return 0x79cc4519 if checkInBoolean(val) else 0x7a879d8a


def FFBoolean(val: int, x: int, y: int, z: int) -> int:
    return ((x ^ y) ^ z) if checkInBoolean(val) else ((x & y) | (x & z) | (y & z))


def GGBoolean(val: int, x: int, y: int, z: int) -> int:
    return ((x ^ y) ^ z) if checkInBoolean(val) else ((x & y) | ((~ x) & z))


def P0(_x: int) -> int:
    return _x ^ cyclic_LShift_32(_x, 9) ^ cyclic_LShift_32(_x, 17)


def P1(_x: int) -> int:
    return _x ^ cyclic_LShift_32(_x, 15) ^ cyclic_LShift_32(_x, 23)


def CompressFunction(_idx: int, _V: int, _B: str) -> int:
    extW, expW = [], []
    __, BitsLen = 1, len(_B)

    while __ < BitsLen:             # 每个 B 有 16 个字。
        __tmp = _B[__ - 1: __ + 31]
        __ += 32
        extW.append(int(__tmp, 2))

    for _ in range(16, 68):
        extW.append(P1(extW[_ - 16] ^ extW[_ - 9] ^ cyclic_LShift_32(extW[_ - 3], 15)) ^
                    cyclic_LShift_32(extW[_ - 13], 7) ^ extW[_ - 6])
    for _ in range(0, 64):
        expW.append(extW[_] ^ extW[_ + 4])

    # 根本不用换端序
    Reg = [(_V >> (256 - i * 32)) & 0xFFFFFFFF for i in range(1, 9)]
    for _ in range(0, 64):
        ss1 = cyclic_LShift_32((cyclic_LShift_32(Reg[0], 12) + Reg[4] +
                                cyclic_LShift_32(funcT(_), _ if _ <= 32 else _ - 32)) & 0xFFFFFFFF, 7)
        ss2 = ss1 ^ cyclic_LShift_32(Reg[0], 12)

        TT1, TT2 = (FFBoolean(_, Reg[0], Reg[1], Reg[2]) + Reg[3] + ss2 + expW[_]) & 0xFFFFFFFF, \
                   (GGBoolean(_, Reg[4], Reg[5], Reg[6]) + Reg[7] + ss1 + extW[_]) & 0xFFFFFFFF

        Reg[3] = Reg[2]
        Reg[2] = cyclic_LShift_32(Reg[1], 9)
        Reg[1] = Reg[0]
        Reg[0] = TT1
        Reg[7] = Reg[6]
        Reg[6] = cyclic_LShift_32(Reg[5], 19)
        Reg[5] = Reg[4]
        Reg[4] = P0(TT2)

    tmp = (Reg[0] << 224) | (Reg[1] << 192) | (Reg[2] << 160) | (Reg[3] << 128) | \
          (Reg[4] << 96) | (Reg[5] << 64) | (Reg[6] << 32) | Reg[7]
    return tmp ^ _V


def initPlaintext() -> str:
    msg = input()

    _bin, k_4_0, st = '', 0, 0

    for c in msg:                   # 固定为 unicode 编码。
        _ = bin(ord(c))[2:]
        while len(_) % 8 != 0:      # 不会自动补成 8 的倍数
            _ = '0' + _
        _bin += _

    _bin_length = len(_bin)

    while True:                     # l + k_(0) = 447 + 512k, l > 0
        _ = 447 + 512 * st - _bin_length
        if _ >= 0:
            k_4_0 = _
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

    for _ in range(0, _lst_check):  # 需填充至 64 位
        temp += '0'
    _bin += temp + _remainBits
    return _bin


def SM3Hash() -> str:
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

    return hex(Vu[num])


if __name__ == "__main__":
    tester = SM3Hash()
    print(tester)
