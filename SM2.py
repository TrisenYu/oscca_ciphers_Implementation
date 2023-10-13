#! /usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
# 第三次重构本程序。
# :cite: https://oscca.gov.cn/sca/xxgk/2010-12/17/1002386/files/b791a9f908bb4803875ab6aeeb7b4e03.pdf
# :NOTE: 不打算实现素数基张成的有限域
# todo: 类拆分。或者不做。

import random
from typing import Optional
import math as mt
import SM3


class AffineDot(object):
    """ 仿射点。传入坐标。"""

    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y


# Elliptic Curve Cryptology
class ECC(object):
    """
    椭圆曲线系数类。可以认为是系统参数的表示形式。
        - y^2 = x^3 + ax + b (mod p)
        - y' = ( 3x^2 + a ) * inv(2y, p) (mod p)
    传入参数：
        - a, b
        - **奇素数** modP
        - 阶 n
        - 基点的两个坐标分量 xG yG
    会根据传入的参数来计算判别式。

    # 基点原本应该是要在初始化时计算的。但是要算二次剩余，还是有点麻烦了。
    """

    def __init__(self,
                 modP: int, xG: int, yG: int,
                 n: int, a: int, b: int):
        self.a, self.b, self.n = a, b, n
        self.p = modP
        self.xG, self.yG = xG, yG
        # 有效性判别
        self.discriminant = (4 * a * a * a + 27 * b * b) % modP

    def isValid(self):
        flag = self.yG * self.yG % self.p == (self.xG * self.xG * self.xG + self.a * self.xG + self.b) % self.p
        return 0 <= self.a, self.b, self.xG, self.yG < self.p and flag


# Finite Field Coordinate
class FFCoord(object):
    """
    椭圆曲线有限域上的点。
    传入参数：
        - 仿射点坐标。
        - 所属的椭圆曲线。
    内置函数：
        - 自加。
        - 求当前点上的导数。
        - 判断当前点是否在椭圆曲线上。
        - 根据基点设置为点。
        - 设置分量（不常用）。
    """

    def __init__(self, DOT: Optional[AffineDot], _ECC: ECC):
        self.coord, self.belong = DOT, _ECC
        self.p = _ECC.p

    @classmethod
    def ECC2Coord(cls, _ECC: ECC) -> 'FFCoord':
        return cls(AffineDot(_ECC.xG, _ECC.yG), _ECC)

    def isOnCur(self) -> bool:
        _a, _b, _p = self.belong.a, self.belong.b, self.belong.p
        if self.coord is None:
            return True
        return self.coord.y * self.coord.y % _p == \
            (self.coord.x * self.coord.x * self.coord.x + _a * self.coord.x + _b) % _p

    def setPartial(self, val: int, isX: bool) -> None:
        """能调用这个函数设置坐标分量，说明坐标一定存在。"""
        if isX:
            self.coord.x = val
        else:
            self.coord.y = val

    def derivative(self) -> tuple[int, Optional[int]]:
        """
        曲线在自己上的导数。 返回分子和分母
            - 一点的切线可以表示为 y = y_p'(x - xp) + yp
            - x^3 - y_p'^2*x^2 + [ a + 2xp y_p'^2 -  2ypy_p'] x + [b + 2ypy_p'xp - yp^2 - xp^2 y_p'^2] = 0
        """
        numerator = (3 * self.coord.x * self.coord.x + self.belong.a) % self.p
        denominator = None if self.coord.y == 0 else InvInOPFF(2 * self.coord.y, self.p)
        return numerator, denominator

    def selfAdd(self):
        """
        自加。如导数不存在，则  P + P + 0 = 0, 返回 2P = 0，即 None，以后同理。
            - 2xP + x_3 = y_p'^2 => {x_3 = y_p'^2 - 2xP}
            - y 见上一个兄弟函数的描述。
        """
        numerator, denominator = self.derivative()
        if denominator is None:
            return FFCoord(None, self.belong)  # 还是竖线一条。

        X = (numerator * numerator * denominator * denominator - 2 * self.coord.x) % self.p
        # 需反转 y 才能使之映射到正确的位置。
        Y = (numerator * denominator * (self.coord.x - X) - self.coord.y) % self.p
        return FFCoord(AffineDot(X, Y), self.belong)


class FFNum(object):
    """
    椭圆曲线有限域上的元素。
    传入参数：
        - 元素值。
        - 所属的椭圆曲线。
    内置函数：
        - 从点来设置元素值。
    """

    def __init__(self, val: int, _ECC: ECC) -> None:
        self.val, self.belong = val, _ECC

    @classmethod
    def setFrom1Coord(cls, P: FFCoord, isX: bool) -> 'FFNum':
        if isX:
            return cls(P.coord.x, P.belong)
        return cls(P.coord.y, P.belong)


def powMod(a: int, n: int, mod: int) -> int:
    _res = 1
    a %= mod
    while n > 0:
        if n & 1:
            _res = (_res * a) % mod
        a = (a * a) % mod
        n //= 2
    return _res


def InvInOPFF(_x: int, mod: int):
    """ 求逆。 """
    return powMod(_x, mod - 2, mod)


def MRPrimeTest(P: int) -> bool:
    """ 费马小定理得到的快速素性检验算法。多次枚举降低误判的可能。"""
    for _ in range(0, 64):
        a = random.randint(2, P - 1)
        if powMod(a, P - 1, P) != 1:
            return False
    return True


def MOVtestFailed(_prime: int, _n: int, B: int = 64) -> bool:
    """抗 MOV 攻击测试。此处 MOV 的阈值默认设置为 64."""
    _t = 1
    for _ in range(1, B + 1):
        _t = (_t * _prime) % _n
        if _t == 1:
            return True
    return False


def num2bytes(_val: int, _len: int) -> bytes:
    """4.2.1 整数转字节串。"""
    if pow(256, _len) <= _val:
        raise ValueError('[Exceed Limit In Function `num2bytes`].')

    tmp = hex(_val)[2:].rjust(_len * 2, '0')
    _res: bytes = b''
    p1, p2 = 0, 1
    while p1 <= len(tmp) - 1:
        _res += bytes.fromhex(str(tmp[p1]) + str(tmp[p2]))
        p1 += 2
        p2 += 2
    return _res


def bytes2num(_val: bytes) -> int:
    """4.2.2"""
    return int.from_bytes(_val, byteorder='little')


def bits2bytes(_val: str) -> bytes:
    """4.2.3"""
    k = mt.ceil(len(_val) / 8)
    _res = b''
    p1, p2 = 0, 1
    while p1 < k:
        tmp = _val[p1 * 8:p2 * 8]
        _res += (((int(tmp[:4], 2) << 4) & 0xF0) + int(tmp[4:], 2)).to_bytes(byteorder='little', length=1)
        p1 += 1
        p2 += 1
    while len(_res) < k:
        _res = b'\x00' + _res
    return _res


def bytes2bits(_val: bytes) -> str:
    """4.2.4"""
    _res = ''
    for c in _val:
        tmp = bin(c)[2:]
        while len(tmp) < 8:
            tmp = '0' + tmp
        _res += tmp
    return _res


def ECCNum2bytes(_val: FFNum) -> bytes:
    """4.2.5。Prerequisite：4.2.1"""
    t = mt.ceil(mt.log(_val.belong.p, 2))
    length = mt.ceil(t / 8)
    return num2bytes(_val.val, length)


def bytes2ECCNum(_ECC: ECC, _val: bytes) -> FFNum:
    """4.2.6。Prerequisite：4.2.2"""
    return FFNum(bytes2num(_val), _ECC)


def ECCNum2Num(_Num: FFNum) -> int:
    """4.2.7"""
    return _Num.val


def Coord2bytes(coord: FFCoord) -> bytes:
    """4.2.8 未压缩形式。"""
    calcX = ECCNum2bytes(FFNum.setFrom1Coord(coord, True))
    calcY = ECCNum2bytes(FFNum.setFrom1Coord(coord, False))
    PC = b'\x04'
    return PC + calcX + calcY


def bytes2Coord(_ECC: ECC, _val: bytes) -> FFCoord:
    """ 4.2.9"""
    if _val[0] != 4:
        raise ValueError('[Fake Message].')
    _tmp = _val.hex()
    l = (len(_val) - 1) // 2
    pre, suf = _val[1:l + 1], _val[l + 1:]
    X = bytes2ECCNum(_ECC, pre[::-1])
    Y = bytes2ECCNum(_ECC, suf[::-1])
    _res: FFCoord = FFCoord(AffineDot(X.val, Y.val), _ECC)
    return _res


def hex2bytes(_val: str) -> bytes:
    while len(_val) % 2 != 0:
        _val = '0' + _val
    return bytes.fromhex(_val)


def ECC_FF_Coord_Add(_P: FFCoord, _Q: FFCoord) -> FFCoord:
    """
    ECC有限域上两个 **不同点** 的加法。
    """
    if _P.coord is None and _Q.coord is None:
        return FFCoord(None, _P.belong)  # 0 + 0
    elif _P.coord is None and _Q.coord is not None:
        return _Q  # 0 + Q
    elif _P.coord is not None and _Q.coord is None:
        return _P  # P + 0

    y: int = (_P.coord.y - _Q.coord.y) % _P.p
    x: int = (_P.coord.x - _Q.coord.x) % _P.p

    if x == 0:
        return FFCoord(None, _P.belong)  # 两个点加出了 None， 一条竖线
    x = InvInOPFF(x, _P.p)
    slope = (y * x) % _P.p
    ''' xP + xQ + xR = slope^2 (mod p) '''
    xR = (slope * slope - _P.coord.x - _Q.coord.x) % _P.p
    yR = (slope * (_P.coord.x - xR) - _P.coord.y) % _P.p

    return FFCoord(AffineDot(xR, yR), _P.belong)


def KG(G: FFCoord, k: int) -> FFCoord:
    """ 有限域上求倍加点。 """
    _res: FFCoord = FFCoord(None, G.belong)
    _ECC: ECC = G.belong
    while k > 0:
        if k & 1:
            if _res.coord is None:
                _res = G
            else:
                _res = ECC_FF_Coord_Add(_res, G)
        G = G.selfAdd()
        k //= 2
    return _res


# 验证与生成模块
def verifySysInECCFF(_ECC: ECC) -> bool:
    """ 不考虑扩域得到的有限域。只考虑素数域的系统参数。"""
    if _ECC.p % 2 == 0 or not _ECC.isValid():
        return False
    if _ECC.discriminant == 0 or not MRPrimeTest(_ECC.n):
        return False
    if _ECC.n <= 2 ** 191 or _ECC.n <= 4 * mt.sqrt(_ECC.p):
        return False
    if KG(FFCoord.ECC2Coord(_ECC), _ECC.n).coord is not None:
        return False
    return _ECC.n != _ECC.p and not MOVtestFailed(_ECC.p, _ECC.n)


def verifyPubInECCFF(pub: Optional[FFCoord]) -> bool:
    """ 验证公钥。"""
    if pub.coord is None or not pub.isOnCur():
        return False
    if 0 > pub.coord.x or pub.coord.x >= pub.p or \
            0 > pub.coord.y or pub.coord.y >= pub.p:
        return False
    return KG(pub, pub.belong.n).coord is None


def secretPublicKeyPairGenerator(_ECC: ECC) -> tuple[int, FFCoord]:
    """ 根据所属椭圆曲线返回密钥对。 """
    _secret = random.randint(1, _ECC.p - 2)
    _G = FFCoord.ECC2Coord(_ECC)
    return _secret, KG(_G, _secret)


def padding_0_hex(string: str):
    """ 十六进制补零。 """
    while len(string) % 2 != 0:
        string = '0' + string
    return string


def KDF(_bits_str: str, _target_len: int) -> str:
    """ 密钥拓展函数。 """

    def padding_0_32bits(string: str):
        """ 32 位数补零。 """
        while len(string) < 32:
            string = '0' + string
        return string

    cnt = 0x00000001  # 32 位
    v, Hello = 256, []

    if _target_len >= v * 0xFFFFFFFFF:
        raise ValueError('[Exceed Limit When KDF Probing].')

    length = _target_len // v if _target_len % v == 0 else _target_len // v + 1
    for _ in range(length):
        _tmp = bits2bytes(_bits_str + padding_0_32bits(bin(cnt)[2:]))
        Hello.append(padding_0_hex(SM3.SM3Hash(True, _tmp.decode('iso-8859-1'))[2:]))
        cnt += 1

    Hi = [bytes2bits(bytes.fromhex(c)) for c in Hello]
    if _target_len % v != 0:
        Hi[-1] = Hi[-1][:_target_len - v * mt.ceil(_target_len / v)]

    _show = hex(int(''.join(Hi), 2))[2:_target_len + 2]
    return _show


def testAll0(_tmp: str) -> bool:
    """ 测试十六进制数是否全零。 """
    return int(_tmp, 16) == 0


def SM2EncryptMsg(_bits_msg: str, _ECC: ECC, _Pub: FFCoord) -> tuple[str, int, int]:
    """
    SM2 明文加密函数。
        :param: _bits_msg:  明文，填充后的比特串。
        :param: _ECC:       所在的椭圆曲线。
        :param: _Pub:       公钥。点形式给出。
        :returns: 密文、C1 在填充比特串下的长度、C2 在填充比特串下的长度。
    """
    while True:
        k = random.randint(1, _ECC.p - 1)
        # NOTE: DEBUG
        #   以下一句是测试内容。
        #       k = 0x4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F
        #   以下是可能会对整个程序产生影响的爆破性 k。
        #       k = 0x427c96b94c197b6edabc3308e03aac45d2cf66f5e5638110aaed5bd6b2d8ffa9
        #           0x5B691A4ECAA9A827FBAB3EBE8F2A8A7EF080090B207628C308F3C680D62AFE44
        #           0x1c8cd326c34d80c166f2c22728a1b19d578cb78d15885f55b327fb04c36c917b
        #   但都已通过测试。
        #   可视情况更换。
        # NOTE: DEBUG END
        tC1 = KG(FFCoord.ECC2Coord(_ECC), k)
        if tC1.coord is None:
            continue
        C1: bytes = Coord2bytes(tC1)
        # !原本应有余因子判断有效性。
        tC3 = KG(_Pub, k)
        Bx3, By3 = bytes2bits(ECCNum2bytes(FFNum.setFrom1Coord(tC3, True))), \
            bytes2bits(ECCNum2bytes(FFNum.setFrom1Coord(tC3, False)))
        tmp = KDF(Bx3 + By3, len(_bits_msg))
        if testAll0(tmp):
            continue

        Length = max(len(_bits_msg), len(tmp))  # 转换后需要的长度补齐
        bC2 = bin(int(_bits_msg, 2) ^ int(tmp, 16))[2:]
        while len(bC2) < Length:
            bC2 = '0' + bC2

        tmpCope = Bx3 + _bits_msg + By3
        C3 = padding_0_hex(SM3.SM3Hash(True, bits2bytes(tmpCope).decode('iso-8859-1'))[2:])

        C2 = hex(int(bC2, 2))[2:]
        while len(C2) < Length // 4:
            C2 = '0' + C2

        return (C1.hex() + C2 + C3).upper(), len(bytes2bits(C1)), len(bC2)  # , k


def SM2DecryptMsg(_secret_key: int, _secret_msg: str, _C1_len: int,
                  _C2_len: int, _ECC: ECC, _Pub: FFCoord) -> bytes:
    """
    SM2 密文解密函数。
        :param: _secret_key:    密钥。
        :param: _secret_msg:    密文，十六进制串。
        :param: _C1_len:        C1 在填充比特串下的长度。
        :param: _C2_len:        C2 在填充比特串下的长度。
        :param: _ECC:           所在的椭圆曲线。
        :param: _Pub:           公钥。点形式给出。
        :returns: 解密后的明文。如解密失败则抛出错误。
    """
    if _secret_msg[:2] != '04':
        raise ValueError('[Invalid Encrypt Message].')
    secret_bits = bytes2bits(hex2bytes(_secret_msg))

    C1 = hex(int(secret_bits[:_C1_len], 2))[2:]
    while len(C1) % 2 != 0:
        C1 = '0' + C1

    _P = bytes2Coord(_ECC, hex2bytes(C1))
    if not _P.isOnCur():
        raise ValueError('[Invalid Point].')

    secret_P = KG(_P, _secret_key)
    X2 = bytes2bits(ECCNum2bytes(FFNum.setFrom1Coord(secret_P, True)))
    Y2 = bytes2bits(ECCNum2bytes(FFNum.setFrom1Coord(secret_P, False)))
    tmp = KDF(X2 + Y2, _C2_len)
    if testAll0(tmp):
        raise ValueError('[Zero Parse Error].')

    C2, C3 = secret_bits[_C1_len:_C1_len + _C2_len], secret_bits[_C1_len + _C2_len:]
    _show_C2LEN, _showC3LEN = len(C2), len(C3)
    Length = max(len(C2), len(tmp))  # 转换后需要的长度补齐
    decrypt_msg = bin(int(tmp, 16) ^ int(C2, 2))[2:]
    while len(decrypt_msg) < Length:
        decrypt_msg = '0' + decrypt_msg
    tC3 = padding_0_hex(SM3.SM3Hash(True, bits2bytes(X2 + decrypt_msg + Y2).decode('iso-8859-1'))[2:])
    C3 = bits2bytes(C3).hex()
    if tC3 != C3:
        raise ValueError('[Hash Parse Error].')
    return bits2bytes(decrypt_msg)


def ZAGenerator(_ECC: ECC, _Pub: FFCoord, _ID_bits: str) -> str:
    """
    ZA 生成函数。
        :param _ID_bits: 身份标识。比特串。
        :param _Pub: 公钥。有限域中的点坐标。
        :param _ECC: 加解密时所用的椭圆曲线。
        :return: SM3(_ID_Len_Bytes + _ID + _a + _b + _xG + _yG + _xP + _yP), 其中的参数按单个单个的字节转为了字符串、返回的
                十六进制数均转为大写。
    """

    def padding_0_2bytes(string: str) -> bytes:
        """ 两字节补零。"""
        while len(string) < 4:
            string = '0' + string
        return bytes.fromhex(string)

    _ID_Len_Bytes = padding_0_2bytes(hex(len(_ID_bits))[2:])

    _ID = bits2bytes(_ID_bits)
    _a, _b = ECCNum2bytes(FFNum(_ECC.a, _ECC)), ECCNum2bytes(FFNum(_ECC.b, _ECC))
    _xG, _yG = ECCNum2bytes(FFNum(_ECC.xG, _ECC)), ECCNum2bytes(FFNum(_ECC.yG, _ECC))
    _xP, _yP = ECCNum2bytes(FFNum(_Pub.coord.x, _ECC)), ECCNum2bytes(FFNum(_Pub.coord.y, _ECC))

    return padding_0_hex(
        SM3.SM3Hash(True, (_ID_Len_Bytes + _ID + _a + _b + _xG + _yG + _xP + _yP).decode('iso-8859-1'))[2:]).upper()


def SM2DigitalSign(ZA: str, _secret_key: int, _msg: str, _ECC: ECC) -> tuple[str, str]:
    """
    数字签名函数。只返回签名(r, s)。
        :param ZA: 无 0x 标识的十六进制杂凑值
        :param _secret_key: 密钥。
        :param _msg: 比特串密文。
        :param _ECC: 所属椭圆曲线。
        :return: 两个可用于验签的签名。均为大写的十六进制。
    """
    __msg = bits2bytes(_msg)
    _ZA = hex2bytes(ZA)
    _e = bytes2num(hex2bytes(SM3.SM3Hash(True, (_ZA + __msg).decode('iso-8859-1'))[2:])[::-1])
    while True:
        k = random.randint(1, _ECC.n - 1)
        # NOTE: DEBUG
        #   k = 0X6CB28D99385C175C94F94E934817663FC176D925DD72B727260DBAAE1FB2F96F
        # NOTE: DEBUG END
        P = KG(FFCoord.ECC2Coord(_ECC), k)
        X, Y = ECCNum2Num(FFNum.setFrom1Coord(P, True)), ECCNum2Num(FFNum.setFrom1Coord(P, False))
        r = (_e + X) % _ECC.n
        if r == 0 or r + k == _ECC.n:
            continue
        s = (InvInOPFF(1 + _secret_key, _ECC.n) * (k - r * _secret_key)) % _ECC.n
        if s == 0:
            continue
        return hex(r)[2:].upper(), hex(s)[2:].upper()


def SM2verifySign(_r: str, _s: str, ZA: str, _msg: str, _ECC: ECC, _Pub: FFCoord) -> bool:
    """
    验签。
        :param _Pub: 公钥。
        :param _ECC: 所属椭圆曲线。
        :param _msg: 密文。比特串形式。
        :param ZA:
        :param _s: s。十六进制数。
        :param _r: r。十六进制数。
        :return: 判断签名是否有效。
    """
    r, s = int(_r, 16), int(_s, 16)
    if 0 >= r or r >= _ECC.n or 0 >= s or s >= _ECC.n:
        return False
    tMsg = hex2bytes(ZA) + bits2bytes(_msg)
    _e = int(padding_0_hex(SM3.SM3Hash(True, tMsg.decode('iso-8859-1'))), 16)
    _t = (r + s) % _ECC.n
    if _t == 0:
        return False
    P = ECC_FF_Coord_Add(KG(FFCoord.ECC2Coord(_ECC), s), KG(_Pub, _t))
    _xP, _yP = ECCNum2Num(FFNum(P.coord.x, _ECC)), ECCNum2Num(FFNum(P.coord.y, _ECC))
    _R = (_e + _xP) % _ECC.n
    return _R == r
