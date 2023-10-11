#! /usr/bin/python3
# SPDX-License-Identifier: GPL-2.0
# :cite: https://oscca.gov.cn/sca/xxgk/2010-12/17/1002386/files/b791a9f908bb4803875ab6aeeb7b4e03.pdf
# NOTE: 1. 不打算实现数字签名、密钥交换，只打算实现公钥的加解密。2. 不打算实现素数基张成的有限域
# WARNING: 尚未通过验证，请不要在生产环境中使用。
import random
from typing import Optional
import math as mt
import SM3


class AffineDot(object):
    def __init__(self, x: int, y: int):
        self.x = x
        self.y = y


def Num2hex(_val: int, _len: int):
    """ 不够目标长度的，高位补 0 """
    tmp = hex(_val)
    while len(tmp) < _len * 2:
        tmp = '00' + tmp
    return tmp


def hex2bits(_bytes: str):
    """4.2.4"""

    def padding0inByte(string: str):
        while len(bin_H) < 4:
            string = '0' + string
        return string

    length = len(_bytes)
    # 至少一定是偶数个 那么可以两个两个跳
    p1, p2 = 0, 1
    res = ''
    while p2 < length:
        _H, _L = ord(_bytes[p1]), ord(_bytes[p2])
        bin_H, bin_L = bin(_H)[2:], bin(_L)[2:]
        bin_H, bin_L = padding0inByte(bin_H), padding0inByte(bin_L)
        res += bin_H + bin_L
        p1 += 2
        p2 += 2
    return res


def powMod(a: int, n: int, mod: int) -> int:
    res = 1
    a %= mod
    while n > 0:
        if n % 2 == 1:
            res = (res * a) % mod
        a = (a * a) % mod
        n //= 2
    return res


def InvInOPFF(_x: int, mod: int):
    return powMod(_x, mod - 2, mod)


def MRPrimeTest(P: int) -> bool:
    """ 费马小定理得到的快速素性检验算法。多次枚举降低误判的可能。"""
    for i in range(0, 64):
        a = random.randint(2, P - 1)
        if powMod(a, P - 1, P) != 1:
            return False
    return True


def MOVtestFailed(_prime: int, _n: int, B: int = 64) -> bool:
    """抗 MOV 攻击测试。此处 MOV 的阈值默认设置为 64."""
    _t = 1
    for i in range(1, B + 1):
        _t = (_t * _prime) % _n
        if _t == 1:
            return True
    return False


# Elliptic Curve
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
    会根据传入的参数来计算判别式。基点原本应该是要在初始化时计算的。
    但是要算二次剩余，还是有点麻烦了。
    """

    def __init__(self,
                 modP: int, xG: int, yG: int,
                 n: int, a: int, b: int):
        self.a, self.b, self.n = a, b, n
        self.p = modP
        self.xG, self.yG = xG, yG
        # 需准备有效性判别
        self.discriminant = (4 * a * a * a + 27 * b * b) % modP

    def isValid(self):
        flag = self.yG * self.yG % self.p == (self.xG * self.xG * self.xG + self.a * self.xG + self.b) % self.p
        return 0 <= self.a, self.b, self.xG, self.yG < self.p and flag


# Finite Field Coordinate
class FFCoord(object):
    def __init__(self, DOT: Optional[AffineDot], _ECC: ECC):
        self.coord, self.belong = DOT, _ECC
        self.p = _ECC.p

    @classmethod
    def ECC2Coord(cls, _ECC: ECC):
        return cls(AffineDot(_ECC.xG, _ECC.yG), _ECC)

    def isOnCur(self) -> bool:
        _a, _b, _p = self.belong.a, self.belong.b, self.belong.p
        if self.coord is None:
            return True
        return self.coord.y * self.coord.y % _p == (self.coord.x * self.coord.x * self.coord.x +
                                                    _a * self.coord.x + _b) % _p

    def setPartial(self, val: int, isX: bool) -> None:
        """能调用这个，说明坐标一定正常。"""
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
            # 注意，这里完成了自加，需要变
            return FFCoord(None, self.belong)  # 还是竖线一条。

        X = (numerator * numerator * denominator * denominator - 2 * self.coord.x) % self.p
        Y = (numerator * denominator * (self.coord.x - X) - self.coord.y) % self.p  # 需要反转 y 才能使之映射到正确的位置。
        return FFCoord(AffineDot(X, Y), self.belong)


def Coord2hex(coord: FFCoord) -> str:
    """4.2.8 未压缩形式。"""
    calcX = ECCNum2hex(FFNum.setFrom1Coord(coord, True))
    calcY = ECCNum2hex(FFNum.setFrom1Coord(coord, False))
    PC = '04'
    return PC + calcX + calcY


def ECC_FF_Coord_Add(_P: FFCoord, _Q: FFCoord) -> FFCoord:
    """
    ECC有限域上两个 **不同点** 的加法。
    实际上不同于标准中定义的加法。
    """
    if _P.coord is None and _Q.coord is None:
        return FFCoord(None, _P.belong)     # 0 + 0
    elif _P.coord is None and _Q.coord is not None:
        return _Q       # 0 + Q
    elif _P.coord is not None and _Q.coord is None:
        return _P       # P + 0

    y: int = (_P.coord.y - _Q.coord.y) % _P.p
    x: int = (_P.coord.x - _Q.coord.x) % _P.p

    if x == 0:
        return FFCoord(None, _P.belong)  # 两个点加出了 None， 一条竖线
    x = InvInOPFF(x, _P.p)
    slope = (y * x) % _P.p
    # 计算时需要翻转 y 值，而为了防止出错，先按根与系数的关系做。
    ''' xP + xQ + xR = slope^2 (mod p) '''
    xR = (slope * slope - _P.coord.x - _Q.coord.x) % _P.p
    yR = (slope * (-xR + _P.coord.x) - _P.coord.y) % _P.p

    return FFCoord(AffineDot(xR, yR), _P.belong)


def KG(G: FFCoord, k: int) -> FFCoord:
    res: FFCoord = FFCoord(None, G.belong)
    _ECC: ECC = G.belong
    while k > 0:
        if k % 2 == 1:
            if res.coord is None:
                res = G
            else:
                res = ECC_FF_Coord_Add(res, G)
        G = G.selfAdd()
        k //= 2
    return res


class FFNum(object):
    def __init__(self, val: int, _ECC: ECC) -> None:
        self.val, self.belong = val, _ECC

    @classmethod
    def setFrom1Coord(cls, P: FFCoord, isX: bool) -> 'FFNum':
        if isX:
            return cls(P.coord.x, P.belong)
        return cls(P.coord.y, P.belong)


def ECCNum2hex(_val: FFNum) -> str:
    """4.2.5"""
    t = mt.ceil(mt.log(_val.belong.p, 2))
    length = mt.ceil(t / 8)
    return Num2hex(_val.val, length)


# 验证与生成模块
def verifySysInECCFF(_ECC: ECC) -> bool:
    """ 不考虑扩域得到的有限域。只考虑素数域的系统参数。"""
    if _ECC.p % 2 == 0 or not _ECC.isValid():
        return False
    if _ECC.discriminant == 0:
        return False
    if not MRPrimeTest(_ECC.n):
        return False
    if _ECC.n <= 2 ** 191 or _ECC.n <= 4 * mt.sqrt(_ECC.p):
        return False
    if KG(FFCoord.ECC2Coord(_ECC), _ECC.n) is not None:
        return False
    return _ECC.n != _ECC.p and not MOVtestFailed(_ECC.p, _ECC.n)


def verifyPubInECCFF(pub: Optional[FFCoord]) -> bool:
    """ 验证公钥。"""
    if pub.coord is None or not pub.isOnCur():
        return False
    if 0 < pub.coord.x or pub.coord.x >= pub.p or \
            0 < pub.coord.y or pub.coord.y >= pub.p:
        return False
    return KG(pub, pub.belong.n) is None


def secretGenerator(_ECC: ECC):
    """ 返回密钥。 """
    secret = random.randint(1, _ECC.p - 2)
    _G = FFCoord.ECC2Coord(_ECC)
    return secret, (_G, secret)


# 转换模块实现
def KDF(bits_str: str, res_bitsLen: int):
    """"""
    def padding_0(string: str):
        while len(string) < 32:
            string = '0' + string
        return string

    def binCalcHex(string: str):
        p1, p2 = 0, 1
        _res = b''
        while p2*8 < len(string):
            _res = _res + int(string[p1*8:p2*8], 2).to_bytes()
            p1 += 1
            p2 += 1
        return _res

    cnt = 0x00000001  # 32 位
    v, Hello = 256, []
    if res_bitsLen >= v * 0xFFFFFFFFF:
        raise ValueError("[Exceed Limit].")

    res = ''
    for i in range(0, mt.ceil(res_bitsLen / v)):
        # NOTE: 非常坑的地方之一。
        # Hello.append(SM3.SM3Hash(True, bits_str + padding_0(bin(cnt)[2:]))[2:])
        tmp_bin_str: str = bits_str + padding_0(bin(cnt)[2:])
        # 直接转换的问题在于长度可能不够。
        while len(tmp_bin_str) % 8 != 0:
            tmp_bin_str = '0' + tmp_bin_str
        bytes_str = binCalcHex(tmp_bin_str)

        Hello.append(SM3.SM3Hash(True, bytes_str.decode('ascii', 'ignore'))[2:])
        cnt += 1

    for H in Hello[:len(Hello)]:
        res += H
    # fixme: 此处可能需要重修。
    if res_bitsLen % v == 0:
        res += Hello[-1]
    else:
        res += Hello[-1][:(res_bitsLen % v)]
    return res[:res_bitsLen]


def SM2encrypt(_bits_msg: str, _ECC: ECC, _Pub: FFCoord):
    def testAll0(string: str) -> bool:
        tester = int('0x' + string, 16)
        return tester == 0

    while True:
        # k = random.randint(1, _ECC.p - 1)
        k = 0x4C62EEFD6ECFC2B95B92FD6C3D9575148AFA17425546D49018E5388D49DD7B4F
        tC1 = KG(FFCoord.ECC2Coord(_ECC), k)
        if tC1.coord is None:
            continue
        # todo:点转hex转比特串
        C1: str = hex2bits(Coord2hex(tC1))
        # 原本应存在余因子来判断公钥。
        tC3 = KG(_Pub, k)
        tmp = KDF(bin(tC3.coord.x)[2:] + bin(tC3.coord.y)[2:], len(_bits_msg))
        if testAll0(tmp):
            continue
        Length = max(len(_bits_msg), len(tmp))  # 转换后需要的长度补齐
        C2 = bin(int(_bits_msg, 2) ^ int(tmp, 16))[2:]
        while len(C2) < Length:
            C2 = '0' + C2
        C3 = SM3.SM3Hash(True, bin(tC3.coord.x)[2:] + _bits_msg + bin(tC3.coord.y)[2:])[2:]
        return C1 + C2 + C3


def SM2decrypt(_enc_msg: str, _ECC: ECC, _Pub: FFCoord):
    """todo."""


sys_para: ECC = ECC(modP=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
                    a=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
                    b=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
                    n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7,
                    xG=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
                    yG=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2)
publicKey: FFCoord = FFCoord(AffineDot(0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A,
                                       0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42),
                             sys_para)

msg = 'encryption standard'.encode('unicode').hex()
bin_msg = bin(int(msg, 16))[2:]
if len(bin_msg) % 2 != 0:
    bin_msg = '0' + bin_msg
print(msg, SM2encrypt(bin_msg, sys_para, publicKey))

print(SM3.SM3Hash(True, "abc"))

# 测试环节一
testMe = b'\x00\x01\x10\xe9\x80\x86\xe7\x81\xab'
print(testMe.decode('utf-8', 'replace'))
print(' ', SM3.SM3Hash(True, '123456'))

# 测试环节二
elliptic_curve = ECC(modP=19, a=1, b=1, n=21, xG=10, yG=2)
point1, point2 = FFCoord(AffineDot(10, 2), elliptic_curve), FFCoord(AffineDot(9, 6), elliptic_curve)
point3 = ECC_FF_Coord_Add(point1, point2)
point1_2 = point1.selfAdd()
print(point1_2.coord.x, point1_2.coord.y, point3.coord.x, point3.coord.y)
