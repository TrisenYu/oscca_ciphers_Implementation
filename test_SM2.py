from SM2 import *

# ================================== 参数设置区域 ==================================

sys_para: ECC = ECC(modP=0x8542D69E4C044F18E8B92435BF6FF7DE457283915C45517D722EDB8B08F1DFC3,
                            a=0x787968B4FA32C3FD2417842E73BBFEFF2F3C848B6831D7E0EC65228B3937E498,
                            b=0x63E4C6D3B23B0C849CF84241484BFE48F61D59A5B16BA06E6E12D1DA27C5249A,
                            n=0x8542D69E4C044F18E8B92435BF6FF7DD297720630485628D5AE74EE7C32E79B7,
                            xG=0x421DEBD61B62EAB6746434EBC3CC315E32220B3BADD50BDC4C4E6C147FEDD43D,
                            yG=0x0680512BCBB42C07D47349D2153B70C4E5D7FDFCBFA36EA1A85841B9E46E09A2)
# 加密样例所用的公钥
"""
publicKey: FFCoord = FFCoord(AffineDot(0x435B39CCA8F3B508C1488AFC67BE491A0F7BA07E581A0E4849A5CF70628A7E0A,
                                       0x75DDBA78F15FEECB4C7895E2C1CDF5FE01DEBB2CDBADF45399CCF77BBA076A42),
                             sys_para)
# 加密函数搭配的校验调试信息。
s = '04245C26FB68B1DDDDB12C4B6BF9F2B6D5FE60A383B0D18D1C4144AB F17F6252 E776CB92 64C2A7E8 8E52B199 03FDC473 78F605E3 ' \
    '6811F5C07423A24B84400F01B8650053A89B41C418B0C3AA D00D886C 00286467 9C3D7360 C30156FA B7C80A02 76712DA9 D8094A63' \
    ' 4B766D3A 285E0748 0653426D'.split(' ')
res = ''.join(s)
print(res)
# 签名样例所用的公钥
publicKey: FFCoord = FFCoord(AffineDot(0x0AE4C7798AA0F119471BEE11825BE46202BB79E2A5844495E97C04FF4DF2548A,
                                       0x7C0240F88F1CD4E16352A73C17B7F16F07353E53A176D684A9FE0C6BB798E857),
                            sys_para)
# 加密样例所用的密钥
secretKey: int = 0x1649AB77A00637BD5E2EFE283FBF353534AA7F7CB89463F208DDBC2920BB0DA0
"""
# 签名样例所用的密钥
# secretKey: int = 0x128B2FA8BD433C6C068C8D803DFF79792A519A55171B1B650C23661D15897263
secretKey, publicKey = secretPublicKeyPairGenerator(sys_para)
# 加密样例所用的明文
msg = '人生苦短，我用 python'.encode('utf-8')
# 签名样例所用的密钥
# msg = 'message digest'.encode('utf-8')
SenderID = 'ALICE123@YAHOO.COM'.encode('utf-8')

# ================================= 验证公钥模块 ==============================================
print(verifySysInECCFF(sys_para), verifyPubInECCFF(publicKey))

print('\n================================== Encrypt and Decrypt  ======================================')
for i in range(64):
    secretKey, publicKey = secretPublicKeyPairGenerator(sys_para)
    secret, C1Len, C2Len = SM2EncryptMsg(bytes2bits(msg), sys_para, publicKey)
    print(f'\nmsg: {msg}\n{secret}\n')
    try:
        message = SM2DecryptMsg(_secret_msg=secret, _ECC=sys_para,
                                _Pub=publicKey, _C1_len=C1Len,
                                _secret_key=secretKey, _C2_len=C2Len)
        print(f'msg: {message.decode("utf-8")}')
    except ValueError as e:
        print(e)
        pass


print('\n================================== Sign and Verify  ======================================')
for i in range(100):
    ZA_id = ZAGenerator(sys_para, publicKey, bytes2bits(SenderID))
    # 生成签名
    remain, signer = SM2DigitalSign(ZA_id, secretKey, bytes2bits(msg), sys_para)
    print(remain, signer)
    # 验证签名
    flag = SM2verifySign(remain, signer, ZA_id, bytes2bits(msg), sys_para, publicKey)
    print(flag)
