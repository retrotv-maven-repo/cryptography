package dev.retrotv.enums;

/**
 * 암호화 알고리즘을 표현하기 위한 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
public enum Algorithm {
      CRC32("CRC-32")
    , MD2("MD2")
    , MD5("MD5")
    , SHA1("SHA-1")
    , SHA224("SHA-224")
    , SHA256("SHA-256")
    , SHA384("SHA-384")
    , SHA512("SHA-512")
    , SHA512224("SHA-512/224")
    , SHA512256("SHA-512/256")
    , SHA3224("SHA3-224")
    , SHA3256("SHA3-256")
    , SHA3384("SHA3-384")
    , SHA3512("SHA3-512")
    , AESECB("AES/ECB")
    , AESCBC("AES/CBC")
    , AESCTS("AES/CTS")
    , AESCFB("AES/CFB")
    , AESOFB("AES/OFB")
    , AESCTR("AES/CTR")
    , AESGCM("AES/GCM")
    , DESECB_NO_PADDING("DES/ECB/NoPadding")
    , DESCBC_NO_PADDING("DES/CBC/NoPadding")
    , DESECB_PADDING("DES/ECB/PKCS5Padding")
    , DESCBC_PADDING("DES/CBC/PKCS5Padding")
    , LEAECB("LEA/ECB")
    , LEACBC("LEA/CBC")
    , LEACCM("LEA/CCM")
    , LEACFB("LEA/CFB")
    , LEAOFB("LEA/OFB")
    , LEACTR("LEA/CTR")
    , LEAGCM("LEA/GCM")
    , LEAECB128_PADDING("LEA/ECB/PKCS5Padding")
    , LEAECB192_PADDING("LEA/ECB/PKCS5Padding")
    , LEAECB256_PADDING("LEA/ECB/PKCS5Padding")
    , LEACBC128_PADDING("LEA/CBC/PKCS5Padding")
    , LEACBC192_PADDING("LEA/CBC/PKCS5Padding")
    , LEACBC256_PADDING("LEA/CBC/PKCS5Padding")
    , LEACFB128_NO_PADDING("LEA/CFB/NoPadding")
    , LEACFB192_NO_PADDING("LEA/CFB/NoPadding")
    , LEACFB256_NO_PADDING("LEA/CFB/NoPadding")
    , LEACTR128_NO_PADDING("LEA/CTR/NoPadding")
    , LEACTR192_NO_PADDING("LEA/CTR/NoPadding")
    , LEACTR256_NO_PADDING("LEA/CTR/NoPadding")
    , LEAOFB128_NO_PADDING("LEA/OFB/NoPadding")
    , LEAOFB192_NO_PADDING("LEA/OFB/NoPadding")
    , LEAOFB256_NO_PADDING("LEA/OFB/NoPadding")
    , LEAGCM128_NO_PADDING("LEA/GCM/NoPadding")
    , LEAGCM192_NO_PADDING("LEA/GCM/NoPadding")
    , LEAGCM256_NO_PADDING("LEA/GCM/NoPadding")
    , TRIPLE_DESECB_NO_PADDING("DESede/ECB/NoPadding")
    , TRIPLE_DESCBC_NO_PADDING("DESede/CBC/NoPadding")
    , TRIPLE_DESECB_PADDING("DESede/ECB/PKCS5Padding")
    , TRIPLE_DESCBC_PADDING("DESede/CBC/PKCS5Padding")
    , RSAECB_PKCS1_PADDING("RSA/ECB/PKCS1Padding")
    , RSAECB_OAEP_WITH_SHA1_MGF1_PADDING("RSA/ECB/OAEPWithSHA-1AndMGF1Padding")
    , RSAECB_OAEP_WITH_SHA256_MGF1_PADDING("RSA/ECB/OAEPWithSHA-256AndMGF1Padding")
    ;

    private final String label;

    Algorithm(String label) {
        this.label = label;
    }

    /**
     * 알고리즘의 label(이름)을 반환합니다.
     *
     * @return 알고리즘 명
     */
    public String label() {
        return label;
    }
}
