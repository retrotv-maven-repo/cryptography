package dev.retrotv.enums;

public enum CipherAlgorithm {
      AESECB("AES/ECB")
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
    , TRIPLE_DESECB_NO_PADDING("DESede/ECB/NoPadding")
    , TRIPLE_DESCBC_NO_PADDING("DESede/CBC/NoPadding")
    , TRIPLE_DESECB_PADDING("DESede/ECB/PKCS5Padding")
    , TRIPLE_DESCBC_PADDING("DESede/CBC/PKCS5Padding")

    // Java는 스펙상 RSA 알고리즘의 None과 ECB의 구별이 없음
    , RSA("RSA/ECB")
    , RSAECB("RSA/ECB")
    , SHA1_WITH_RSA("SHA1WithRSA")
    , SHA256_WITH_RSA("SHA256withRSA")
    ;

    private final String label;

    CipherAlgorithm(String label) {
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
