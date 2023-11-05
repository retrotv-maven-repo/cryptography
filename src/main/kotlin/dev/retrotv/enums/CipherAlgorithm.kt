package dev.retrotv.enums

enum class CipherAlgorithm(private val label: String) {
    AESECB("AES/ECB"),
    AESCBC("AES/CBC"),
    AESCTS("AES/CTS"),
    AESCFB("AES/CFB"),
    AESOFB("AES/OFB"),
    AESCTR("AES/CTR"),
    AESGCM("AES/GCM"),
    DESECB("DES/ECB"),
    DESCBC("DES/CBC"),
    DESCTS("DES/CTS"),
    DESCFB("DES/CFB"),
    DESOFB("DES/OFB"),
    DESCTR("DES/CTR"),
    LEAECB("LEA/ECB"),
    LEACBC("LEA/CBC"),
    LEACCM("LEA/CCM"),
    LEACFB("LEA/CFB"),
    LEAOFB("LEA/OFB"),
    LEACTR("LEA/CTR"),
    LEAGCM("LEA/GCM"),
    TRIPLE_DESECB("DESede/ECB"),
    TRIPLE_DESCBC("DESede/CBC"),
    TRIPLE_DESCTS("DESede/CTS"),
    TRIPLE_DESCFB("DESede/CFB"),
    TRIPLE_DESOFB("DESede/OFB"),
    TRIPLE_DESCTR("DESede/CTR"),
    RSA("RSA/ECB"),
    RSAECB("RSA/ECB"),
    SHA1_WITH_RSA("SHA1WithRSA"),
    SHA256_WITH_RSA("SHA256withRSA");

    /**
     * 알고리즘의 label(이름)을 반환합니다.
     *
     * @return 알고리즘 명
     */
    fun label(): String {
        return label
    }
}
