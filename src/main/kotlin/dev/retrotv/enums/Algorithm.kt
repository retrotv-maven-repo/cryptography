package dev.retrotv.enums

class Algorithm {

    /**
     * 해시 알고리즘을 표현하기 열거형 클래스 입니다.
     *
     * @author  yjj8353
     * @since   1.0.0
     */
    enum class Hash(private val label: String) {
        CRC32("CRC-32"),
        MD2("MD2"),
        MD5("MD5"),
        SHA1("SHA-1"),
        SHA224("SHA-224"),
        SHA256("SHA-256"),
        SHA384("SHA-384"),
        SHA512("SHA-512"),
        SHA512224("SHA-512/224"),
        SHA512256("SHA-512/256"),
        SHA3224("SHA3-224"),
        SHA3256("SHA3-256"),
        SHA3384("SHA3-384"),
        SHA3512("SHA3-512");

        /**
         * 알고리즘의 label(이름)을 반환합니다.
         *
         * @return 알고리즘 명
         */
        fun label(): String {
            return label
        }
    }

    /**
     * 양방향/전자서명 암호화 알고리즘을 표현하기 위한 열거형 클래스 입니다.
     *
     * @author  yjj8353
     * @since   1.0.0
     */
    enum class Cipher(private val label: String) {
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

    /**
     * 서명 알고리즘을 표현하기 열거형 클래스 입니다.
     *
     * @author  yjj8353
     * @since   1.0.0
     */
    enum class Signature(private val label: String) {
        NONE("NONEwithRSA"),
        MD2("MD2withRSA"),
        MD5("MD5withRSA"),
        SHA1("SHA1withRSA"),
        SHA224("SHA224withRSA"),
        SHA256("SHA256withRSA"),
        SHA384("SHA384withRSA"),
        SHA512("SHA512withRSA"),
        SHA512224("SHA512/224withRSA"),
        SHA512256("SHA512/256withRSA"),
        SHA3224("SHA3-224"),
        SHA3256("SHA3-256"),
        SHA3384("SHA3-384"),
        SHA3512("SHA3-512");

        /**
         * 알고리즘의 label(이름)을 반환합니다.
         *
         * @return 알고리즘 명
         */
        fun label(): String {
            return label
        }
    }
}