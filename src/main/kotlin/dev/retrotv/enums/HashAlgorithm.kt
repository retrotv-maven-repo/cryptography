package dev.retrotv.enums

enum class HashAlgorithm(private val label: String) {
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
