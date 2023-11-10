package dev.retrotv.enums

/**
 * 서명 알고리즘을 표현하기 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
enum class SignatureAlgorithm(private val label: String) {
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
