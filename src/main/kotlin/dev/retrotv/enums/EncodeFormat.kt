package dev.retrotv.enums

/**
 * 문자열 인코더를 표현하기 위한 열거형 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
enum class EncodeFormat(private val label: String) {
    HEX("Hex"),
    BASE64("Base64");

    fun label(): String {
        return label
    }
}
