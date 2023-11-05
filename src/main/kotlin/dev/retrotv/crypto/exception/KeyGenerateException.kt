package dev.retrotv.crypto.exception

/**
 * 키 생성 시, 발생할 수 있는 오류를 처리하기 위한 예외입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
class KeyGenerateException : RuntimeException {
    constructor() : super()
    constructor(message: String?) : super(message)
    constructor(message: String?, throwable: Throwable?) : super(message, throwable)
}
