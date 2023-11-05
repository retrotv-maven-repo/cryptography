package dev.retrotv.crypto.exception

/**
 * 암복호화 시, 발생할 수 있는 오류를 처리하기 위한 예외입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
class CryptoFailException : RuntimeException {
    constructor() : super()
    constructor(message: String?) : super(message)
    constructor(message: String?, throwable: Throwable?) : super(message, throwable)
}