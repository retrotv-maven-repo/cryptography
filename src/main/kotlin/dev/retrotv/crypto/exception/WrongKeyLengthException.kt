package dev.retrotv.crypto.exception

/**
 * 잘못 된 키 길이를 입력 받았을 시, 발생할 수 있는 오류를 처리하기 위한 예외입니다.
 *
 * @author  yjj8353
 * @since   1.8
 */
class WrongKeyLengthException : RuntimeException {
    constructor() : super("지원하지 않는 Key 길이 입니다.")
    constructor(message: String?) : super(message)
    constructor(message: String?, throwable: Throwable?) : super(message, throwable)
}
