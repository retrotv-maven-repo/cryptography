package dev.retrotv.crypto.exception

/**
 * 잘못된 형식의 패딩 사용 시, 발생할 수 있는 예외를 처리하기 위한 예외입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
class WrongPaddingException : RuntimeException {
    constructor() : super("해당 알고리즘에서 지원하지 않는 패딩 기법 입니다.")
    constructor(message: String) : super(message)
    constructor(message: String, throwable: Throwable) : super(message, throwable)
}
