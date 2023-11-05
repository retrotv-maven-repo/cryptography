package dev.retrotv.crypto.exception

class WrongPaddingException : RuntimeException {
    constructor() : super("해당 알고리즘에서 지원하지 않는 패딩 기법 입니다.")
    constructor(message: String?) : super(message)
    constructor(message: String?, throwable: Throwable?) : super(message, throwable)
}
