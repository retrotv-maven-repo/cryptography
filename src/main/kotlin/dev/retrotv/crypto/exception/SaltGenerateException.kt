package dev.retrotv.crypto.exception

class SaltGenerateException : RuntimeException {
    constructor() : super()
    constructor(message: String) : super(message)
    constructor(message: String, throwable: Throwable) : super(message, throwable)
}