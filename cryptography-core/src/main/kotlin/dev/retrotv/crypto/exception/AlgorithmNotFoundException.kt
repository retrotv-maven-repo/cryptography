package dev.retrotv.crypto.exception

class AlgorithmNotFoundException : IllegalArgumentException {
    constructor() : super()
    constructor(message: String) : super(message)
    constructor(message: String, throwable: Throwable) : super(message, throwable)
}