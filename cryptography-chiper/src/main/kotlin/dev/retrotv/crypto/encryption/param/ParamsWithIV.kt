package dev.retrotv.crypto.encryption.param

/**
 * 암호화 및 복호화에 필요한 파라미터 클래스 입니다.
 * Params 클래스를 상속받습니다.
 */
class ParamsWithIV(
    override val key: ByteArray,
    val iv: ByteArray?
) : Params(key)