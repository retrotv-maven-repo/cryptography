package dev.retrotv.crypto.encryption.result

/**
 * AEAD 암호화 결과를 담는 클래스 입니다.
 * @property data 암호화된 데이터
 * @property tag 인증 태그
 */
class AEADResult(
    override val data: ByteArray,
    private val tag: ByteArray
) : Result(data)