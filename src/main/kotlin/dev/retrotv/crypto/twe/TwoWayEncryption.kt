package dev.retrotv.crypto.twe

import dev.retrotv.crypto.exception.CryptoFailException
import dev.retrotv.data.enums.EncodeFormat.*
import dev.retrotv.data.utils.*

/**
 * 양방향 암호화 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
interface TwoWayEncryption {

    /**
     * 데이터를 암호화 하고, 암호화 된 데이터를 반환 합니다.
     *
     * @param data 암호화 할 데이터
     * @param params 암호화 시, 사용할 매개변수
     * @return 암호화 결과가 담긴 객체
     */
    @Throws(CryptoFailException::class)
    fun encrypt(data: ByteArray, params: Params): Result

    /**
     * 암호화 된 데이터를 복호화 하고, 복호화 된 데이터를 반환 합니다.
     *
     * @param encryptedData 암호화 된 데이터
     * @param params 복호화 시, 사용할 매개변수
     * @return 복호화 결과가 담긴 객체
     */
    @Throws(CryptoFailException::class)
    fun decrypt(encryptedData: ByteArray, params: Params): Result
}
