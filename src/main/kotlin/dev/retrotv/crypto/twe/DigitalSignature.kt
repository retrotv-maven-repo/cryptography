package dev.retrotv.crypto.twe

import java.security.PrivateKey
import java.security.PublicKey

/**
 * 전자서명 클래스 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
interface DigitalSignature {

    /**
     * 전자서명을 생성하고 암호화 된 데이터를 반환합니다.
     *
     * @param data 암호화 할 데이터
     * @param privateKey 암호화 시, 사용할 개인 키
     * @return 암호화 된 데이터
     */
    fun sign(data: ByteArray, privateKey: PrivateKey): ByteArray

    /**
     * 전자서명을 복호화 하고 원본 데이터와 비교 후, 검증 성공 여부를 반환합니다.
     *
     * @param originalData 원본 데이터
     * @param encryptedData 개인키를 통해 암호화 된 데이터
     * @param publicKey 복호화 시, 사용할 공개 키
     * @return 검증 성공 여부
     */
    fun verify(originalData: ByteArray, encryptedData: ByteArray, publicKey: PublicKey): Boolean
}
