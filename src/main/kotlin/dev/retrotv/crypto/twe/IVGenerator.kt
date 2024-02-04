package dev.retrotv.crypto.twe

/**
 * 초기화 벡터(IV) 생성 메소드 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
fun interface IVGenerator {

    /**
     * 암호화 시, 사용 될 초기화 벡터(IV)를 생성하고 반환합니다.
     *
     * @return 생성된 초기화 벡터
     */
    fun generateIV(): ByteArray
}
