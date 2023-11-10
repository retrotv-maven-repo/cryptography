package dev.retrotv.crypto.twe

import java.security.spec.AlgorithmParameterSpec

/**
 * 암호화 알고리즘 파라미터 스펙 생성 메소드 구현을 위한 인터페이스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
fun interface ParameterSpecGenerator<T : AlgorithmParameterSpec> {

    /**
     * 암호화 시, 사용 될 초기화 벡터를 생성하고 반환합니다.
     *
     * @return 생성된 초기화 벡터 spec
     */
    fun generateSpec(): T
}
