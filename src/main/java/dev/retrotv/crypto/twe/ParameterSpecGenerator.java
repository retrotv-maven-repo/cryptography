package dev.retrotv.crypto.twe;

import java.security.spec.AlgorithmParameterSpec;

public interface ParameterSpecGenerator<T extends AlgorithmParameterSpec> {

    /**
     * 암호화 시, 사용 될 초기화 벡터를 생성하고 반환합니다.
     *
     * @return 생성된 초기화 벡터 spec
     */
    T generateSpec();
}
