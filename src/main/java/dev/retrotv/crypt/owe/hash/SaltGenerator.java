package dev.retrotv.crypt.owe.hash;

import dev.retrotv.enums.SecurityStrength;

public interface SaltGenerator {

    /**
     * 소금을 생성하고 반환합니다.
     * 보안 강도와 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @return 생성된 소금
     */
    String generateSalt();

    /**
     * len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     * 보안 강도는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param len 생성할 소금의 길이
     * @return 생성된 소금
     */
    String generateSalt(int len);

    /**
     * securityStrength 수준의 소금을 생성하고 반환합니다.
     * 소금의 길이는 RandomValue에서 지정한 기본 값으로 설정됩니다.
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @return 생성된 소금
     */
    String generateSalt(SecurityStrength securityStrength);

    /**
     * securityStrength의 수준과 len 만큼의 길이를 가진 소금을 생성하고 반환합니다.
     *
     * @param securityStrength 보안 강도, {@link SecurityStrength} 참조
     * @param len 생성할 소금의 길이
     * @return 생성된 소금
     */
    String generateSalt(SecurityStrength securityStrength, int len);
}
