package dev.retrotv.crypto.password;

public interface PasswordEncoder {

    /**
     * 비밀번호를 암호화하여 반환합니다.
     *
     * @param rawPassword 암호화 할 비밀번호
     * @return 암호화 된 비밀번호
     */
    /* @Nullable */ String encode(/* @Nullable */ CharSequence rawPassword);

    /**
     * 암호화 된 비밀번호와 입력받은 비밀번호를 비교하고 일치 여부를 반환합니다.
     *
     * @param rawPassword 비교할 비밀번호
     * @param encodedPassword 암호화 된 비밀번호
     * @return 비밀번호 일치여부
     */
    boolean matches(/* @Nullable */ CharSequence rawPassword, /* @Nullable */ String encodedPassword);

    /**
     * 보안 강화를 위해 인코딩된 비밀번호를 다시 인코딩해야 하는 경우 true를 반환합니다.
     * 그렇지 않으면 false입니다. 기본 구현은 항상 false를 반환합니다.
     *
     * @param encodedPassword 확인할 인코딩된 비밀번호
     * @return 보안 강화를 위해 인코딩된 비밀번호를 다시 인코딩해야 하는 경우 true를 반환합니다.
     *         그렇지 않으면 false입니다.
     */
    default boolean upgradeEncoding(/* @Nullable */ String encodedPassword) {
        return false;
    }
}
