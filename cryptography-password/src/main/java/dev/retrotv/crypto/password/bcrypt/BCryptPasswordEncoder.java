package dev.retrotv.crypto.password.bcrypt;

import dev.retrotv.crypto.password.PasswordEncoder;
import dev.retrotv.crypto.password.enums.BCryptVersion;

import java.security.SecureRandom;

/**
 * BCrypt 해싱 함수를 사용하는 PasswordEncoder 구현.
 * BCryptPasswordEncoder는 라운드 횟수, 버전 및 SecureRandom 객체 매개변수를 제공할 수 있습니다.
 */
public class BCryptPasswordEncoder implements PasswordEncoder {
    private final org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder encoder;

    public BCryptPasswordEncoder() {
        this.encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder();
    }

    public BCryptPasswordEncoder(int strength) {
        this.encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(strength);
    }

    public BCryptPasswordEncoder(BCryptVersion version) {
        this.encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(selectVersion(version));
    }

    public BCryptPasswordEncoder(BCryptVersion version, SecureRandom random) {
        this.encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(selectVersion(version), random);
    }

    public BCryptPasswordEncoder(int strength, SecureRandom random) {
        this.encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(strength, random);
    }

    public BCryptPasswordEncoder(BCryptVersion version, int strength) {
        this.encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(selectVersion(version), strength);
    }

    public BCryptPasswordEncoder(BCryptVersion version, int strength, SecureRandom random) {
        this.encoder = new org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder(selectVersion(version), strength, random);
    }

    @Override
    public String encode(CharSequence rawPassword) {
        return this.encoder.encode(rawPassword);
    }

    @Override
    public boolean matches(CharSequence rawPassword, String encodedPassword) {
        return this.encoder.matches(rawPassword, encodedPassword);
    }

    private org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion selectVersion(BCryptVersion version) {
        switch (version) {
            case $2A: return org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion.$2A;
            case $2Y: return org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion.$2Y;
            case $2B: return org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder.BCryptVersion.$2B;
            default: throw new IllegalArgumentException("Unknown BCryptVersion: " + version);
        }
    }
}

