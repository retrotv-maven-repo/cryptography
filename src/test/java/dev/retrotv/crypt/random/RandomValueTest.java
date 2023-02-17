package dev.retrotv.crypt.random;

import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

public class RandomValueTest {
    private final static Logger log = Logger.getGlobal();

    @Test
    @DisplayName("낮은 보안 수준의 랜덤 값 생성")
    void generateLowStrengthRandomValue() {
        String randomValue = RandomValue.generate(SecurityStrength.LOW, 200);
        log.info(randomValue);

        assertNotNull(randomValue);
    }

    @Test
    @DisplayName("중간 보안 수준의 랜덤 값 생성")
    void generateMiddleStrengthRandomValue() {
        String randomValue = RandomValue.generate(SecurityStrength.MIDDLE, 200);
        log.info(randomValue);

        assertNotNull(randomValue);
    }

    @Test
    @DisplayName("높은 보안 수준의 랜덤 값 생성")
    void generateHighStrengthRandomValue() {
        String randomValue = RandomValue.generate(SecurityStrength.HIGH, 200);
        log.info(randomValue);

        assertNotNull(randomValue);
    }
}
