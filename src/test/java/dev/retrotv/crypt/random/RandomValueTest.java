package dev.retrotv.crypt.random;

import dev.retrotv.enums.SecurityStrength;
import org.junit.jupiter.api.DisplayName;
import org.junit.jupiter.api.Test;

import java.util.logging.Logger;

import static org.junit.jupiter.api.Assertions.*;

public class RandomValueTest {
    private final static Logger log = Logger.getGlobal();

    @Test
    @DisplayName("낮은 보안 수준의 무작위 값 생성")
    void generateLowStrengthRandomValue() {
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.LOW, 200);
        log.info(rv.getValue());

        assertNotNull(rv.getValue());
    }

    @Test
    @DisplayName("중간 보안 수준의 무작위 값 생성")
    void generateMiddleStrengthRandomValue() {
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.MIDDLE, 200);
        log.info(rv.getValue());

        assertNotNull(rv.getValue());
    }

    @Test
    @DisplayName("높은 보안 수준의 무작위 값 생성")
    void generateHighStrengthRandomValue() {
        RandomValue rv = new RandomValue();
        rv.generate(SecurityStrength.HIGH, 200);
        log.info(rv.getValue());

        assertNotNull(rv.getValue());
    }
}
