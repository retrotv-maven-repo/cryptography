package dev.retrotv.crypto.twe.lea

import dev.retrotv.crypto.common.ExtendedSecretKeySpec
import dev.retrotv.enums.Algorithm
import dev.retrotv.enums.Padding
import dev.retrotv.utils.generate
import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.bouncycastle.crypto.engines.LEAEngine
import java.security.Key

val log: Logger = LogManager.getLogger()

/**
 * LEA 계열의 양방향 암호화 구현을 위한 상속용 클래스 입니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
abstract class LEA {
    protected val engine = LEAEngine()
    protected var keyLen = 0
    protected lateinit var algorithm: Algorithm.Cipher
    protected var padding = Padding.NO_PADDING

    /**
     * 데이터를 패딩하도록 설정합니다.
     * 기본적으로 PKCS#5 Padding을 사용합니다.
     */
    fun dataPadding() {
        padding = Padding.PKCS5_PADDING
    }

    fun generateKey(): Key {
        return ExtendedSecretKeySpec(generate(keyLen / 8), "LEA")
    }
}
