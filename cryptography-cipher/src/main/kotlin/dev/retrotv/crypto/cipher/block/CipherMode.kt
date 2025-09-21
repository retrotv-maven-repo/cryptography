package dev.retrotv.crypto.cipher.block

import dev.retrotv.crypto.cipher.TwoWayEncryption
import dev.retrotv.crypto.cipher.enums.EMode
import org.slf4j.LoggerFactory

/**
 * 암호화 모드 구현을 위한 추상 클래스 입니다.
 * @param mode 암호화 모드
 * @param blockCipher 블록 암호화 클래스
 */
abstract class CipherMode(val mode: EMode, blockCipher: BlockCipher) : TwoWayEncryption {
    private val log = LoggerFactory.getLogger(this::class.java)
    val algorithm = blockCipher.algorithm
    protected var engine = blockCipher.engine
}