package dev.retrotv.crypto.cipher.block

import dev.retrotv.crypto.cipher.enums.ECipher
import org.bouncycastle.crypto.BlockCipher

/**
 * 블록 암호화 알고리즘 구현을 위한 추상 클래스 입니다.
 */
abstract class BlockCipher {
    lateinit var engine: BlockCipher
    lateinit var algorithm: ECipher
}