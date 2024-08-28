package dev.retrotv.crypto.util

import dev.retrotv.random.ByteGenerator
import dev.retrotv.random.PasswordGenerator
import dev.retrotv.random.enums.SecurityStrength
import dev.retrotv.random.enums.SecurityStrength.MIDDLE
import java.security.SecureRandom
import java.util.*

object RandomGenerateUtils {

    @JvmStatic
    @JvmOverloads
    fun generateBytes(
        length: Int = 16,
        random: Random = SecureRandom()
    ): ByteArray {
        val generator = ByteGenerator(random)
        return generator.generate(length)
    }

    @JvmStatic
    @JvmOverloads
    fun generateString(
        length: Int = 16,
        secureStrength: SecurityStrength = MIDDLE,
        random: Random = SecureRandom()
    ): String {
        val generator = PasswordGenerator(secureStrength, random)
        return generator.generate(length)
    }
}
