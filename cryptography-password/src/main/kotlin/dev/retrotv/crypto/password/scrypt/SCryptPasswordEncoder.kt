package dev.retrotv.crypto.password.scrypt

import dev.retrotv.crypto.password.PasswordEncoder
import org.springframework.security.crypto.scrypt.SCryptPasswordEncoder

class SCryptPasswordEncoder : PasswordEncoder {
    private var encoder: SCryptPasswordEncoder

    constructor() {
        encoder = SCryptPasswordEncoder(65536, 8, 1, 32, 64)
    }

    constructor(cpuCost: Int, memoryCost: Int, parallelization: Int, keyLength: Int, saltLength: Int) {
        encoder = SCryptPasswordEncoder(cpuCost, memoryCost, parallelization, keyLength, saltLength)
    }

    override fun encode(rawPassword: CharSequence): String {
        return encoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return encoder.matches(rawPassword, encodedPassword)
    }
}