package dev.retrotv.crypto.password.argon2

import dev.retrotv.crypto.password.PasswordEncoder
import org.springframework.security.crypto.argon2.Argon2PasswordEncoder

class Argon2PasswordEncoder : PasswordEncoder {
    private val encoder: Argon2PasswordEncoder

    constructor() {
        this.encoder = Argon2PasswordEncoder(16, 32 , 1, 16384, 2 )
    }

    constructor(saltLength: Int, hashLength: Int, parallelism: Int, memory: Int, iterations: Int) {
        this.encoder = Argon2PasswordEncoder(saltLength, hashLength, parallelism, memory, iterations)
    }

    override fun encode(rawPassword: CharSequence): String {
        return this.encoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return this.encoder.matches(rawPassword, encodedPassword)
    }
}