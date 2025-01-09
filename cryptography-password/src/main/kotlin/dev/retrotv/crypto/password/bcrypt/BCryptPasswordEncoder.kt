package dev.retrotv.crypto.password.bcrypt

import dev.retrotv.crypto.password.PasswordEncoder
import dev.retrotv.crypto.password.enums.BCryptVersion
import dev.retrotv.crypto.password.enums.BCryptVersion.`$2A`
import dev.retrotv.crypto.password.enums.BCryptVersion.`$2B`
import dev.retrotv.crypto.password.enums.BCryptVersion.`$2Y`
import org.springframework.security.crypto.bcrypt.BCryptPasswordEncoder
import java.security.SecureRandom

class BCryptPasswordEncoder : PasswordEncoder {
    private val encoder: BCryptPasswordEncoder

    constructor() {
        this.encoder = BCryptPasswordEncoder()
    }

    constructor(strength: Int) {
        this.encoder = BCryptPasswordEncoder(strength)

    }

    constructor(version: BCryptVersion) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version))
    }

    constructor(version: BCryptVersion, random: SecureRandom) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version), random)
    }

    constructor(strength: Int, random: SecureRandom) {
        this.encoder = BCryptPasswordEncoder(strength, random)
    }

    constructor(version: BCryptVersion, strength: Int) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version), strength)
    }

    constructor(version: BCryptVersion, strength: Int, random: SecureRandom) {
        this.encoder = BCryptPasswordEncoder(selectVersion(version), strength, random)
    }

    override fun encode(rawPassword: CharSequence): String {
        return this.encoder.encode(rawPassword)
    }

    override fun matches(rawPassword: CharSequence, encodedPassword: String?): Boolean {
        return this.encoder.matches(rawPassword, encodedPassword)
    }

    private fun selectVersion(version: BCryptVersion): BCryptPasswordEncoder.BCryptVersion {
        return when (version) {
            `$2A` -> BCryptPasswordEncoder.BCryptVersion.`$2A`
            `$2Y` -> BCryptPasswordEncoder.BCryptVersion.`$2Y`
            `$2B` -> BCryptPasswordEncoder.BCryptVersion.`$2B`
        }
    }
}