package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.data.utils.toHexString
import dev.retrotv.enums.Algorithm.Hash.SHA3256
import dev.retrotv.utils.digest

class SHA3256 : Hash() {

    override fun hash(data: ByteArray): String {
        return toHexString(digest(SHA3256, data))
    }
}