package dev.retrotv.crypto.owe.hash.sha

import dev.retrotv.crypto.owe.hash.Hash
import dev.retrotv.data.utils.toHexString
import dev.retrotv.enums.Algorithm.Hash.SHA3512
import dev.retrotv.utils.digest

class SHA3512 : Hash() {

    override fun hash(data: ByteArray): String {
        return toHexString(digest(SHA3512, data))
    }
}