package dev.retrotv.enums

enum class Padding(private val label: String) {
    OAEP_WITH_SHA1_MGF1_PADDING("OAEPWithSHA-1AndMGF1Padding"),
    OAEP_WITH_SHA256_MGF1_PADDING("OAEPWithSHA-256AndMGF1Padding"),
    PKCS1_PADDING("PKCS1Padding"),
    PKCS5_PADDING("PKCS5Padding"),
    NO_PADDING("NoPadding");

    /**
     * 알고리즘의 label(이름)을 반환합니다.
     *
     * @return 알고리즘 명
     */
    fun label(): String {
        return label
    }
}
