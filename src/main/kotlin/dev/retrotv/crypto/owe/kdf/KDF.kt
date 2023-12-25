package dev.retrotv.crypto.owe.kdf

import org.apache.logging.log4j.LogManager
import org.apache.logging.log4j.Logger
import org.springframework.security.crypto.password.PasswordEncoder

/**
 * 패스워드 암호화 클래스 구현을 위한 추상 클래스입니다.
 * [PasswordEncoder] 인터페이스를 상속받습니다.
 *
 * @author  yjj8353
 * @since   1.0.0
 */
abstract class KDF : PasswordEncoder {
    protected val log: Logger = LogManager.getLogger(this.javaClass)
}
