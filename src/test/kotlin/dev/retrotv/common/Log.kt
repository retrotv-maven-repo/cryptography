package dev.retrotv.common

import org.junit.jupiter.api.BeforeAll
import java.util.logging.ConsoleHandler
import java.util.logging.Logger

open class Log {
    companion object {

        @JvmStatic
        protected val log: Logger = Logger.getGlobal()

        @JvmStatic
        @BeforeAll
        fun setLoggerFormatter(): Unit {
            log.setUseParentHandlers(false)
            val formatter = LogFormatter()
            val handler = ConsoleHandler()
            handler.setFormatter(formatter)
            log.addHandler(handler)
        }
    }
}
