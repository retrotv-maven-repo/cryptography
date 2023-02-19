package dev.retrotv.common;

import org.junit.jupiter.api.BeforeAll;

import java.util.logging.ConsoleHandler;
import java.util.logging.Logger;

public class Log {
    protected static final Logger log = Logger.getGlobal();

    @BeforeAll
    static void setLoggerFormatter() {
        log.setUseParentHandlers(false);
        LogFormatter formatter = new LogFormatter();
        ConsoleHandler handler = new ConsoleHandler();
        handler.setFormatter(formatter);
        log.addHandler(handler);
    }
}
