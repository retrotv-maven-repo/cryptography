package dev.retrotv.crypto.cipher.block.vector;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.algorithm.ARIA;
import dev.retrotv.crypto.cipher.block.algorithm.LEA;
import dev.retrotv.crypto.cipher.block.mode.CCM;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.data.utils.ByteUtils;
import dev.retrotv.data.utils.StringUtils;
import org.junit.jupiter.api.Assertions;
import org.junit.jupiter.api.DynamicTest;
import org.junit.jupiter.api.TestFactory;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import java.io.File;
import java.util.ArrayList;
import java.util.List;
import java.util.stream.Stream;

class JCCMTest {
    private byte[] hexToBytes(String hex) throws Exception { return StringUtils.hexToByteArray(hex); }
    private String bytesToHex(byte[] bytes) { return ByteUtils.toHexString(bytes).toUpperCase(); }

    private static final Logger log = LoggerFactory.getLogger(JCCMTest.class);
    private static final String[] ALGORITHM = {"ARIA", "LEA"};
    private static final int[] KEY_LENGTH = {128, 192, 256};

    @TestFactory
    Stream<DynamicTest> test_ccmDv() {
        List<DynamicTest> tests = new ArrayList<>();

        for (String algorithm : ALGORITHM) {
            BlockCipher blockCipher;
            if (algorithm.equals("ARIA")) {
                blockCipher = new ARIA();
            } else if (algorithm.equals("LEA")) {
                blockCipher = new LEA();
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }

            for (int keyLength : KEY_LENGTH) {
                File file = new File("src/vector/" + algorithm + "/CCM_" + algorithm + "-" + keyLength + "_DV.txt");
                List<String> lines;
                try {
                    lines = java.nio.file.Files.readAllLines(file.toPath());
                } catch (Exception e) {
                    continue;
                }

                String count = "";
                String k = "";
                String n = "";
                String a = "";
                String c = "";
                int tLen = 0;
                String p = "";

                for (String line : lines) {
                    line = line.trim();
                    String trim = line.substring(line.indexOf('=') + 1).trim();
                    if (line.startsWith("COUNT =")) {
                        count = trim;
                    } else if (line.startsWith("K =")) {
                        k = trim;
                    } else if (line.startsWith("N =")) {
                        n = trim;
                    } else if (line.startsWith("A =")) {
                        a = trim;
                    } else if (line.startsWith("C =")) {
                        c = trim;
                    } else if (line.startsWith("Tlen =")) {
                        tLen = Integer.parseInt(trim) / 8;
                    } else if (line.startsWith("P =") || line.startsWith("INVALID")) {
                        if (line.startsWith("P =")) {
                            p = trim;
                        }
                        if (line.startsWith("P =") || line.startsWith("INVALID")) {
                            String testName = "CCM-" + algorithm + "-" + keyLength + "-DV COUNT=" + count;
                            String finalA = a;
                            String finalK = k;
                            String finalN = n;
                            String finalC = c;
                            int finalTLen = tLen;
                            String finalP = p;

                            tests.add(DynamicTest.dynamicTest(testName, () -> {
                                CCM ccm = new CCM(blockCipher);
                                ccm.updateAAD(hexToBytes(finalA));
                                ccm.updateTagLength(finalTLen);
                                ParamWithIV params = new ParamWithIV(hexToBytes(finalK), hexToBytes(finalN));
                                byte[] result = ccm.encrypt(hexToBytes(finalP), params).getData();
                                String resultHex = bytesToHex(result);

                                if (!finalP.isEmpty()) {
                                    Assertions.assertEquals(finalC.toUpperCase(), resultHex, "Failed at " + testName);
                                } else {
                                    Assertions.assertNotEquals(finalC.toUpperCase(), resultHex, "Failed at " + testName);
                                }
                            }));
                            p = "";
                        }
                    }
                }
            }
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> test_ccmGe() {
        List<DynamicTest> tests = new ArrayList<>();

        for (String algorithm : ALGORITHM) {
            BlockCipher blockCipher;
            if (algorithm.equals("ARIA")) {
                blockCipher = new ARIA();
            } else if (algorithm.equals("LEA")) {
                blockCipher = new LEA();
            } else {
                throw new IllegalArgumentException("Unsupported algorithm: " + algorithm);
            }

            for (int keyLength : KEY_LENGTH) {
                File file = new File("src/vector/" + algorithm + "/CCM_" + algorithm + "-" + keyLength + "_GE.txt");
                List<String> lines;
                try {
                    lines = java.nio.file.Files.readAllLines(file.toPath());
                } catch (Exception e) {
                    continue;
                }

                String count = "";
                String k = "";
                String n = "";
                String a = "";
                String p = "";
                int tLen = 0;
                String c;

                for (String line : lines) {
                    line = line.trim();
                    String trim = line.substring(line.indexOf('=') + 1).trim();
                    if (line.startsWith("COUNT =")) {
                        count = trim;
                    } else if (line.startsWith("K =")) {
                        k = trim;
                    } else if (line.startsWith("N =")) {
                        n = trim;
                    } else if (line.startsWith("A =")) {
                        a = trim;
                    } else if (line.startsWith("P =")) {
                        p = trim;
                    } else if (line.startsWith("Tlen =")) {
                        tLen = Integer.parseInt(trim) / 8;
                    } else if (line.startsWith("C =")) {
                        c = trim;
                        String testName = "CCM-" + algorithm + "-" + keyLength + "-GE COUNT=" + count;

                        String finalA = a;
                        String finalK = k;
                        String finalN = n;
                        String finalC = c;
                        int finalTLen = tLen;
                        String finalP = p;

                        tests.add(DynamicTest.dynamicTest(testName, () -> {
                            CCM ccm = new CCM(blockCipher);
                            ccm.updateAAD(hexToBytes(finalA));
                            ccm.updateTagLength(finalTLen);
                            ParamWithIV params = new ParamWithIV(hexToBytes(finalK), hexToBytes(finalN));
                            byte[] result = ccm.encrypt(hexToBytes(finalP), params).getData();
                            String resultHex = bytesToHex(result);

                            Assertions.assertEquals(finalC.toUpperCase(), resultHex, "Failed at " + testName);
                        }));
                    }
                }
            }
        }
        return tests.stream();
    }
}
