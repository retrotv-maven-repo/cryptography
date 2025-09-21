package dev.retrotv.crypto.cipher.block.vector;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.algorithm.ARIA;
import dev.retrotv.crypto.cipher.block.algorithm.LEA;
import dev.retrotv.crypto.cipher.block.mode.GCM;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.AEADResult;
import dev.retrotv.crypto.cipher.result.Result;
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

class GCMTest {
    private byte[] hexToBytes(String hex) throws Exception { return StringUtils.hexToByteArray(hex); }
    private String bytesToHex(byte[] bytes) { return ByteUtils.toHexString(bytes).toUpperCase(); }

    private static final Logger log = LoggerFactory.getLogger(GCMTest.class);
    private static final String[] ALGORITHM = {"ARIA", "LEA"};
    private static final int[] KEY_LENGTH = {128, 192, 256};

    @TestFactory
    Stream<DynamicTest> test_gcmAd() {
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
                File file = new File("src/vector/" + algorithm + "/GCM_" + algorithm + "-" + keyLength + "_AD.txt");
                List<String> lines;
                try { lines = java.nio.file.Files.readAllLines(file.toPath()); } catch (Exception e) { continue; }
                String count = "", key = "", iv = "", aData = "", c = "", t = "", pt = "";
                for (String line : lines) {
                    line = line.trim();
                    if (line.startsWith("COUNT =")) count = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("Key =")) key = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("IV =")) iv = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("Adata =")) aData = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("C =")) c = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("T =")) t = line.substring(line.indexOf('=')+1).trim();
                    else if (line.startsWith("P =") || line.startsWith("Invalid")) {
                        if (line.startsWith("P =")) pt = line.substring(line.indexOf('=')+1).trim();
                        String testName = "CCM-" + algorithm + "-" + keyLength + "-AD COUNT=" + count;
                        log.info("COUNT: {}", count);
                        log.info("K: {}", key);
                        log.info("N: {}", iv);
                        log.info("A: {}", aData);
                        log.info("C: {}", c);
                        log.info("Tlen: {}", t);
                        log.info("P: {}", pt);
                        log.info("Invalid: {}", pt.isEmpty() ? "true" : "false");
                        log.info("테스트 명: {}", testName);

                        String finalAData = aData;
                        String finalKey = key;
                        String finalIv = iv;
                        String finalPt = pt;
                        String finalC = c;

                        tests.add(DynamicTest.dynamicTest(testName, () -> {
                            GCM gcm = new GCM(blockCipher);
                            gcm.updateAAD(hexToBytes(finalAData));
                            ParamWithIV params = new ParamWithIV(hexToBytes(finalKey), hexToBytes(finalIv));
                            byte[] result = gcm.encrypt(hexToBytes(finalPt), params).getData();
                            String resultHex = bytesToHex(result);
                            if (!finalPt.isEmpty()) {
                                Assertions.assertEquals(finalC.toUpperCase(), resultHex, "Failed at " + testName);
                            } else {
                                Assertions.assertNotEquals(finalC.toUpperCase(), resultHex, "Failed at " + testName);
                            }
                        }));
                    }
                }
            }
        }
        return tests.stream();
    }

    @TestFactory
    Stream<DynamicTest> test_gcmAe() {
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
                File file = new File("src/vector/" + algorithm + "/GCM_" + algorithm + "-" + keyLength + "_AE.txt");
                List<String> lines;
                try {
                    lines = java.nio.file.Files.readAllLines(file.toPath());
                } catch (Exception e) {
                    continue;
                }

                String count = "";
                String key = "";
                String iv = "";
                String pt = "";
                String aData = "";
                String c = "";
                String t = "";

                for (String line : lines) {
                    line = line.trim();
                    if (line.startsWith("COUNT =")) {
                        count = line.substring(line.indexOf('=') + 1).trim();
                    } else if (line.startsWith("Key =")) {
                        key = line.substring(line.indexOf('=') + 1).trim();
                    } else if (line.startsWith("IV =")) {
                        iv = line.substring(line.indexOf('=') + 1).trim();
                    } else if (line.startsWith("PT =")) {
                        pt = line.substring(line.indexOf('=') + 1).trim();
                    } else if (line.startsWith("Adata =")) {
                        aData = line.substring(line.indexOf('=') + 1).trim();
                    } else if (line.startsWith("C =")) {
                        c = line.substring(line.indexOf('=') + 1).trim();
                    } else if (line.startsWith("T =")) {
                        t = line.substring(line.indexOf('=') + 1).trim();
                        String testName = "CCM-" + algorithm + "-" + keyLength + "-AE COUNT=" + count;

                        log.info("COUNT: {}", count);
                        log.info("Key: {}", key);
                        log.info("IV: {}", iv);
                        log.info("PT: {}", pt);
                        log.info("Adata: {}", aData);
                        log.info("C: {}", c);
                        log.info("T: {}", t);
                        log.info("테스트 명: {}", testName);

                        String finalAData = aData;
                        String finalKey = key;
                        String finalIv = iv;
                        String finalPt = pt;
                        String finalC = c;
                        String finalT = t;

                        tests.add(DynamicTest.dynamicTest(testName, () -> {
                            GCM gcm = new GCM(blockCipher);
                            gcm.updateAAD(hexToBytes(finalAData));
                            ParamWithIV params = new ParamWithIV(hexToBytes(finalKey), hexToBytes(finalIv));
                            Result result = gcm.encrypt(hexToBytes(finalPt), params);
                            String resultHex = bytesToHex(result.getData());
                            String resultTag = bytesToHex(((AEADResult) result).getTag());

                            Assertions.assertEquals(finalC.toUpperCase(), resultHex.replace(resultTag, ""), "Failed at " + testName);
                        }));
                    }
                }
            }
        }
        return tests.stream();
    }
}

