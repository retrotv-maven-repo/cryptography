package dev.retrotv.crypto.cipher.block.vector;

import dev.retrotv.crypto.cipher.block.BlockCipher;
import dev.retrotv.crypto.cipher.block.algorithm.ARIA;
import dev.retrotv.crypto.cipher.block.algorithm.LEA;
import dev.retrotv.crypto.cipher.block.mode.GCM;
import dev.retrotv.crypto.cipher.param.ParamWithIV;
import dev.retrotv.crypto.cipher.result.AEADResult;
import dev.retrotv.crypto.cipher.result.Result;
import dev.retrotv.crypto.exception.CryptoFailException;
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

import static java.nio.file.Files.readAllLines;
import static org.junit.jupiter.api.Assertions.assertThrows;

class GCMTest {
    private byte[] hexToBytes(String hex) throws Exception { return StringUtils.hexToByteArray(hex); }
    private String bytesToHex(byte[] bytes) { return ByteUtils.toHexString(bytes).toUpperCase(); }

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
                try {
                    lines = readAllLines(file.toPath());
                } catch (Exception e) { continue; }

                int tagLen = 0;

                String count = "";
                String key = "";
                String iv = "";
                String aData = "";
                String c = "";
                String pt = "";
                String t = "";

                for (String line : lines) {
                    line = line.trim();
                    String trim = line.substring(line.indexOf('=') + 1).trim();

                    if (line.startsWith("[TagLen =")) tagLen = Integer.parseInt(trim.replace("]", ""));
                    else if (line.startsWith("COUNT =")) count = trim;
                    else if (line.startsWith("Key =")) key = trim;
                    else if (line.startsWith("IV =")) iv = trim;
                    else if (line.startsWith("Adata =")) aData = trim;
                    else if (line.startsWith("C =")) c = trim;
                    else if (line.startsWith("T =")) t = trim;
                    else if (line.startsWith("PT =") || line.startsWith("Invalid")) {
                        if (line.startsWith("PT =")) pt = trim;
                        else if (line.startsWith("Invalid")) pt = "Invalid";

                        String testName = "GCM-" + algorithm + "-" + keyLength + "-AD COUNT=" + count;
                        int finalTagLen = tagLen;
                        String finalAData = aData;
                        String finalKey = key;
                        String finalIv = iv;
                        String finalPt = pt;
                        String finalC = c;
                        String finalT = t;

                        tests.add(DynamicTest.dynamicTest(testName, () -> {
                            GCM gcm = new GCM(blockCipher);
                            gcm.updateAAD(hexToBytes(finalAData));
                            gcm.updateTagLength(finalTagLen / 8);
                            ParamWithIV params = new ParamWithIV(hexToBytes(finalKey), hexToBytes(finalIv));

                            if (!"Invalid".equals(finalPt)) {
                                byte[] result = gcm.encrypt(hexToBytes(finalPt), params).getData();
                                String resultHex = bytesToHex(result);
                                Assertions.assertEquals(finalC.toUpperCase() + finalT, resultHex, "Encrypted fail at " + testName);

                                result = gcm.decrypt(hexToBytes(finalC + finalT), params).getData();
                                resultHex = bytesToHex(result);
                                Assertions.assertEquals(finalPt.toUpperCase(), resultHex, "Decrypted fail at " + testName);
                            } else {
                                byte[] htb = hexToBytes(finalC);
                                assertThrows(CryptoFailException.class, () -> {
                                    gcm.decrypt(htb, params);
                                });
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
                    lines = readAllLines(file.toPath());
                } catch (Exception e) { continue; }

                String count = "";
                String key = "";
                String iv = "";
                String pt = "";
                String aData = "";
                String c = "";

                for (String line : lines) {
                    line = line.trim();
                    String trim = line.substring(line.indexOf('=') + 1).trim();
                    if (line.startsWith("COUNT =")) count = trim;
                    else if (line.startsWith("Key =")) key = trim;
                    else if (line.startsWith("IV =")) iv = trim;
                    else if (line.startsWith("PT =")) pt = trim;
                    else if (line.startsWith("Adata =")) aData = trim;
                    else if (line.startsWith("C =")) c = trim;
                    else if (line.startsWith("T =")) {
                        String testName = "CCM-" + algorithm + "-" + keyLength + "-AE COUNT=" + count;
                        String finalAData = aData;
                        String finalKey = key;
                        String finalIv = iv;
                        String finalPt = pt;
                        String finalC = c;

                        tests.add(DynamicTest.dynamicTest(testName, () -> {
                            GCM gcm = new GCM(blockCipher);
                            gcm.updateAAD(hexToBytes(finalAData));
                            ParamWithIV params = new ParamWithIV(hexToBytes(finalKey), hexToBytes(finalIv));

                            Result result = gcm.encrypt(hexToBytes(finalPt), params);
                            String resultHex = bytesToHex(result.getData());
                            String resultTag = bytesToHex(((AEADResult) result).getTag());
                            Assertions.assertEquals(finalC.toUpperCase(), resultHex.replace(resultTag, ""), "Encrypted fail at " + testName);

                            result = gcm.decrypt(result.getData(), params);
                            resultHex = bytesToHex(result.getData());
                            Assertions.assertEquals(finalPt.toUpperCase(), resultHex, "Decrypted failed at " + testName);
                        }));
                    }
                }
            }
        }

        return tests.stream();
    }
}

