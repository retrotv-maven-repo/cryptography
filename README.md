# Cryptography
[![](https://jitpack.io/v/retrotv-maven-repo/cryptography.svg)](https://jitpack.io/#retrotv-maven-repo/cryptography)

Java 및 Kotlin에서 사용할 수 있는 암호화 라이브러리 입니다.

## 지원 JDK
JDK 1.8 이상

## 지원하는 알고리즘

### KDF(키 유도 함수) 계열
- Argon2
- BCrypt
- Pbkdf2
- SCrypt

### Hash(해시) 계열
- CRC-32
- MD2
- MD5
- SHA-1
- SHA-224
- SHA-256
- SHA-384
- SHA-512
- SHA-512/224
- SHA-512/256

### AES 알고리즘
- AES-128 (ECB, CBC, CFB, OFB, CRT, CTS, GCM)
- AES-192 (ECB, CBC, CFB, OFB, CRT, CTS, GCM)
- AES-256 (ECB, CBC, CFB, OFB, CRT, CTS, GCM)
#### ECB, CBC 모드는 PKCS#5 Padding을 기본으로 사용

### LEA 알고리즘
- LEA-128 (ECB, CBC, CCM, CFB, OFB, CRT, GCM)
- LEA-192 (ECB, CBC, CCM, CFB, OFB, CRT, GCM)
- LEA-256 (ECB, CBC, CCM, CFB, OFB, CRT, GCM)
#### ECB, CBC 모드는 PKCS#5 Padding을 기본으로 사용

### RSA 계열
- RSA-1024 (OAEPWITHSHA-256ANDMGF1PADDING, SHA256withRSA)
- RSA-2048 (OAEPWITHSHA-256ANDMGF1PADDING, SHA256withRSA)

## 사용법
```
// 해시 (체크섬)
Hash checksum = new SHA256();
checksum.hash(new File(filePath));

// 해시 (패스워드 + 소금 암호화)
Hash password = new SHA256();
password.encode(myPassword, salt);

// 키 유도 함수 (패스워드 암호화)
Password password = new BCrypt();
password.encode(myPassword);

// 양방향 암호화 (암/복호화)
TwoWayEncryption twe = new AESCBC(128);
byte[] encryptedData = twe.encrypt(data, key, iv);
byte[] originalData = twe.decrypt(encryptedData, key, iv);

// 양방향 암호화 (전자서명)
DigitalSignature ds = new RSA2048();
byte[] encryptedData = ds.sign(data, privateKey);
boolean verifyResult = ds.verify(encryptedData, publicKey);
```
