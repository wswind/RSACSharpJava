package com.example.test;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.security.KeyFactory;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Base64;

import javax.crypto.Cipher;

public class Main {

    public static PrivateKey loadPrivateKey(String resourcePath) throws Exception {
        try (InputStream is = RsaKeyLoader.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + resourcePath);
            }
            String privateKeyPem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            String privateKeyPEM = privateKeyPem
                    .replace("-----BEGIN PRIVATE KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PRIVATE KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(privateKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            PKCS8EncodedKeySpec keySpec = new PKCS8EncodedKeySpec(encoded);
            return keyFactory.generatePrivate(keySpec);
        }
    }

    public static PublicKey loadPublicKey(String resourcePath) throws Exception {
        try (InputStream is = RsaKeyLoader.class.getClassLoader().getResourceAsStream(resourcePath)) {
            if (is == null) {
                throw new IllegalArgumentException("Resource not found: " + resourcePath);
            }
            String publicKeyPem = new String(is.readAllBytes(), StandardCharsets.UTF_8);
            String publicKeyPEM = publicKeyPem
                    .replace("-----BEGIN PUBLIC KEY-----", "")
                    .replaceAll(System.lineSeparator(), "")
                    .replace("-----END PUBLIC KEY-----", "");

            byte[] encoded = Base64.getDecoder().decode(publicKeyPEM);
            KeyFactory keyFactory = KeyFactory.getInstance("RSA");
            X509EncodedKeySpec keySpec = new X509EncodedKeySpec(encoded);
            return keyFactory.generatePublic(keySpec);
        }
    }

    public static void main(String[] args) throws Exception {
        String privateKeyPath = "private_key.pem";
        String publicKeyPath = "public_key.pem";

        PrivateKey privateKey = loadPrivateKey(privateKeyPath);
        PublicKey publicKey = loadPublicKey(publicKeyPath);

        String transformation = "RSA/ECB/PKCS1Padding";

        // 加密
        String text = "Hello, RSA!";
        System.out.println("text: " + text);
        byte[] data = text.getBytes(StandardCharsets.UTF_8);


        Cipher encryptCipher = Cipher.getInstance(transformation);
        encryptCipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedData = encryptCipher.doFinal(data);

        String base64EncryptedData = Base64.getEncoder().encodeToString(encryptedData);
        System.out.println("Encrypted data: " + base64EncryptedData);

        // 测试
        // String base64EncryptedData = "HLNfqN1UW+/irfuy7nOMayYEWavkcgoBDP/0K4K5jVLpYul3402WMO2cf4q9idlCLFP6w5GwR7vHnemENh0Gy9axKsGTnNturEK60UEp/UmvRG+RE4Rcf3Wou756N/QXBqnbeT5SE7I4a+gRRLv1r97QyE6MR7sbTSvfFRg2PTLep6fl4LNbRF2KPSxGcKG66/DgnCtrbMg9Zz76lHrwOT21MbjD/dcC8osESE/7wTwKhFxFEAHk/6YrYLnrR0rji0+m2yDmQ1l4EgTwbF1pKnS8CDqpUB3yE0m9oQHQyzK+qWHK5afl6TIWlsdBIY0qNbdUgx/Qfx/SivGb8aHsRQ==";
        // byte[] encryptedData = Base64.getDecoder().decode(base64EncryptedData);

        // 解密
        Cipher decryptCipher = Cipher.getInstance(transformation);
        decryptCipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedData = decryptCipher.doFinal(encryptedData);

        String decryptedText = new String(decryptedData, StandardCharsets.UTF_8);
        System.out.println("Decrypted text: " + decryptedText);
    }
}