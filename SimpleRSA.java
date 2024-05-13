package org.example;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Base64;

import javax.crypto.Cipher;

public class SimpleRSA {
    private PublicKey publicKey;
    private PrivateKey privateKey;

    public SimpleRSA() throws NoSuchAlgorithmException {
        KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA");
        keyGen.initialize(2048);
        KeyPair pair = keyGen.generateKeyPair();
        this.publicKey = pair.getPublic();
        this.privateKey = pair.getPrivate();
    }

    public String encrypt(String message) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.ENCRYPT_MODE, publicKey);
        byte[] encryptedBytes = cipher.doFinal(message.getBytes());
        return Base64.getEncoder().encodeToString(encryptedBytes);
    }

    public String decrypt(String encryptedMessage) throws Exception {
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(Base64.getDecoder().decode(encryptedMessage));
        return new String(decryptedBytes);
    }

    public static void main(String[] args) {
        try {
            SimpleRSA rsa = new SimpleRSA();
            String originalMessage = "Hello, world!";
            String encryptedMessage = rsa.encrypt(originalMessage);
            String decryptedMessage = rsa.decrypt(encryptedMessage);

            System.out.println("Original: " + originalMessage);
            System.out.println("Encrypted: " + encryptedMessage);
            System.out.println("Decrypted: " + decryptedMessage);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
