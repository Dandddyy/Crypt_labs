package org.example;

import org.bouncycastle.crypto.engines.TwofishEngine;
import org.bouncycastle.crypto.modes.CBCBlockCipher;
import org.bouncycastle.crypto.paddings.PaddedBufferedBlockCipher;
import org.bouncycastle.crypto.params.KeyParameter;
import org.bouncycastle.crypto.params.ParametersWithIV;
import org.bouncycastle.jce.provider.BouncyCastleProvider;

import java.security.Security;
import java.util.Base64;

public class SimpleTwofish {
    static {
        Security.addProvider(new BouncyCastleProvider());
    }

    public static String encrypt(String data, byte[] key, byte[] iv) throws Exception {
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
        cipher.init(true, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] input = data.getBytes();
        byte[] encrypted = new byte[cipher.getOutputSize(input.length)];
        int olen = cipher.processBytes(input, 0, input.length, encrypted, 0);
        cipher.doFinal(encrypted, olen);
        return Base64.getEncoder().encodeToString(encrypted);
    }

    public static String decrypt(String encryptedData, byte[] key, byte[] iv) throws Exception {
        byte[] decodedData = Base64.getDecoder().decode(encryptedData);
        PaddedBufferedBlockCipher cipher = new PaddedBufferedBlockCipher(new CBCBlockCipher(new TwofishEngine()));
        cipher.init(false, new ParametersWithIV(new KeyParameter(key), iv));
        byte[] out = new byte[cipher.getOutputSize(decodedData.length)];
        int olen = cipher.processBytes(decodedData, 0, decodedData.length, out, 0);
        olen += cipher.doFinal(out, olen);
        return new String(out, 0, olen);
    }

    public static void main(String[] args) {
        try {
            String original = "Hello, world!";
            byte[] key = new byte[32]; // 256 bits key
            byte[] iv = new byte[16];

            System.out.println("Original: " + original);

            // Encrypt
            String encrypted = encrypt(original, key, iv);
            System.out.println("Encrypted: " + encrypted);

            // Decrypt
            String decrypted = decrypt(encrypted, key, iv);
            System.out.println("Decrypted: " + decrypted);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }
}
