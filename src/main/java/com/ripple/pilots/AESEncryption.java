package com.ripple.pilots;

import org.bouncycastle.util.encoders.Hex;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import java.security.AlgorithmParameters;
import java.security.Key;
import java.security.KeyStore;
import java.util.Arrays;
import java.util.Random;

public class AESEncryption {

    public static void main(String[] args) throws Exception{

        String aesKeyLabel = "test_aes_wrappingkey_01";
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
        keyStoreManager.keyStoreLogin();
        KeyStore keyStore = keyStoreManager.getKeyStore();
        Key key = keyStore.getKey(aesKeyLabel, "crypto1".toCharArray());

        Cipher encCipher = null;
        Cipher decCipher = null;
        AlgorithmParameters lunaParams = null;
        byte[] iv = null;
        encCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        decCipher = Cipher.getInstance("AES/CBC/PKCS5Padding", "LunaProvider");
        iv = encCipher.getIV();
        if (iv == null) {
            // is AES ok for any secret key?
            lunaParams = AlgorithmParameters.getInstance("AES", "LunaProvider");
            //IvParameterSpec IV16 = new IvParameterSpec(new byte[] { 0x01, 0x02, 0x03, 0x04, 0x05, 0x06, 0x07, 0x08, 0x09,
            //        0x0A, 0x0B, 0x0C, 0x0D, 0x0E, 0x10, 0x11 });
            IvParameterSpec IV16 = new IvParameterSpec("1234567812345678".getBytes());
            lunaParams.init(IV16);
        }
        encCipher.init(Cipher.ENCRYPT_MODE, key, lunaParams);
        IvParameterSpec ivps = new IvParameterSpec(encCipher.getIV());
        decCipher.init(Cipher.DECRYPT_MODE, key, lunaParams);

        System.out.println("Encrypting PlainText");
        byte[] blockSizeData = new byte[1024];
        Random r = new Random();
        r.nextBytes(blockSizeData);
        byte[] nonblockSizeData = new byte[1021];
        r.nextBytes(nonblockSizeData);
        byte[] encryptedbytes = null;
        encryptedbytes = encCipher.doFinal(blockSizeData);

        System.out.println("Decrypting to PlainText");
        byte[] decryptedbytes = null;
        decryptedbytes = decCipher.doFinal(encryptedbytes);

        if(Arrays.equals(decryptedbytes, blockSizeData)) System.out.println("Enc and dec succsussful1");

        byte[] encryptedbytes1 = KeyFormatter.encryptWithAESWrappingKey(keyStore, aesKeyLabel, blockSizeData);
        if(Arrays.equals(encryptedbytes1, encryptedbytes)) System.out.println("Enc and dec successful2");


        //----------------------------------------
        String eddsaKey = "303f020100301006032b656406092b06010401da470f01042830260201010421001cd3bbdc0bd177e52e640f29a4026fd2fa1b8b5935dd141c9a72956e9a2dcb68";
        byte[] eddsaKeyBytes = Hex.decode(eddsaKey);
        encryptedbytes = encCipher.doFinal(eddsaKeyBytes);
        System.out.println("Eddsa Encrypted: " + Hex.toHexString(encryptedbytes));

        String eddsaKeyEnc = "e49d93a8cf64c9901717b29a974155908825227cfac1c9f556ff5ef3053201909ba0f9a9e279ac3bea22f99ab2c7d77aeeb9e159ef23734ef797303f7cf6010f630eb34fde45bd47d864821566b81ffa";
        byte[] eddsaKeyEncBytes = Hex.decode(eddsaKeyEnc);
        decryptedbytes = decCipher.doFinal(eddsaKeyEncBytes);
        System.out.println("Eddsa Decrypted: " + Hex.toHexString(decryptedbytes));

    }
}
