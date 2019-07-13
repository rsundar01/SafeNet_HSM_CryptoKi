package com.ripple.pilots;

import com.safenetinc.luna.provider.key.LunaKey;
import org.bouncycastle.asn1.*;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.util.encoders.Hex;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateException;
import java.security.spec.InvalidParameterSpecException;
import java.util.Arrays;


public class KeyFormatter {

    //ASN1 structure when length of the keys is 33 bytes (leading 00 to positive the integer)
    static byte[] asn1PrivateKeyStructure = new byte[] {(byte)0x30, (byte)0x3F, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x03,
            (byte)0x2B, (byte)0x65, (byte)0x64, (byte)0x06, (byte)0x09, (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01, (byte)0xDA, (byte)0x47, (byte)0x0F,
            (byte)0x01, (byte)0x04, (byte)0x28, (byte)0x30, (byte)0x26, (byte)0x02, (byte)0x01, (byte)0x01, (byte)0x04, (byte)0x21};

    static byte[] asn1PublicStruct = new byte[] {(byte)0x30, (byte)0x35, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x03, (byte)0x2B,
            (byte)0x65, (byte)0x64, (byte)0x06, (byte)0x09, (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01, (byte)0xDA,
            (byte)0x47, (byte)0x0F, (byte)0x01, (byte)0x03, (byte)0x21};

    public static boolean importKey(KeyStoreManager keyStoreManager, byte[] ed25519PrivateKey, boolean isPrivateKeyEncoded, String rsaImportKeyLabel, String aesWrappingKeyLabel,
                             String importedKeyLabel) throws IOException, KeyStoreException, NoSuchAlgorithmException,
            CertificateException, NoSuchProviderException, InvalidAlgorithmParameterException, IOException, KeyStoreException,
            CertificateException, InvalidKeyException, NoSuchPaddingException, IllegalBlockSizeException,
            UnrecoverableKeyException, BadPaddingException, InvalidParameterSpecException {
        boolean retValue = false;
        generateWrappingKey(keyStoreManager, rsaImportKeyLabel, aesWrappingKeyLabel);
        byte[] decodedPrivateKey = null;
        if(isPrivateKeyEncoded) decodedPrivateKey = asnEd25519PrivateKeyParserBc(ed25519PrivateKey);
        else decodedPrivateKey = ed25519PrivateKey;
        byte[] lunaEncodedPrivateKey = asnEd25519PrivateKeyEncoderLuna(decodedPrivateKey);
        System.out.println("Luna encoded key: " + Hex.toHexString(lunaEncodedPrivateKey));
        //byte[] wrappedPrivateKey = encryptWithAESWrappingKey(keyStoreManager.getKeyStore(), aesWrappingKeyLabel,
        //                                                    lunaEncodedPrivateKey);
        byte[] wrappedPrivateKey = encryptWithAESWrappingKeyBC(lunaEncodedPrivateKey);
        System.out.println("Luna enccoded encrypted key: " + Hex.toHexString(wrappedPrivateKey));
        retValue = LunaManager.importEd25519PrivateKey(wrappedPrivateKey, aesWrappingKeyLabel, importedKeyLabel);
        //ImportEd25519PrivateKey.importKey();
        retValue = true;
        return retValue;
    }

    private static void generateWrappingKey(KeyStoreManager keyStoreManager, String rsaImportKeyLabel, String aesWrappingKeyLabel) throws
                            NoSuchAlgorithmException, NoSuchProviderException,
                            InvalidAlgorithmParameterException, IOException, KeyStoreException,
                            CertificateException, InvalidKeyException, NoSuchPaddingException,
                            IllegalBlockSizeException, UnrecoverableKeyException {
        // Check if AES Wrapping Key already exists
        // Check if RSA Wrapping Key already exists
        boolean isRsaKeyAlreadyPresent = keyStoreManager.getKeyStore().containsAlias(rsaImportKeyLabel);
        boolean isAesWrapKeyAlreadyPresent = keyStoreManager.getKeyStore().containsAlias(aesWrappingKeyLabel);
        if(isAesWrapKeyAlreadyPresent) return;
        if(!isRsaKeyAlreadyPresent) keyStoreManager.generateKeyPair(rsaImportKeyLabel, "RSA", false);
        PublicKey rsaPublicKey = keyStoreManager.retrieveCertificate(rsaImportKeyLabel).getPublicKey();

        //AES key to be imported in the HSM value = 01020304050607080910111213141516
        byte[] encoded = Hex.decode("01020304050607080910111213141516");
        SecretKeySpec skeySpec = new SecretKeySpec(encoded, "AES");

        // wrap the AESkey with the public key Cert using BoucyCastle
        Cipher c2 = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "BC"); // RSA/ECB/PKCS1Padding   RSA/ECB/OAEPWithSHA1AndMGF1Padding
        c2.init(Cipher.WRAP_MODE, rsaPublicKey);
        byte[] aesWrappedKey = c2.wrap(skeySpec);

        //Uwrap the AES keys to be stored in the HSM
        Cipher c1 = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "LunaProvider"); // RSA/ECB/PKCS1Padding   RSA/ECB/OAEPWithSHA1AndMGF1Padding
        c1.init(Cipher.UNWRAP_MODE, keyStoreManager.retrievePrivateKey("test_rsa_importkey_01"));
        LunaKey aesKey = (LunaKey)c1.unwrap(aesWrappedKey, "AES", Cipher.SECRET_KEY);
        //SetKeyAttributeToNotExtractable(aesKey.GetKeyHandle());
        aesKey.MakePersistent(aesWrappingKeyLabel);

    }

    public static byte[] asnEd25519PrivateKeyParserBc(byte[] privateKey) throws IOException{
        ASN1Primitive p;
        ASN1InputStream input = new ASN1InputStream(privateKey);
        byte[] filteredByteArray = null;
        while ((p = input.readObject()) != null) {
            ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
            ASN1OctetString octetString = ASN1OctetString.getInstance(asn1.getObjectAt(2));
            filteredByteArray = Arrays.copyOfRange(octetString.getOctets(), 2, octetString.getOctets().length);
        }
        return filteredByteArray;
    }

    public static byte[] asnEd25519PrivateKeyEncoderLuna(byte[] privateKey) {
        byte[] encodedPrivateKey = Arrays.copyOf(asn1PrivateKeyStructure, asn1PrivateKeyStructure.length + 33);
        byte[] zero = new byte[1];
        zero[0] = (byte)0x0;
        System.arraycopy(zero, 0, encodedPrivateKey, asn1PrivateKeyStructure.length, zero.length);
        System.arraycopy(privateKey, 0, encodedPrivateKey, asn1PrivateKeyStructure.length+1, privateKey.length);
        return encodedPrivateKey;
    }

    private static byte[] encryptWithAESWrappingKeyBC(byte[] privateKey) throws InvalidKeyException,
                        InvalidAlgorithmParameterException, NoSuchPaddingException, NoSuchAlgorithmException,
                        NoSuchProviderException, IllegalBlockSizeException, BadPaddingException {
        Security.addProvider(new BouncyCastleProvider());
        byte[] encoded = Hex.decode("01020304050607080910111213141516");

        SecretKeySpec skeySpec = new SecretKeySpec(encoded, "AES");
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding",  "BC");
        //ckdemo will wait for an IV of 1234567812345678
        cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec("1234567812345678".getBytes()));
        return cipher.doFinal(privateKey);
    }

    public static byte[] encryptWithAESWrappingKey(KeyStore keyStore, String aesKeyLabel, byte[] privateKey)
            throws UnrecoverableKeyException,InvalidAlgorithmParameterException, InvalidKeyException,
            KeyStoreException, NoSuchPaddingException, NoSuchAlgorithmException, InvalidParameterSpecException,
            NoSuchProviderException, IllegalBlockSizeException, BadPaddingException {
        Key key = keyStore.getKey(aesKeyLabel, "crypto1".toCharArray());
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding",  "LunaProvider");
        AlgorithmParameters lunaParams = AlgorithmParameters.getInstance("AES", "LunaProvider");
        lunaParams.init(new IvParameterSpec("1234567812345678".getBytes()));
        cipher.init(Cipher.ENCRYPT_MODE, key,lunaParams);
        return cipher.doFinal(privateKey);
    }
    public static byte[] asnEd25519PrivateKeyParserOpenssl(byte[] privateKey) throws IOException{
        ASN1Primitive p;
        ASN1InputStream input = new ASN1InputStream(privateKey);
        byte[] filteredByteArray = null;
        if ((p = input.readObject()) != null) {
            ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
            ASN1OctetString octetString = ASN1OctetString.getInstance(asn1.getObjectAt(2));
            filteredByteArray = Arrays.copyOfRange(octetString.getOctets(), 2, octetString.getOctets().length);
        }
        return filteredByteArray;
    }

    public static byte[] asnEd25519PublicKeyParserOpenssl(byte[] publicKey) throws IOException{
        ASN1Primitive p;
        ASN1InputStream input = new ASN1InputStream(publicKey);
        byte[] filteredByteArray = null;
        if ((p = input.readObject()) != null) {
            ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
            DERBitString derBitString = DERBitString.getInstance(asn1.getObjectAt(1));
            filteredByteArray = Arrays.copyOfRange(derBitString.getEncoded(), 3, derBitString.getEncoded().length);
        }
        return filteredByteArray;
    }

}
