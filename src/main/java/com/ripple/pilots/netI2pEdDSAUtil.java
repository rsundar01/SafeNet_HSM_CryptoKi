package com.ripple.pilots;


import net.i2p.crypto.eddsa.EdDSAEngine;
import net.i2p.crypto.eddsa.EdDSAPrivateKey;
import net.i2p.crypto.eddsa.EdDSAPublicKey;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveSpec;
import net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable;
import net.i2p.crypto.eddsa.spec.EdDSAParameterSpec;
import net.i2p.crypto.eddsa.spec.EdDSAPublicKeySpec;
import org.bouncycastle.util.encoders.Hex;

import java.security.*;
import java.security.spec.PKCS8EncodedKeySpec;

import static net.i2p.crypto.eddsa.spec.EdDSANamedCurveTable.ED_25519;

public class netI2pEdDSAUtil {
    public static final EdDSANamedCurveSpec EDDSA_CURVE_SPEC = EdDSANamedCurveTable.getByName(ED_25519);
    public static final String ED25519_HASH_ALGORITHM = EDDSA_CURVE_SPEC.getHashAlgorithm();

    public static KeyPair getKeyPairFromFile() {
        try {
            KeyFormatter keyFormatter = new KeyFormatter();
            byte[] publicKeyBytesOpenssl = KeyFileReader.readEd25519PubKeyFromFile();
            byte[] privateKeyBytesOpenssl = KeyFileReader.readEd25519PrivKeyFromFile();
            System.out.println(Hex.toHexString(privateKeyBytesOpenssl));
            EdDSAPrivateKey privateKey = new EdDSAPrivateKey(new PKCS8EncodedKeySpec(privateKeyBytesOpenssl));

            EdDSAPublicKeySpec spec = new EdDSAPublicKeySpec(privateKey.getAbyte(), EDDSA_CURVE_SPEC);
            EdDSAPublicKey publicKey = new EdDSAPublicKey(spec);

            return new KeyPair(publicKey, privateKey);
        } catch (Exception e) {
            throw new RippleCryptoException(e);
        }
    }

    public static KeyPair getRFC8032Test3Keys() {
        try {
            KeyFormatter keyFormatter = new KeyFormatter();
            //byte[] encodedPrivateKey = Hex.decode("302e020100300506032b6570042204204ccd089b28ff96da9db6c346ec114e0f5b8a319f35aba624da8cf6ed4fb8a6fb");
            byte[] encodedPrivateKey = Hex.decode("302e020100300506032b657004220420c5aa8df43f9f837bedb7442f31dcb7b166d38535076f094b85ce3a2e0b4458f7");
            EdDSAPrivateKey privateKey = new EdDSAPrivateKey(new PKCS8EncodedKeySpec(encodedPrivateKey));

            EdDSAPublicKeySpec spec = new EdDSAPublicKeySpec(privateKey.getAbyte(), EDDSA_CURVE_SPEC);
            EdDSAPublicKey publicKey = new EdDSAPublicKey(spec);
            System.out.println(Hex.toHexString(privateKey.getEncoded()));
            System.out.println(Hex.toHexString(publicKey.getEncoded()));
            return new KeyPair(publicKey, privateKey);
        } catch(Exception e) {
            throw new RippleCryptoException(e);
        }


    }

    public static byte[] signUsingI2p(PrivateKey privateKey, byte[] dataToSign) {
        byte[] signature = null;
        try {
            EdDSAParameterSpec spec = EdDSANamedCurveTable.getByName(EdDSANamedCurveTable.ED_25519);
            Signature signer = new EdDSAEngine(MessageDigest.getInstance(spec.getHashAlgorithm()));
            signer.initSign(privateKey);
            signer.update(dataToSign);
            signature = signer.sign();
        }catch (Exception e) {
            throw new RippleCryptoException(e);
        }
        return signature;
    }

    public static byte[] signUsingBC(PrivateKey privateKey, byte[] datatToSign) {
        return null;
    }

    public static void main(String[] args) {

        KeyPair keyPair = getRFC8032Test3Keys();
        //KeyPair keyPair = getKeyPairFromFile();
        System.out.println(Hex.toHexString(keyPair.getPrivate().getEncoded()));
        //String dataToSign = "Hello World, How are you doing?";
        byte b[] = Hex.decode("af82");
        //byte[] signature = signUsingI2p(keyPair.getPrivate(), dataToSign.getBytes());
        byte[] signature = signUsingI2p(keyPair.getPrivate(), b);
        System.out.println(Hex.toHexString(signature));
        String expectedSignature = "6291d657deec24024827e69c3abe01a30ce548a284743a445e3680d7db5ac3ac18ff9b538d16f290ae67f760984dc6594a7c15e9716ed28dc027beceea1ec40a";
        if(expectedSignature.equals(Hex.toHexString(signature))) {
            System.out.println("Signature matches the test3 test vector in rfc 8032");
        } else {
            System.out.println("Test Failed");
        }
    }

    /*public static EdDSAPublicKey fromX509UrlEncodedString(String urlEncodedPublicKey) {
        try {
            byte[] bytes = DECODER.decode(urlEncodedPublicKey);
            return new EdDSAPublicKey(new X509EncodedKeySpec(bytes));
        } catch (InvalidKeySpecException e) {
            throw new RippleCryptoException(e);
        }
    }

    public static String toEncodedString(PublicKey publicKey) {
        return Base64.getUrlEncoder().withoutPadding().encodeToString(publicKey.getEncoded());
    }*/

}
