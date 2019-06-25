package com.ripple.pilots;

import com.safenetinc.luna.provider.key.LunaKey;
import org.bouncycastle.crypto.AsymmetricCipherKeyPair;
import org.bouncycastle.crypto.generators.Ed25519KeyPairGenerator;
import org.bouncycastle.crypto.params.Ed25519KeyGenerationParameters;
import org.bouncycastle.crypto.params.Ed25519PrivateKeyParameters;
import org.bouncycastle.crypto.params.Ed25519PublicKeyParameters;
import org.bouncycastle.util.encoders.Base64;
import org.bouncycastle.util.encoders.Hex;

import java.io.File;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.X509Certificate;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Enumeration;
import java.util.Scanner;
import org.bouncycastle.crypto.Signer;
import org.bouncycastle.crypto.signers.Ed25519Signer;

public class KeyFileReader {

    public static void main(String[] args) {
        try {

            Security.addProvider(new org.bouncycastle.jce.provider.BouncyCastleProvider());
            //KeyFactory keyFactory = KeyFactory.getInstance("EdDSAE25519", "BC");
            //KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("EdDSA", "BC");
            Ed25519KeyPairGenerator keyPairGenerator = new Ed25519KeyPairGenerator();
            keyPairGenerator.init(new Ed25519KeyGenerationParameters(new SecureRandom()));
            AsymmetricCipherKeyPair ed25519KeyPair = keyPairGenerator.generateKeyPair();
            Ed25519PrivateKeyParameters ed25519PrivateKey = (Ed25519PrivateKeyParameters)ed25519KeyPair.getPrivate();
            Ed25519PublicKeyParameters ed25519PublicKey = (Ed25519PublicKeyParameters)ed25519KeyPair.getPublic();
            byte[] privateKeyBytes = ed25519PrivateKey.getEncoded();
            System.out.println("Private key: " + Hex.toHexString(privateKeyBytes));


            // Sign data
            String dataToSign = "Hello World, How are you doing?";
            byte[] dataBytesToSign = dataToSign.getBytes(StandardCharsets.UTF_8);
            //Signature signer = Signature.getInstance("EdDSA", "BC");
            //signer.initSign(ed25519PrivateKey);
            //signer.update(dataBytesToSign);
            //byte[] signature = signer.sign();
            Signer signer = new org.bouncycastle.crypto.signers.Ed25519Signer();
            signer.init(true, ed25519PrivateKey);
            signer.update(dataBytesToSign, 0, dataBytesToSign.length);
            byte[] signature = signer.generateSignature();
            System.out.println("Signature Local: " + Hex.toHexString(signature));
            Signer verifier = new org.bouncycastle.crypto.signers.Ed25519Signer();
            verifier.init(false, ed25519PublicKey);
            verifier.update(dataBytesToSign, 0, dataBytesToSign.length);
            System.out.println("Verification Result: " + verifier.verifySignature(signature));

            // Generate Key Pair for Luna provider
            //keyFactory = KeyFactory.getInstance("EdDSA", "LunaProvider");

            // Import key pair to HSM
            ImportEd25519PrivateKey importEdKey = new ImportEd25519PrivateKey();
            //System.out.println(Hex.toHexString(importEdKey.parseJavaPrivateKeyASN(privateKeyBytes)));
            String ed25519KeyLabel = "test_imported_ed25519_02";
            boolean isImportSuccessful =
                    importEdKey.importKey(privateKeyBytes, false,"test_rsa_importkey_01", "test_aes_wrappingkey_01",
                           ed25519KeyLabel );
            /*KeyPair ed25519KeyPair = new KeyPair(ed25519PublicKey, ed25519PrivateKey);
            //keyStoreManager.importKeyPairToHSM(ed25519KeyPair, keyLabel);
            PrivateKey injectedKey = LunaKey.InjectPrivateKey(ed25519PrivateKey, 0);
            KeyStore keyStore = keyStoreManager.getKeyStore();*/

            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
            Enumeration<String> hsmObjects = keyStoreManager.listContents();
            while(hsmObjects.hasMoreElements()) {
                System.out.println(hsmObjects.nextElement());
            }

            // Sign data
            com.ripple.pilots.Ed25519Signer signer1 = new com.ripple.pilots.Ed25519Signer();
            byte[] signature1 = signer1.sign(keyStoreManager, ed25519KeyLabel, dataBytesToSign);
            System.out.println("Signature HSM: " + Hex.toHexString(signature1));
            System.out.println("Both signatures match: " + Arrays.equals(signature, signature1));

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }



    public static byte[] readEd25519PrivKeyFromFile() throws Exception{
        // Read private key
        File privateKey = new File("/mnt/hgfs/raghavsundaravaradan/Projects/eddsa-poc/test_ed25519_key.pem");
        Scanner scanner = new Scanner(privateKey);
        byte[] privateKeyBytes = null;
        while(scanner.hasNextLine()) {
            if(!scanner.nextLine().equals("-----BEGIN PRIVATE KEY-----")) continue;
            else {
                String privateKeyBase64 = scanner.nextLine();
                privateKeyBytes = Base64.decode(privateKeyBase64);
                break;
            }
        }

        System.out.println(Hex.toHexString(privateKeyBytes));
        return privateKeyBytes;
    }

    public static PrivateKey getEd25519PkcsSpec() throws Exception {
        byte[] privateKeyBytes = readEd25519PrivKeyFromFile();
        PKCS8EncodedKeySpec pkcs8EncodedPrivKey = new PKCS8EncodedKeySpec(privateKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC");
        PrivateKey ed25519PrivateKey = keyFactory.generatePrivate(pkcs8EncodedPrivKey);
        return ed25519PrivateKey;
    }

    public static byte[] readEd25519PubKeyFromFile() throws Exception{
        // Read public key
        File publicKey = new File("/mnt/hgfs/raghavsundaravaradan/Projects/eddsa-poc/test_ed25519_public_key.pem");
        Scanner scanner = new Scanner(publicKey);
        byte[] publicKeyBytes = null;
        while(scanner.hasNextLine()) {
            if(!scanner.nextLine().equals("-----BEGIN PUBLIC KEY-----")) continue;
            else {
                String publicKeyBase64 = scanner.nextLine();
                publicKeyBytes = Base64.decode(publicKeyBase64);
                break;
            }
        }
        System.out.println(Hex.toHexString(publicKeyBytes));
        return publicKeyBytes;
    }

    public static PublicKey getEd25519X502Spec() throws Exception {
        byte[] publicKeyBytes = readEd25519PubKeyFromFile();
        X509EncodedKeySpec x509EncodedPubKey = new X509EncodedKeySpec(publicKeyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "BC");
        PublicKey ed25519PublicKey = keyFactory.generatePublic(x509EncodedPubKey);
        return ed25519PublicKey;
    }
}
