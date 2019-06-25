package com.ripple.pilots;

import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.security.spec.ECGenParameterSpec;
import java.util.Enumeration;

public class KeyGenerationMain {

    public static final String PROVIDER = "LunaProvider";

    public static void main(String[] args) {
        System.out.println("Starting excecution...");
        try {
            // Log into HSM
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
            keyStoreManager.keyStoreLogin();
            /*Enumeration<String> keys = keyStoreManager.listContents();
            while(keys.hasMoreElements()){
                System.out.println(keys.nextElement());
            }*/

            // Generate a key in the HSM
            keyStoreManager.generateKeyPair("test_ne_rsa_01", "RSA", false);
            keyStoreManager.listContents();

            /*KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", PROVIDER);
            ECGenParameterSpec ecSpec = new ECGenParameterSpec("Ed25519");
            keyPairGenerator.initialize(ecSpec);
            KeyPair keyPair = keyPairGenerator.generateKeyPair();

            X509Certificate[] certificates = (X509Certificate[]) keyStoreManager.generateSelfSignedCertificate(keyPair);
            for(X509Certificate certificate : certificates) {
                System.out.println(certificate.toString());
            }*/
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
