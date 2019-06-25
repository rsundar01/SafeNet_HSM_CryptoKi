package com.ripple.pilots;

import com.safenetinc.luna.provider.key.LunaKey;

import java.security.KeyFactory;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Enumeration;

public class TokenObjectListMain {

    public static void main(String[] args) {
        System.out.println("Starting excecution...");
        try {
            // Log into HSM
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
            keyStoreManager.keyStoreLogin();
            Enumeration<String> keys = keyStoreManager.listContents();
            while(keys.hasMoreElements()){
                System.out.println(keys.nextElement());
            }

            try{KeyFactory keyFactory = KeyFactory.getInstance("ED25519", "LunaProvider");}
            catch(Exception e){System.out.println(e.getMessage());}
            try{KeyFactory keyFactory = KeyFactory.getInstance("Ed25519", "LunaProvider");}
            catch(Exception e){System.out.println(e.getMessage());}
            try{KeyFactory keyFactory = KeyFactory.getInstance("EDDSA", "LunaProvider");}
            catch(Exception e){System.out.println(e.getMessage());}
            try{KeyFactory keyFactory = KeyFactory.getInstance("EdDSA", "LunaProvider");}
            catch(Exception e){System.out.println(e.getMessage());}


            KeyStore keyStore = keyStoreManager.getKeyStore();
            /*X509Certificate[] certificates = (X509Certificate[]) keyStore.getCertificateChain("test_new_ed25519_01-Certificate-Trusted");
            for(X509Certificate certificate : certificates) {
                System.out.println(certificate.toString());
            }*/

            //X509Certificate certificate = (X509Certificate) keyStore.getCertificate("test_ne_ed25519_01");
            //System.out.println(certificate.toString());

            LunaKey k1 = LunaKey.LocateKeyByAlias("test_ne_ed25519_01");
            System.out.println(k1.getAlgorithm());
            System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(k1.getEncoded()));
            LunaKey k2 = LunaKey.LocateKeyByAlias("test_ed25519_01");
            System.out.println(k2.getAlgorithm());
            System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(k2.getEncoded()));
            LunaKey k3 = LunaKey.LocateKeyByAlias("test_ne_ed25519_02");
            System.out.println(k3.getAlgorithm());
            System.out.println(javax.xml.bind.DatatypeConverter.printHexBinary(k3.getEncoded()));
        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
