package com.ripple.pilots;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaKeyStore;
import com.safenetinc.luna.provider.key.LunaKey;
import org.bouncycastle.util.encoders.Hex;

import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;
import java.util.Enumeration;

public class CryptoOperationsMain {
    public static void main(String[] args){

        System.out.println("Perform crypto operations...");

        try {

            // Log into HSM
            LunaSlotManager slotManager1 = LunaSlotManager.getInstance();
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
            keyStoreManager.keyStoreLogin();
            Enumeration<String> keys = keyStoreManager.listContents();
            while(keys.hasMoreElements()){
                System.out.println(keys.nextElement());
            }



            // Retrieve Privatekey Handle
            Key privateKey = null;
            try {
                privateKey = keyStoreManager.retrievePrivateKey("test_ed25519_01");
            } catch(Exception e){}
            if(privateKey != null) System.out.println("Private key: " + privateKey.toString());

            privateKey = keyStoreManager.retrievePrivateKey("test_ne_ed25519_01");
            if(privateKey != null) System.out.println("Private key: " + privateKey.toString());

            // Retrieve Certificate Handle
            //Certificate certificate = keyStoreManager.retrieveCertificate("test_ed25519_01");
            KeyStore keyStore = keyStoreManager.getKeyStore();
            Key key = keyStore.getKey("test_ne_ed25519_01", "crypto1".toCharArray());
            if(key != null) { System.out.println("Key: " + key.toString());
            System.out.println("Is Instance of Private key?: " + (key instanceof PrivateKey)); }
            //Certificate certificate = keyStore.getCertificate("test_ne_ed25519_01");
            LunaKey lunaKey = LunaKey.LocateKeyOnlyByAlias("test_ne_ed25519_01");
            if(lunaKey != null) {System.out.println("test_ne_ed25519_01: " + Hex.toHexString(lunaKey.getEncoded()));
            lunaKey = LunaKey.LocateKeyByAlias("test_ed25519_01");
            System.out.println("test_ed25519_01: " + Hex.toHexString(lunaKey.getEncoded()));}
            //System.out.println("Certificate: " + certificate.toString());

            System.out.println("Is reconnect required: " + slotManager1.getReconnectRequired());
            try {
                slotManager1.detectTokenConnectionProblem(0);
            } catch (Exception e) {
                System.out.println(e.getMessage());
            }
            LunaSlotManager slotManager2 = LunaSlotManager.getInstance();
            System.out.println("Is reconnect required(slotmanager2): " + slotManager2.getReconnectRequired());
            slotManager1.reinitialize(true);
            keyStoreManager.keyStoreLogin();

            // Sign data
            Ed25519Signer signer = new Ed25519Signer();
            String dataToSign = "Hello World, How are you doing?";
            byte[] dataBytesToSign = dataToSign.getBytes(StandardCharsets.UTF_8);
            byte[] signature = signer.sign(keyStoreManager, "test_imported_ed25519_01", dataBytesToSign);
            System.out.println("Signature: " + Hex.toHexString(signature));
            signer = new Ed25519Signer();
            signature = signer.sign(keyStoreManager, "test_imported_ed25519_02", dataBytesToSign);
            System.out.println("Signature: " + Hex.toHexString(signature));

            // Verify signature
            //Ed25519Verifier verifier = new Ed25519Verifier();
            //boolean verification = verifier.verify(keyStoreManager, "test_ed25519_01", "Some data to sign".getBytes(), signature);

            /*if(verification) {
                System.out.println("Verification successful");
            } else {
                System.out.println("Verification failed");
            }*/
        } catch (IOException ioe) {
            System.out.println("IOException: " + ioe.getMessage());
        } catch (CertificateException certe) {
            System.out.println("Certificate Exception: " + certe.getMessage());
        } catch (KeyStoreException kse) {
            System.out.println("Key Store Exception; " + kse.getMessage());
        } catch (Exception e) {
            System.out.println(e.getClass().getCanonicalName() + ": " + e.getMessage());
        }

    }
}
