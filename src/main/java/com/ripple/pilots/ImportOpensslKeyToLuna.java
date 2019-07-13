package com.ripple.pilots;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;
import org.bouncycastle.util.encoders.Hex;

import java.security.KeyStore;
import java.util.Enumeration;

public class ImportOpensslKeyToLuna {

    public static void main(String[] args) throws Exception {

        String aesWrapKeyLabel = "test_aes_wrappingkey_02";
        String importKeyLabel = "test_imported_ed25519_04";

        KeyFormatter keyFormatter = new KeyFormatter();
        byte[] publicKeyBytesOpenssl = KeyFileReader.readEd25519PubKeyFromFile();
        byte[] privateKeyBytesOpenssl = KeyFileReader.readEd25519PrivKeyFromFile();
        byte[] publicKeyBytes = keyFormatter.asnEd25519PublicKeyParserOpenssl(publicKeyBytesOpenssl);
        byte[] privateKeyBytes = keyFormatter.asnEd25519PrivateKeyParserOpenssl(privateKeyBytesOpenssl);
        System.out.println("Private key bytes: " + Hex.toHexString(privateKeyBytes));

        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
        if(!keyStoreManager.keyStoreLogin()) {
            System.out.println("Login unsuccessful"); return;
        }
        KeyStore keyStore = keyStoreManager.getKeyStore();

        /*if(keyStore.containsAlias(aesWrapKeyLabel)) {
            //keyStore.deleteEntry(aesWrapKeyLabel);
            if (LunaTokenObject.LocateKeyByAlias(aesWrapKeyLabel) != null) {
                LunaTokenObject.LocateKeyByAlias(aesWrapKeyLabel).DestroyObject();
            }
            if(keyStore.containsAlias(aesWrapKeyLabel)) {
                System.out.println("Wrapping key is still present");
                return;
            }
        }*/

        KeyFormatter.importKey(keyStoreManager, privateKeyBytes, false, "test_rsa_importkey_01",
                aesWrapKeyLabel, importKeyLabel);

        if(keyStoreManager.getKeyStore().containsAlias(importKeyLabel)) {
            System.out.println("Import successful");
        } else {
            System.out.println("Import failed");
        }
    }
}
