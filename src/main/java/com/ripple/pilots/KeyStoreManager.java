package com.ripple.pilots;

import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.provider.LunaCertificateX509;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.Date;
import java.util.Enumeration;
import java.util.concurrent.atomic.AtomicBoolean;


// Labels of generated keys so for:
// test_ed25519_01

public class KeyStoreManager {

    private static final String slot = "0";
    private static final String passcode = "crypto1";
    public static final String PROVIDER = "LunaProvider";
    public static final String  KEY_STORE_PROVIDER = "Luna";
    private static final KeyStoreManager keyStoreManager = new KeyStoreManager();
    private static final LunaSlotManager lunaSlotManager = LunaSlotManager.getInstance();

    private AtomicBoolean isLoggedIn = new AtomicBoolean(false);
    private KeyStore keyStore = null;
    private KeyStoreManager(){}

    public synchronized static KeyStoreManager getInstance() {
        return keyStoreManager;
    }

    public boolean loginStatus() {
        return isLoggedIn.get();
    }

    public synchronized boolean keyStoreLogin() throws IOException,
                                                    KeyStoreException,
                                                    NoSuchAlgorithmException,
                                                    CertificateException
    {
        System.out.println("Logging in...");
        isLoggedIn = new AtomicBoolean(false);
        if(!LunaManager.detectToken() || LunaManager.requiresInitialization()) {
            return isLoggedIn.get();
        }
        ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
        KeyStore keyStore = KeyStore.getInstance(KEY_STORE_PROVIDER);
        keyStore.load(is1, passcode.toCharArray());
        this.keyStore = keyStore;
        isLoggedIn = new AtomicBoolean(true);
        return isLoggedIn.get();
    }

    public synchronized KeyPair generateKeyPair(String keyLabel, String algorithm,
                                                boolean isExtractable) throws IOException,
                                                                              NoSuchAlgorithmException,
                                                                              KeyStoreException,
                                                                              CertificateException,
                                                                              NoSuchProviderException,
                                                                              InvalidAlgorithmParameterException,
                                                                              InvalidKeyException
    {
        KeyPair keyPair = null;
        if(!isLoggedIn.get()) return keyPair;
        algorithm = algorithm.toLowerCase();
        switch(algorithm) {
            case "eddsa":
            case "ed25519":
                keyPair = generateEd25519Key(isExtractable);
                break;
            case "rsa":
                keyPair = generateRSAKey(isExtractable);
                break;
            case "ecdsa":
                keyPair = generateECDSAKey(isExtractable);
                break;
            default:
                keyPair = generateRSAKey(isExtractable);
        }
        importKeyPairToHSM(keyPair, keyLabel);
        return keyPair;
    }

    public Enumeration<String> listContents() throws IOException, NoSuchAlgorithmException,
            KeyStoreException, CertificateException {

        Enumeration<String> aliases = null;
        if(!isLoggedIn.get()) return aliases;
        aliases = keyStore.aliases();
        return aliases;
    }

    public PrivateKey retrievePrivateKey(String keyLabel) throws IOException, NoSuchAlgorithmException,
                           KeyStoreException, CertificateException, UnrecoverableKeyException   {
        PrivateKey retrievedPrivateKey = null;
        if(!isLoggedIn.get()) return retrievedPrivateKey;
        if(keyStore.containsAlias(keyLabel)){
            retrievedPrivateKey =  (PrivateKey) keyStore.getKey(keyLabel, passcode.toCharArray());
        }
        return retrievedPrivateKey;
    }

    public Certificate retrieveCertificate(String keyLabel) throws IOException, NoSuchAlgorithmException,
                            KeyStoreException, CertificateException {
        Certificate retrievedCertificate = null;
        if(!isLoggedIn.get()) return retrievedCertificate;
        if(keyStore.containsAlias(keyLabel)){
            retrievedCertificate = (Certificate) keyStore.getCertificateChain(keyLabel)[0];
            return retrievedCertificate;
        }
        return  retrievedCertificate;
    }

    public KeyStore getKeyStore() throws IOException, KeyStoreException, NoSuchAlgorithmException, CertificateException {
        if(!isLoggedIn.get()) return null;
        return keyStore;
    }

    private KeyPair generateEd25519Key(boolean isExtractable) throws NoSuchAlgorithmException,
                                                                    NoSuchProviderException,
                                                                    InvalidAlgorithmParameterException
    {
        LunaSlotManager.getInstance().setPrivateKeysExtractable(isExtractable);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("Ed25519", PROVIDER);
        ECGenParameterSpec ecSpec = new ECGenParameterSpec("Ed25519");
        keyPairGenerator.initialize(ecSpec);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        LunaSlotManager.getInstance().setPrivateKeysExtractable(false);
        return keyPair;
    }

    private KeyPair generateRSAKey(boolean isExtractable) throws NoSuchAlgorithmException,
                                                                NoSuchProviderException
    {
        LunaSlotManager.getInstance().setPrivateKeysExtractable(isExtractable);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA", PROVIDER);
        keyPairGenerator.initialize(4096);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        LunaSlotManager.getInstance().setPrivateKeysExtractable(false);
        return keyPair;
    }

    private KeyPair generateECDSAKey(boolean isExtractable) throws NoSuchAlgorithmException,
                                                                  NoSuchProviderException
    {
        LunaSlotManager.getInstance().setPrivateKeysExtractable(isExtractable);
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("ECDSA", PROVIDER);
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        LunaSlotManager.getInstance().setPrivateKeysExtractable(false);
        return keyPair;
    }

   private Certificate[] generateSelfSignedCertificate(KeyPair keyPair, String subjectName) throws InvalidKeyException,
                                                                                                    CertificateEncodingException
    {
        Certificate[] certChain = new LunaCertificateX509[1];
        BigInteger serialNumber = new BigInteger("12345");
        Date notBefore = new Date();
        Date notAfter = new Date(notBefore.getTime() + 1000000000);
        certChain[0] = LunaCertificateX509.SelfSign(keyPair, subjectName, serialNumber, notBefore, notAfter);
        return certChain;
    }

    public boolean importKeyPairToHSM(KeyPair keyPair, String keyLabel) throws InvalidKeyException,
                                                                               CertificateException,
                                                                               KeyStoreException,
                                                                               IOException,
                                                                               NoSuchAlgorithmException
    {
        boolean isImportSuccessful = false;
        if(!isLoggedIn.get()) return isImportSuccessful;
        Certificate[] certChain = generateSelfSignedCertificate(keyPair, "CN=" + keyLabel);
        keyStore.setKeyEntry( keyLabel, keyPair.getPrivate(), null, certChain);
        isImportSuccessful = true;
        return isImportSuccessful;
    }

    public void logout() {
        lunaSlotManager.logout(Integer.parseInt(slot));
    }

    /*private synchronized boolean detectToken() {
        boolean istokenPresent = false;
        try {
            lunaSlotManager.detectTokenConnectionProblem(Integer.parseInt(slot));
            istokenPresent = true;
        } catch (Exception e) { }
        return istokenPresent;
    }*/

    /*private synchronized boolean checkAndInitialized() throws IOException, KeyStoreException,
                                            NoSuchAlgorithmException, CertificateException {
        boolean result = false;
        if (!isLoggedIn.get()) return isLoggedIn.get();
        else if(!detectToken() || lunaSlotManager.getReconnectRequired()) {
            isLoggedIn.set(false);
        }
        return result;
    }*/
}
