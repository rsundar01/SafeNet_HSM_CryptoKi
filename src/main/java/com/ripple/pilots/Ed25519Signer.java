package com.ripple.pilots;

import java.io.IOException;
import java.security.*;
import java.security.cert.CertificateEncodingException;
import java.security.cert.CertificateException;

public class Ed25519Signer {
    public static final String PROVIDER = "LunaProvider";

    public byte[] sign(KeyStoreManager keyStoreManager, String keyLabel, byte[] dataToSign) throws NoSuchProviderException, NoSuchAlgorithmException,
            IOException, KeyStoreException, CertificateException, UnrecoverableKeyException, InvalidKeyException, SignatureException {

        Signature signature= Signature.getInstance("EDDSA", PROVIDER);
        PrivateKey privateKey = keyStoreManager.retrievePrivateKey(keyLabel);
        if(privateKey != null) {
            System.out.println("Inside sign(): private key not null");
            signature.initSign(privateKey);
            signature.update(dataToSign);
            return signature.sign();
        } else {
            System.out.println("Inside sign(): private key null");
            return null;
        }
    }
}
