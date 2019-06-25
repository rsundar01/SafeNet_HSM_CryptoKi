package com.ripple.pilots;

import java.io.IOException;
import java.security.*;
import java.security.cert.Certificate;
import java.security.cert.CertificateException;

public class Ed25519Verifier {

    public static final String PROVIDER = "LunaProvider";

    public boolean verify(KeyStoreManager keyStoreManager, String keyLabel, byte[] dataToVerify,
                          byte[] signatureBytes) throws NoSuchAlgorithmException, NoSuchProviderException,
                        IOException, KeyStoreException, CertificateException, InvalidKeyException, SignatureException {

        Signature signature= Signature.getInstance("EDDSA", PROVIDER);
        Certificate certificate = keyStoreManager.retrieveCertificate(keyLabel);
        signature.initVerify(certificate);
        signature.update(dataToVerify);
        return signature.verify(signatureBytes);
    }
}
