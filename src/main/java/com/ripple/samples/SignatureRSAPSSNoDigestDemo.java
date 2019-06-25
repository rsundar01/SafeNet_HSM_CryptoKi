package com.ripple.samples;

import com.safenetinc.luna.LunaUtils;

import java.io.ByteArrayInputStream;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;

import java.security.MessageDigest;
import java.security.Signature;
import java.security.spec.MGF1ParameterSpec;
import java.security.spec.PSSParameterSpec;

/**
 * This sample demonstrates generating an RSA-PSS Signature where no hashing is done by the provider but
 * the Signature object accepts raw hash bytes and the provider sends the raw hash bytes to the Luna HSM.
 */

public class SignatureRSAPSSNoDigestDemo {

  // Configure these as required.
  private static final int slot = 0;
  private static final String passwd = "userpin";
  public static final String provider = "LunaProvider";
  public static final String keystoreProvider = "Luna";


  public static void main(String[] args) throws Exception {

    ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
    KeyStore myStore = KeyStore.getInstance(keystoreProvider);
    myStore.load(is1, passwd.toCharArray());

    System.out.println("Generating RSA Keypair");
    KeyPairGenerator keyGen = KeyPairGenerator.getInstance("RSA", "LunaProvider");
    keyGen.initialize(2048);
    KeyPair keyPair = keyGen.generateKeyPair();

    MessageDigest messageDigest = MessageDigest.getInstance("SHA256");
    String message = "RSA PSS Signature Message!";
    System.out.println("Message: " + message);

    byte[] hash = messageDigest.digest(message.getBytes());

    System.out.println("Hash of the message: " + LunaUtils.getHexString(hash, false));

    Signature sigSign = Signature.getInstance("NONEwithRSAPSS", "LunaProvider");

    //Construct the PSSParameterSpec and assign to the Signature object
    PSSParameterSpec spec = new PSSParameterSpec("SHA256", "MGF1", MGF1ParameterSpec.SHA256, 32, 1);
    sigSign.setParameter(spec);

    sigSign.initSign(keyPair.getPrivate());
    sigSign.update(hash);
    byte[] signature = sigSign.sign();

    System.out.println("RSA PSS Signature: " + LunaUtils.getHexString(signature, false));

    Signature sigVerify = Signature.getInstance("NONEwithRSAPSS", "LunaProvider");
    sigVerify.setParameter(spec);
    sigVerify.initVerify(keyPair.getPublic());
    sigVerify.update(hash);

    if (sigVerify.verify(signature)) {
      System.out.println("The signature was verified successfully!");
    } else {
      System.out.println("The signature was invalid.");
    }
  }
}
