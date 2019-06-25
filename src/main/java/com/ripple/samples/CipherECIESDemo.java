package com.ripple.samples;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.InvalidAlgorithmParameterException;
import java.security.InvalidKeyException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.security.spec.ECGenParameterSpec;
import java.util.Random;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.SealedObject;

public class CipherECIESDemo {

  // Configure these as required.
  private static final int slot = 0;
  private static final String passwd = "userpin";
  public static final String provider = "LunaProvider";
  public static final String keystoreProvider = "Luna";
  public static SealedObject so = null;

  public static void main(String[] args) {

    System.out.println("This sample requires an ECIES-capable HSM...");
    System.out.println("");

    KeyStore myStore = null;
    try {

      /* Note: could also use a keystore file, which contains the token label or slot no. to use. Load that via
       * "new FileInputStream(ksFileName)" instead of ByteArrayInputStream. Save objects to the keystore via a
       * FileOutputStream. */

      ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
      myStore = KeyStore.getInstance(keystoreProvider);
      myStore.load(is1, passwd.toCharArray());
    } catch (KeyStoreException kse) {
      System.out.println("Unable to create keystore object");
      System.exit(-1);
    } catch (NoSuchAlgorithmException nsae) {
      System.out.println("Unexpected NoSuchAlgorithmException while loading keystore");
      System.exit(-1);
    } catch (CertificateException e) {
      System.out.println("Unexpected CertificateException while loading keystore");
      System.exit(-1);
    } catch (IOException e) {
      // this should never happen
      System.out.println("Unexpected IOException while loading keystore.");
      System.exit(-1);
    }

    try {

      System.out.println("This sample requires the ECIES CUF be applied to the Luna appliance.");

      KeyPairGenerator kpg = KeyPairGenerator.getInstance("ECDSA", "BC");
      ECGenParameterSpec ecParam = new ECGenParameterSpec("c2pnb304w1");
      kpg.initialize(ecParam);

      KeyPair kp = kpg.generateKeyPair();
      byte[] orig = new byte[15 * 1024];
      Random r = new Random();
      r.nextBytes(orig);

      Cipher cipher = Cipher.getInstance("ECIES", provider);
      cipher.init(Cipher.ENCRYPT_MODE, kp.getPublic());
      byte[] enc = cipher.doFinal(orig);

      Cipher decrypter = Cipher.getInstance("ECIES", provider);
      decrypter.init(Cipher.DECRYPT_MODE, kp.getPrivate(), cipher.getParameters());
      byte[] dec = decrypter.doFinal(enc);

      System.out.println("ECIES enc/dec succeeded.");

    } catch (InvalidKeyException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (InvalidAlgorithmParameterException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchPaddingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (IllegalBlockSizeException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (BadPaddingException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }
}
