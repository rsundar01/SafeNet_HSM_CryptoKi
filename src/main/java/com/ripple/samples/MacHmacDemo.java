package com.ripple.samples;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.cert.CertificateException;

import javax.crypto.KeyAgreement;
import javax.crypto.KeyGenerator;
import javax.crypto.Mac;
import javax.crypto.SealedObject;
import javax.crypto.SecretKeyFactory;
import javax.crypto.spec.PBEKeySpec;

import com.safenetinc.luna.LunaSlotManager;

public class MacHmacDemo {

  // Configure these as required.
  private static final int slot = 0;
  private static final String passwd = "userpin";
  public static final String provider = "LunaProvider";
  public static final String keystoreProvider = "Luna";
  public static SealedObject so = null;

  private static String sDigest = "SHA1";
//  private static String sHmac = "HmacSHA1";
//  private static String sHmac = "HmacSHA224";
//  private static String sHmac = "HmacSHA256";
//  private static String sHmac = "HmacSHA384";
  private static String sHmac = "HmacSHA512";
  private static String sGen = "HmacSHA1";
  private static String sPbkdf = "PBKDF2WithHmacSHA1";
  private static String sDerive = "CKKeyDerivationSHA1";

  private static LunaSlotManager slotManager = null;
  private static Key mKey = null;

  /**
   * method toHex: convert bytes to printable string.
   */
  public static String toHex(byte[] digest) {
    if (digest == null)
      return new String("(null)");
    String digits = "0123456789abcdef";
    StringBuilder sb = new StringBuilder(digest.length * 2);
    for (byte b : digest) {
      int bi = b & 0xff;
      sb.append(digits.charAt(bi >> 4));
      sb.append(digits.charAt(bi & 0xf));
    }
    return sb.toString();
  }

  /**
   * method doDigest: compute digest of sample string.
   */
  public static void doDigest() {
    try {
      String in = "abc";
      MessageDigest md = MessageDigest.getInstance(sDigest, provider);
      md.update(in.getBytes());
      byte[] out = md.digest();
      System.out.println("MessageDigest." + sDigest + " = " + toHex(out));
      System.out.println("MessageDigest." + sDigest + ".length = " + out.length);
    } catch (Exception e) {
      System.out.println("MessageDigest." + sDigest + ": " + e.getMessage());
      System.exit(1);
    }
  }

  /**
   * method doGen: generate key via Hmac.
   */
  public static void doGen() {
    try {
      KeyGenerator kg = KeyGenerator.getInstance(sGen, provider);
      Key out = kg.generateKey();
      System.out.println("KeyGenerator." + sGen + ".getAlgorithm = " + out.getAlgorithm());
      System.out.println("KeyGenerator." + sGen + ".getFormat = " + out.getFormat());
      if (out.getFormat().equalsIgnoreCase("RAW")) {
        System.out.println("KeyGenerator." + sGen + ".getEncoded = " + toHex(out.getEncoded()));
        System.out.println("KeyGenerator." + sGen + ".length = " + out.getEncoded().length);
      }
      mKey = out;
    } catch (Exception e) {
      System.out.println("KeyGenerator." + sGen + ": " + e.getMessage());
      System.exit(1);
    }
  }

  /**
   * method doHmac: compute Hmac of sample string.
   */
  public static void doHmac() {
    try {
      String in = "abc";
      Mac mac = Mac.getInstance(sHmac, provider);
      mac.init(mKey);
      mac.update(in.getBytes());
      byte[] out = mac.doFinal();
      System.out.println("Mac." + sHmac + " = " + toHex(out));
      System.out.println("Mac." + sHmac + ".length = " + out.length);
    } catch (Exception e) {
      System.out.println("Mac." + sHmac + ": " + e.getMessage());
      System.exit(1);
    }
  }

  /**
   * method doPbkdf: generate key via password-based key derivation.
   */
  public static void doPbkdf() {
    try {
      String password = "password";
      String salt = "saltvalue";
      /* PBEKeySpec is mandatory; keyLength is mandatory; multiple of 8 bits is mandatory */
      PBEKeySpec spec = new PBEKeySpec(password.toCharArray(), salt.getBytes(), 1000, (8 * 32)/* bits */);
      SecretKeyFactory skf = null;
      if (provider.equalsIgnoreCase("LunaProvider")) {
        skf = SecretKeyFactory.getInstance(sPbkdf, provider);
      } else {
        /* "SunJCE" is the only software provider that implements PBKDF2 */
        skf = SecretKeyFactory.getInstance(sPbkdf, "SunJCE");
      }
      Key out = skf.generateSecret(spec);
      System.out.println("SecretKeyFactory." + sPbkdf + ".getAlgorithm = " + out.getAlgorithm());
      System.out.println("SecretKeyFactory." + sPbkdf + ".getFormat = " + out.getFormat());
      if (out.getFormat().equalsIgnoreCase("RAW")) {
        System.out.println("SecretKeyFactory." + sPbkdf + ".getEncoded = " + toHex(out.getEncoded()));
        System.out.println("SecretKeyFactory." + sPbkdf + ".length = " + out.getEncoded().length);
      }
      mKey = out;
    } catch (Exception e) {
      System.out.println("SecretKeyFactory." + sPbkdf + ": " + e.getMessage());
      System.exit(1);
    }
  }

  /**
   * method doDerive: derive key using CK key derivation mechanism.
   */
  public static void doDerive() {
    try {
      KeyAgreement keyAgreement = KeyAgreement.getInstance(sDerive, provider);
      keyAgreement.init(mKey);
      keyAgreement.doPhase(null, true);
      // Key out = keyAgreement.generateSecret("GenericSecret");
      Key out = keyAgreement.generateSecret("AES");
      System.out.println("KeyAgreement." + sDerive + ".getAlgorithm = " + out.getAlgorithm());
      System.out.println("KeyAgreement." + sDerive + ".getFormat = " + out.getFormat());
      if (out.getFormat().equalsIgnoreCase("RAW")) {
        System.out.println("KeyAgreement." + sDerive + ".getEncoded = " + toHex(out.getEncoded()));
        System.out.println("KeyAgreement." + sDerive + ".length = " + out.getEncoded().length);
      }
      mKey = out;
    } catch (Exception e) {
      System.out.println("KeyAgreement." + sDerive + ": " + e.getMessage());
      System.exit(1);
    }
  }

  /**
   * main.
   */
  public static void main(String[] args) {
    // Print actual provider
    System.out.println("provider = " + provider);
    boolean isHsm = (provider.equalsIgnoreCase("LunaProvider"));

    // Login HSM
    if (isHsm) {
      slotManager = LunaSlotManager.getInstance();
      // slotManager.login(slot, passwd);
    }

    KeyStore myKeyStore = null;
    try {

      /* Note: could also use a keystore file, which contains the token label or slot no. to use. Load that via
       * "new FileInputStream(ksFileName)" instead of ByteArrayInputStream. Save objects to the keystore via a
       * FileOutputStream. */

      ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
      myKeyStore = KeyStore.getInstance(keystoreProvider);
      myKeyStore.load(is1, passwd.toCharArray());
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

    // Digest
    System.out.println("\n--- Digest:\n");
    doDigest();

    // KeyGen
    System.out.println("\n--- KeyGen:\n");
    if (isHsm) {
      slotManager.setSecretKeysDerivable( true );
    }
    doGen();
    if (isHsm) {
      slotManager.setSecretKeysDerivable( false );
    }
    doHmac();

    // Derive
    if (isHsm) {
      System.out.println("\n--- Derive:\n");
      doDerive();
      doHmac();
    }

    // Pbkdf
    System.out.println("\n--- Pbkdf:\n");
    if (isHsm) {
      slotManager.setSecretKeysDerivable( true );
    }
    doPbkdf();
    if (isHsm) {
      slotManager.setSecretKeysDerivable( false );
    }
    doHmac();

    // Derive
    if (isHsm) {
      System.out.println("\n--- Derive:\n");
      doDerive();
      doHmac();
    }

    // Logout HSM and exit
    if (isHsm) {
      slotManager.logout();
    }
  }

}
