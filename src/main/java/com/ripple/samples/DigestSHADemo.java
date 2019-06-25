package com.ripple.samples;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;
import java.util.Arrays;
import java.util.Random;

public class DigestSHADemo {

  // Configure these as required.
  private static final int slot = 0;
  private static final String passwd = "userpin";
  public static final String provider = "LunaProvider";
  public static final String keystoreProvider = "Luna";

  /**
   * subset.
   */
  public static byte[] subset(byte[] src, int offset, int n) throws Exception {
    byte[] dest = new byte[n];
    System.arraycopy(src, offset, dest, 0, n);
    return dest;
  }

  public static void main(String[] args) {

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
      Random r = new Random();
      int mLength;
      String algorithm;
      algorithm = "SHA1";
      algorithm = "SHA224";
      algorithm = "SHA256";
      algorithm = "SHA384";
      algorithm = "SHA512";
      if (algorithm.equalsIgnoreCase("MD2")) {
        mLength = 16;
      } else if (algorithm.equalsIgnoreCase("SHA1")) {
        mLength = 20;
      } else if (algorithm.equalsIgnoreCase("SHA224")) {
        mLength = 28;
      } else if (algorithm.equalsIgnoreCase("SHA256")) {
        mLength = 32;
      } else if (algorithm.equalsIgnoreCase("SHA384")) {
        mLength = 48;
      } else if (algorithm.equalsIgnoreCase("SHA512")) {
        mLength = 64;
      } else if (algorithm.equalsIgnoreCase("SM3")) {
        mLength = 32;
      } else {
        mLength = 16;
      }
      byte[] orig = new byte[1 + 64 + 1]; /* at least (1+64+1) bytes */
      r.nextBytes(orig);

      MessageDigest dig1 = MessageDigest.getInstance(algorithm, "LunaProvider");
      dig1.update(orig);
      byte[] enc = dig1.digest();
      if (enc.length == mLength) {
        System.out.println("length of digest is correct");
      }

      MessageDigest dig2 = MessageDigest.getInstance(algorithm, "LunaProvider");
      dig2.update(subset(orig, 0, 1));
      dig2.update(subset(orig, 1, 64));
      dig2.update(subset(orig, 65, 1));
      byte[] dec = dig2.digest();
      if (Arrays.equals(dec, enc)) {
        System.out.println("The digests are equal");
      }

    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (Exception e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }
}
