package com.ripple.samples;

import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.KeyStoreException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.cert.CertificateException;

import javax.crypto.KeyGenerator;
import javax.crypto.SealedObject;

import com.safenetinc.luna.LunaTokenObject;
import com.safenetinc.luna.provider.key.LunaKey;

public class KeyGeneratorDemo {

  // Configure these as required.
  private static final int slot = 0;
  private static final String passwd = "userpin";
  public static final String provider = "LunaProvider";
  public static final String keystoreProvider = "Luna";
  public static SealedObject so = null;

  public static void main(String[] args) {

    KeyStore myStore = null;
    try {

      /* Note: could also use a keystore file, which contains the token label or slot no. to use. Load that via
       * "new FileInputStream(ksFileName)" instead of ByteArrayInputStream. Save objects to the keystore via a
       * FileOutputStream. */

      ByteArrayInputStream is1 = new ByteArrayInputStream(("slot:" + slot).getBytes());
      myStore = KeyStore.getInstance("Luna");
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
      KeyPairGenerator kpg;
      kpg = KeyPairGenerator.getInstance("ECwithExtraRandomBits", provider);
      KeyPair kp = kpg.generateKeyPair();
      LunaKey key = (LunaKey) kp.getPublic();
      LunaTokenObject lto = LunaTokenObject.LocateObjectByHandle(key.GetKeyHandle());
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      KeyGenerator kg = KeyGenerator.getInstance("DES", provider);
      LunaKey key = (LunaKey) kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      KeyGenerator kg = KeyGenerator.getInstance("DES2", provider);
      LunaKey key = (LunaKey) kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      KeyGenerator kg = KeyGenerator.getInstance("DESede", provider);
      LunaKey key = (LunaKey) kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      KeyGenerator kg = KeyGenerator.getInstance("AES", provider);
      LunaKey key = (LunaKey) kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      KeyGenerator kg = KeyGenerator.getInstance("ARIA", provider);
      LunaKey key = (LunaKey) kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      KeyGenerator kg = KeyGenerator.getInstance("HmacSHA1", "LunaProvider");
      LunaKey key = (LunaKey) kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

    try {
      KeyGenerator kg = KeyGenerator.getInstance("HmacSM3", "LunaProvider");
      LunaKey key = (LunaKey) kg.generateKey();
    } catch (NoSuchAlgorithmException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    } catch (NoSuchProviderException e) {
      // TODO Auto-generated catch block
      e.printStackTrace();
    }

  }
}
