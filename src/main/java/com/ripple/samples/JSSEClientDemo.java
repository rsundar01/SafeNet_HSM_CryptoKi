package com.ripple.samples; /*******************************************************************************
 *
 * Copyright (c) 2018 SafeNet, All rights reserved.
 *  
 * All rights reserved.  This file contains information that is
 * proprietary to SafeNet and may not be distributed
 * or copied without written consent from SafeNet.
 *******************************************************************************/

import java.io.BufferedWriter;
import java.io.FileInputStream;
import java.io.OutputStreamWriter;
import java.security.Key;
import java.security.KeyStore;
import java.util.Base64;

import javax.net.ssl.KeyManagerFactory;
import javax.net.ssl.SSLContext;
import javax.net.ssl.SSLParameters;
import javax.net.ssl.SSLSocket;
import javax.net.ssl.SSLSocketFactory;
import javax.net.ssl.TrustManagerFactory;

//import sun.misc.BASE64Encoder;

public class JSSEClientDemo {

  private static final String passwdForKeyStore = "123456";
  private static final String passwdForTrustStore = "123456";

  // Steps to generate client keys and certs:
  // 1. generate an SSL-based client RSA key pair and cert file-based jks
  // on the client box:
  // keytool -genkey -v -keystore client.jks -keypass 123456 -storepass 123456 -dname "cn=rmorton, ou=jsp, o=gemalto,
  // c=CA" -keyalg RSA -alias selfsignedclient -validity 360 -keysize 2048

  // 2. import the self-signed client cert into the Luna SA for authentication from a remote client
  // on the client box:
  // keytool -export -v -keystore client.jks -keypass 123456 -storepass 123456 -alias selfsignedclient -file
  // clientForServer.cer
  // on the server box:
  // copy clientForServer.cer to server box
  // keytool -import -v -trustcacerts -storetype luna -keystore lunassl.ks -keypass userpin -storepass userpin -alias
  // selfsignedclient -file clientForServer.cer

  static public void clientSocket() throws Exception {

    // init key manager - for client auth
    // comment out this section if client auth not wanted...ensure server is not expecting it
    char[] ksPass = passwdForKeyStore.toCharArray();
    KeyStore ks = KeyStore.getInstance(KeyStore.getDefaultType());
    FileInputStream ksFile = new FileInputStream("client.jks");
    ks.load(ksFile, ksPass);
    KeyManagerFactory kmf = KeyManagerFactory.getInstance("SunX509");
    kmf.init(ks, ksPass);
    // get private key from jks file keystore
    String aliasName = new String("selfsignedclient");
    Key key = ks.getKey(aliasName, passwdForKeyStore.toCharArray());
    //String b64 = new BASE64Encoder().encode(key.getEncoded());
    byte[] aNewB64 = Base64.getEncoder().encode(key.getEncoded());
    String b64 = new String(aNewB64);
    System.out.println("-----BEGIN PRIVATE KEY-----");
    System.out.println(b64);
    System.out.println("-----END PRIVATE KEY-----");
    // comment out to here for no client auth

    // now trust manager - for client assume anything but Luna SA (e.g. jks)
    char[] tsPass = passwdForTrustStore.toCharArray();
    KeyStore ts = KeyStore.getInstance(KeyStore.getDefaultType());
    FileInputStream tsFile = new FileInputStream("cacertsForClient.jks");
    ts.load(tsFile, tsPass);
    TrustManagerFactory tmf = TrustManagerFactory.getInstance("SunX509");
    tmf.init(ts);

    // SSLContext sslctx = SSLContext.getInstance("TLSv1.1");
    SSLContext sslctx = SSLContext.getInstance("TLSv1.2");
    // uncomment following line for no client auth
    // sslctx.init(null, tmf.getTrustManagers(), null);
    // comment following line for no client auth
    sslctx.init(kmf.getKeyManagers(), tmf.getTrustManagers(), null);

    SSLSocketFactory ssf = sslctx.getSocketFactory();
    SSLSocket socket = (SSLSocket) ssf.createSocket("127.0.0.1", 10123);
    SSLParameters sslParams = new SSLParameters();
    sslParams.setEndpointIdentificationAlgorithm("HTTPS");
    socket.setSSLParameters(sslParams);

    try {
      BufferedWriter writer = new BufferedWriter(new OutputStreamWriter(socket.getOutputStream()));
      writer.write("Hello from the SSL/TLS client!\n");
      writer.close();
    } finally {
      socket.close();
    }
  }

  public static void main(String args[]) throws Exception {

//    java.lang.System.setProperty("javax.net.debug", "all");

    System.out.println("This sample should be used in conjunction with JSSEServerDemo...");
    System.out.println("It has a dependency on jdk1.8...");
    System.out.println();
    System.out.println(
        "Pease see instructions in the comments at the beginning of both of these related classes...");
    System.out.println();

    clientSocket();

  }

}
