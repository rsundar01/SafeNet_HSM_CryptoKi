package com.ripple.AdditionalSamples;

import java.io.FileInputStream;
import java.io.FileOutputStream;
import java.io.IOException;
import java.security.Key;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.Security;
import java.util.Arrays;
import java.util.Enumeration;

import javax.crypto.Cipher;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1OctetString;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.DERBitString;
import org.bouncycastle.asn1.util.ASN1Dump;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


public class PrepareECCPrivateKeyForCkdemo {


	String asn1PrivStruc = "303F020100301006032B656406092B06010401DA470F0104283026020101042100C38DB94C0E23C0CB912E363E86F708F3A1E7E3C409810F9E983DD25ACA656BBE";
	//ASN1 structure when length of the keys is 33 bytes (leading 00 to positive the integer)
	static byte[] asn1PrivateKeyStructure33bytes = new byte[] {(byte)0x30, (byte)0x3F, (byte)0x02, (byte)0x01, (byte)0x00, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x03, 
			(byte)0x2B, (byte)0x65, (byte)0x64, (byte)0x06, (byte)0x09, (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01, (byte)0xDA, (byte)0x47, (byte)0x0F, 
			(byte)0x01, (byte)0x04, (byte)0x28, (byte)0x30, (byte)0x26, (byte)0x02, (byte)0x01, (byte)0x01, (byte)0x04, (byte)0x21};

	//Todo Replace your private / public key accordingly
	static byte[] eccPrivKeyValue = hexStringToByteArray("B5B444E0A7BE9B52F4F922EFEE046D165A0B704ACD6374563B8CC95B4C53C85D");
	static byte[] eccPublKeyValue = hexStringToByteArray("00D9F947FB606FDAE8052EDA237C748497D2A14B8EDC862C61EAAB5D2362A9F068");

	static byte[] asn1PublicStruct = new byte[] {(byte)0x30, (byte)0x35, (byte)0x30, (byte)0x10, (byte)0x06, (byte)0x03, (byte)0x2B, 
			(byte)0x65, (byte)0x64, (byte)0x06, (byte)0x09, (byte)0x2B, (byte)0x06, (byte)0x01, (byte)0x04, (byte)0x01, (byte)0xDA,
			(byte)0x47, (byte)0x0F, (byte)0x01, (byte)0x03, (byte)0x21};


	public static void main(String[] args) throws Exception
	{
		/**
		 * This is to understand to structure of the JAVA Edward key representation and where the public and private key are
		 */
		Security.addProvider(new BouncyCastleProvider());
		byte[] eccPrikeyASN1 = null;
		byte[] eccPrivValue = eccPrivKeyValue;
		//byte[] eccPrivValue = customerKey();
		// byte[]eccPrikey = extractCustomerECCKey(eccPrivValue);
		//byte[] eccPrivValue = generateECCKey();


		/**
		 * Prepare the private Key
		 */

		//prepare the byte array with ASN1 + ec private key
		//depending on the size of the ECC private key the ASN1 structure will be slightly different specially n the length values
		if (eccPrivValue.length == 33) {
			eccPrikeyASN1= new byte[asn1PrivateKeyStructure33bytes.length + eccPrivValue.length];
			System.arraycopy(asn1PrivateKeyStructure33bytes, 0, eccPrikeyASN1, 0, asn1PrivateKeyStructure33bytes.length);
			System.arraycopy(eccPrivValue, 0, eccPrikeyASN1, asn1PrivateKeyStructure33bytes.length, eccPrivValue.length);
		}else if(eccPrivValue.length == 32) {
			eccPrikeyASN1 = new byte[asn1PrivateKeyStructure33bytes.length + eccPrivValue.length + 1];
			System.arraycopy(asn1PrivateKeyStructure33bytes, 0, eccPrikeyASN1, 0, asn1PrivateKeyStructure33bytes.length);
			eccPrikeyASN1[asn1PrivateKeyStructure33bytes.length] = 0x00; //need to add 0x00 to be sure that it is not a negative integer
			System.arraycopy(eccPrivValue, 0, eccPrikeyASN1, asn1PrivateKeyStructure33bytes.length + 1, eccPrivValue.length);
		}else {
			System.out.println("Private key size not supported = " + eccPrivValue.length);
			throw new Exception("Wrong key lengths");
		}

		displayASN1KeyForCKdemo(eccPrikeyASN1);

		//encrypt the keys for HSM injection
		Security.addProvider(new BouncyCastleProvider());
		byte[] encoded = hexStringToByteArray("01020304050607080910111213141516");
		
		SecretKeySpec skeySpec = new SecretKeySpec(encoded, "AES");
		Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding",  "BC");
		//ckdemo will wait for an IV of 1234567812345678
		cipher.init(Cipher.ENCRYPT_MODE, skeySpec, new IvParameterSpec("1234567812345678".getBytes()));
		byte[] doFinal = cipher.doFinal(eccPrikeyASN1);
		//System.out.println("luna CM key decrypted decodeBase64 ="+ KMSEncodingUtils.encodeBase64(doFinal));
		System.out.println("EC ED Priv Key for ckdemo ="+ bytesToHex(doFinal));

		//write to binary file
		FileOutputStream fos = new FileOutputStream("KnowECCSteven");
		fos.write(doFinal);
		fos.close();



	

	}


	private static byte[] customerKey() throws Exception {
		final char[] keyPassphrase = "password".toCharArray();
		final KeyStore ks = KeyStore.getInstance("PKCS12");
		ks.load(new FileInputStream("keystore-CI.pkcs12"), keyPassphrase);
		Enumeration<String> enumerations = ks.aliases();

		while (enumerations.hasMoreElements()){

			String alias = enumerations.nextElement();

			System.out.println(alias);

		}

		Key key = ks.getKey("rn_node_privkey", "password".toCharArray());
		
		ASN1Primitive p;
		ASN1InputStream input = new ASN1InputStream(key.getEncoded());
		byte[] filteredByteArray = null;
		while ((p = input.readObject()) != null) {
			ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
			ASN1OctetString octetString= ASN1OctetString.getInstance(asn1.getObjectAt(2));
			//Remove Tag and length from ASN1 structure to retreive private key
			filteredByteArray = Arrays.copyOfRange(octetString.getOctets(), 2, octetString.getOctets().length);
			System.out.println(ASN1Dump.dumpAsString(p, true));
			System.out.println("------>>>>> This is the private key value = " + bytesToHex(filteredByteArray));
		}
		System.out.println("Value of customer key rn_code_privkey = " + bytesToHex(key.getEncoded()));
		return key.getEncoded();

	}


	public static byte[] hexStringToByteArray(String s) {
		int len = s.length();
		byte[] data = new byte[len / 2];
		for (int i = 0; i < len; i += 2) {
			data[i / 2] = (byte) ((Character.digit(s.charAt(i), 16) << 4)
					+ Character.digit(s.charAt(i+1), 16));
		}
		return data;
	}

	private final static char[] hexArray = "0123456789ABCDEF".toCharArray();
	public static String bytesToHex(byte[] bytes) {
		char[] hexChars = new char[bytes.length * 2];
		for ( int j = 0; j < bytes.length; j++ ) {
			int v = bytes[j] & 0xFF;
			hexChars[j * 2] = hexArray[v >>> 4];
			hexChars[j * 2 + 1] = hexArray[v & 0x0F];
		}
		return new String(hexChars);
	}


	private static void displayASN1KeyForCKdemo(byte[] asn1key) throws IOException {
		ASN1InputStream input = new ASN1InputStream(asn1key);
		ASN1Primitive p;
		byte[] filteredByteArray = null;
		System.out.println("Display ASN1 strucutre ready for cipher then import in CKDEMO");
		while ((p = input.readObject()) != null) {
			System.out.println(ASN1Dump.dumpAsString(p, true));
		}
	}



	private static byte[] generateECCKey() throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
		KeyPair kp = kpg.generateKeyPair();
		System.out.println("ECC key generated " + kp.getPublic().getAlgorithm());
		System.out.println("ECC ASN 1 private key generated value = " + bytesToHex(kp.getPrivate().getEncoded()));
		System.out.println("ECC AS1 1 public key generated value = " + bytesToHex(kp.getPublic().getEncoded()));

		byte[] data = null; // obviously need to supply real data here
		ASN1InputStream input = new ASN1InputStream(kp.getPrivate().getEncoded());

		System.out.println("Private ASN 1 structure detail");
		ASN1Primitive p;
		byte[] filteredByteArray = null;
		while ((p = input.readObject()) != null) {
			ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
			ASN1OctetString octetString= ASN1OctetString.getInstance(asn1.getObjectAt(2));
			//Remove Tag and length from ASN1 structure to retreive private key
			filteredByteArray = Arrays.copyOfRange(octetString.getOctets(), 2, octetString.getOctets().length);
			System.out.println(ASN1Dump.dumpAsString(p, true));
			System.out.println("------>>>>> This is the private key value = " + bytesToHex(filteredByteArray));
		}

			    System.out.println("Public ASN 1 structure detail");
			    System.out.println("Public ASN 1 structure value : " + bytesToHex(kp.getPublic().getEncoded()));
			    input = new ASN1InputStream(kp.getPublic().getEncoded());
			    while ((p = input.readObject()) != null) {
			        System.out.println(ASN1Dump.dumpAsString(p, true));
			        ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
			        DERBitString  octetString= DERBitString.getInstance(asn1.getObjectAt(1));
			    	
			    	System.out.println("------>>>>> This is the public key value = " + bytesToHex(octetString.getOctets()));
			 	   
			    }


		return filteredByteArray;
	}
	private static byte[] extractCustomerECCKey(byte[] keyASN1Value) throws NoSuchAlgorithmException, NoSuchProviderException, IOException {
		//		KeyPairGenerator kpg = KeyPairGenerator.getInstance("Ed25519", "BC");
		//		KeyPair kp = kpg.generateKeyPair();
		//		System.out.println("ECC key generated " + kp.getPublic().getAlgorithm());
		//		System.out.println("ECC ASN 1 private key generated value = " + bytesToHex(kp.getPrivate().getEncoded()));
		//		System.out.println("ECC AS1 1 public key generated value = " + bytesToHex(kp.getPublic().getEncoded()));
		//		
		byte[] data = null; // obviously need to supply real data here
		ASN1InputStream input = new ASN1InputStream(keyASN1Value);

		System.out.println("Private ASN 1 structure detail");
		ASN1Primitive p;
		byte[] filteredByteArray = null;
		while ((p = input.readObject()) != null) {
			ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
			ASN1OctetString octetString= ASN1OctetString.getInstance(asn1.getObjectAt(2));
			filteredByteArray = Arrays.copyOfRange(octetString.getOctets(), 2, octetString.getOctets().length - 2);
			System.out.println(ASN1Dump.dumpAsString(p, true));
			System.out.println("------>>>>> This is the private key value = " + bytesToHex(filteredByteArray));
		}

		//	    System.out.println("Public ASN 1 structure detail");
		//	    input = new ASN1InputStream(kp.getPublic().getEncoded());
		//	    while ((p = input.readObject()) != null) {
		//	        System.out.println(ASN1Dump.dumpAsString(p, true));
		//	        ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
		//	        DERBitString  octetString= DERBitString.getInstance(asn1.getObjectAt(1));
		//	    	
		//	    	System.out.println("------>>>>> This is the public key value = " + bytesToHex(octetString.getOctets()));
		//	 	   
		//	    }


		return filteredByteArray;
	}
}
