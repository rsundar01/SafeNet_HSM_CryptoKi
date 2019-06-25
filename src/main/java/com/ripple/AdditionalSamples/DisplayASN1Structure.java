
package com.ripple.AdditionalSamples;

import java.util.Base64;

import org.bouncycastle.asn1.ASN1InputStream;
import org.bouncycastle.asn1.ASN1Primitive;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.util.ASN1Dump;

public class DisplayASN1Structure {

	static byte [] asn1PrivHSM = hexStringToByteArray("3035301006032B656406092B06010401DA470F01032100B047178B617DB2A5AD465DD860718BD64A200A968E2060D45CA5E7CFBDC02007");
	static byte[] asn1Openssl = Base64.getDecoder().decode("MCowBQYDK2VwAyEAImRU6xfdqsj3Fni8B/CZdO8DXlB3GtLTRfEtcvI8zBk=");

	public static void main(String[] args) throws Exception
	{

		/**
		 * Display the base64 key strucutre
		 */
		ASN1InputStream input = new ASN1InputStream(asn1Openssl);
	
		/**
		 * Display the asn1 structure and private key
		 */
		//ASN1InputStream input = new ASN1InputStream(asn1PrivHSM);
		
		System.out.println("ASN1 structure value = " + bytesToHex(asn1Openssl));
		System.out.println("Private ASN 1 structure detail");
		ASN1Primitive p;

		while ((p = input.readObject()) != null) {
			ASN1Sequence asn1 = ASN1Sequence.getInstance(p);
			System.out.println(ASN1Dump.dumpAsString(p, true));
		}
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
}
