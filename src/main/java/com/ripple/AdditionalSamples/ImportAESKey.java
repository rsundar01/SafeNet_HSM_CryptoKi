package com.ripple.AdditionalSamples;

import java.math.BigInteger;
import java.security.InvalidAlgorithmParameterException;
import java.security.KeyPair;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SecureRandom;
import java.security.Security;
import java.security.spec.RSAKeyGenParameterSpec;
import java.util.Date;

import javax.crypto.Cipher;
import javax.crypto.spec.SecretKeySpec;

import org.bouncycastle.jce.provider.BouncyCastleProvider;

import com.safenetinc.luna.LunaAPI;
import com.safenetinc.luna.LunaSlotManager;
import com.safenetinc.luna.LunaTokenObject;

// This sample show how to exchange a AES symmetric key between 2 HSMs partitions


import com.safenetinc.luna.exception.LunaException;
import com.safenetinc.luna.provider.LunaCertificateX509;
import com.safenetinc.luna.provider.LunaProvider;
import com.safenetinc.luna.provider.key.LunaKey;
import com.safenetinc.luna.provider.keygen.LunaKeyPairGeneratorRsa;







public class ImportAESKey {

	// TODO Configure these as required.
	private static final String pwd0  = "Gemplus13";	/* Partition 0 password */
	private static final int part_0 = 0;		/* Partition 0 slot number*/


	private static LunaSlotManager manager;



	// ********************************************
	// Generate the HSM RSA key pair 
	// ********************************************
	public static KeyPair lunaGenerateRsaKeyPair(int keySize, BigInteger publicExponent) throws NoSuchAlgorithmException,
	NoSuchProviderException, InvalidAlgorithmParameterException
	{
		Security.addProvider(new LunaProvider());
		LunaKeyPairGeneratorRsa kpg = new LunaKeyPairGeneratorRsa();	    
		RSAKeyGenParameterSpec  kgps = new RSAKeyGenParameterSpec(keySize, publicExponent);

		kpg.initialize(kgps, SecureRandom.getInstance("LunaRNG"));
		KeyPair kp = kpg.generateKeyPair();

		// make private key not extractable
		//SetKeyAttributeToNotExtractable(((LunaKey)kp.getPrivate()).GetKeyHandle());

		((LunaKey)kp.getPrivate()).MakePersistent("priv_RSA_IMPORT_AES"+keySize); // you can check the persisted key by running C:\Program Files\SafeNet\LunaClient>cmu getattribute
		((LunaKey)kp.getPrivate()).MakePersistent("publ_RSA_IMPORT_AES"+keySize); // you can check the persisted key by running C:\Program Files\SafeNet\LunaClient>cmu getattribute

		return kp;
	}

	// ********************************************
	// Set working partition 
	// ********************************************
	public static void SetWorkingPartitionTo(int slot_part)
	{
		// Sets the default partition to the given partition. 
		boolean ret4 = manager.setDefaultSlot(slot_part);
		System.out.println("------------------\n- Current slot " + manager.getDefaultSlot()+" -\n------------------");
	}

	// ********************************************
	// Set key attribute to NOT EXTRACTABLE
	// ********************************************
	public static void SetKeyAttributeToNotExtractable(int KeyHandle)
	{

		// modify the object attribute CKA_EXTRACTABLE
		LunaTokenObject Obj = null;

		try {
			Obj = LunaTokenObject.LocateObjectByHandle(KeyHandle);
			

			// get/set a small attribute value - CKA_EXTRACTABLE
			Obj.SetSmallAttribute(LunaAPI.CKA_PRIVATE, 0); //set key not extractable cannot be exported

		}
		catch (LunaException le) {
			System.out.println("LunaException: " + le.getMessage());
			le.printStackTrace();
			System.exit(-1);
		}
		catch (Exception ex) {
			System.out.println("Got unexpected Exception while modifying attributes");
			ex.printStackTrace();
			System.exit(-1);
		}
	}



	// ********************************************
	// Main 
	// ********************************************
	public static void main(String[] args) throws Exception
	{
		// login into the both partitions  ( PART1 & PART2 )
		manager = LunaSlotManager.getInstance();
		manager.setSecretKeysExtractable(false);
		Security.addProvider(new LunaProvider());


		if (manager.login(part_0, pwd0) == false )
		{
			System.out.println("Login to " + part_0 + " failed");
			System.exit(1);
		}
		


		Security.addProvider(new BouncyCastleProvider());


		//===============================================================================
		// Set working partition to PART1
		//===============================================================================
		SetWorkingPartitionTo(part_0);



		// generate RSA 4096 key pair in the HSM (CKM_RSA_PKCS_KEY_PAIR_GEN) with public exponent-value F4 = 65537.
		KeyPair rsaPriv = lunaGenerateRsaKeyPair(4096, RSAKeyGenParameterSpec.F4);
		

		// generate self signed certificate with the RSA key pair and SHA256 hash
		// this is not ideal but it's a shortcut, normally I should use a certificate chain with a CA for the source of trust 
		// and avoid the man in the middle attack.
		BigInteger serialNumber = new BigInteger("0");
		Date notBefore = new Date();
		Date notAfter = new Date(notBefore.getTime() + 1000000000);
		LunaCertificateX509[] certChain = new LunaCertificateX509[1];
		certChain[0] = LunaCertificateX509.SelfSign("SHA256withRSA",rsaPriv, "CN=Cert Part_1, L=london, C=UK", serialNumber, notBefore, notAfter, 0);
		System.out.println("Certificate selfsign created needed to unwrap key in the HSM");
		byte certPart1HEX[] = certChain[0].getEncoded();
		certChain[0].MakePersistent("SelfSignedCertFromPart_FOR_AES");
		// Copy certificate from PART1 into PART2
		LunaCertificateX509 cert2 = LunaCertificateX509.LocateCertByAlias("SelfSignedCertFromPart_FOR_AES");

		//AES key to be imported in the HSM value = 01020304050607080910111213141516
		byte[] encoded = hexStringToByteArray("01020304050607080910111213141516");
		SecretKeySpec skeySpec = new SecretKeySpec(encoded, "AES");

		// wrap the AESkey with the public key Cert using BoucyCastle
		Cipher c2 = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "BC"); // RSA/ECB/PKCS1Padding   RSA/ECB/OAEPWithSHA1AndMGF1Padding
		c2.init(Cipher.WRAP_MODE, cert2.getPublicKey());
		byte[] aesWrappedKey = c2.wrap(skeySpec);
		
		//Uwrap the AES keys to be stored in the HSM
		Cipher c1 = Cipher.getInstance("RSA/ECB/OAEPWithSHA1AndMGF1Padding", "LunaProvider"); // RSA/ECB/PKCS1Padding   RSA/ECB/OAEPWithSHA1AndMGF1Padding
		c1.init(Cipher.UNWRAP_MODE, rsaPriv.getPrivate());
		LunaKey aesKey = (LunaKey)c1.unwrap(aesWrappedKey, "AES", Cipher.SECRET_KEY);
		//SetKeyAttributeToNotExtractable(aesKey.GetKeyHandle());
		aesKey.MakePersistent("AES wrappingKey");
		System.out.println("AES Key unwrapped in the HSM, use ckdemo to verify that hte key was loaded in the HSM");

		

		
		// logout
		manager.logout(part_0);
		

		new ImportAESKey();
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

	
}

