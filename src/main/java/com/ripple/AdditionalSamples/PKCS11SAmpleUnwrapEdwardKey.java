package com.ripple.AdditionalSamples;

import com.safenetinc.jcprov.CKR_Exception;
import com.safenetinc.jcprov.CK_ATTRIBUTE;
import com.safenetinc.jcprov.CK_BBOOL;
import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.CK_MECHANISM;
import com.safenetinc.jcprov.CK_OBJECT_HANDLE;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.LongRef;
import com.safenetinc.jcprov.constants.CKA;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKK;
import com.safenetinc.jcprov.constants.CKM;
import com.safenetinc.jcprov.constants.CKO;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.jcprov.constants.CK_KEY_TYPE;
import com.safenetinc.jcprov.constants.CK_OBJECT_CLASS;

public class PKCS11SAmpleUnwrapEdwardKey
{
	final static String fileVersion = "FileVersion: $Source: src/com/safenetinc/jcprov/sample/GenerateKey.java $ $Revision: 1.1.1.2 $";
	
	//TODO change your private key value encrypted ready for import, you can use ImportKnowECCPrivateCkdemo.java to prepare that value
	static byte [] wrappedKey = hexStringToByteArray("E49D93A8CF64C9901717B29A974155908825227CFAC1C9F556FF5EF305320190761FE3AA220849431420B7D89D821878086C874238B9BC23AB42AEDF3DD08938EBCDB8E531E3FDD69AAD8338C92DBDDD");
	
	
	
	// Unwrap template used by UNWRAP_TEMPLATE attribute.
    static String templatekeyName = "commonAESKey_2";
    
    static CK_ATTRIBUTE[] unWrapTemplate =
    {
        new CK_ATTRIBUTE(CKA.CLASS,     CKO.SECRET_KEY),
        new CK_ATTRIBUTE(CKA.KEY_TYPE,  CKK.AES),
        new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.ENCRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.DECRYPT,   CK_BBOOL.TRUE),
        new CK_ATTRIBUTE(CKA.LABEL,     templatekeyName.getBytes())
    };
	// Symmetric template.
    private static String keyLabel = "Edward JCPROV import";
    static CK_ATTRIBUTE[] privateTemplate =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     CKO.PRIVATE_KEY),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            //No object for Edward key need to specify the long value
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  0x80000012),
            new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyLabel.getBytes()),
            new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.DECRYPT,   CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.UNWRAP,    CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.SIGN,      CK_BBOOL.TRUE),
        };
	private static final byte[] pwd_4  = "Gemplus13".getBytes();	/* Partition 1 password */
	private static final int part_4 = 0;		/* Partition 1 name */
	/** easy access to System.out.println */
	static public void println(String s)
	{
		System.out.println(s);
	}


	
	/** main execution method */
	public static void main(String[] args)
	{
		CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
		long slotId = part_4;

		

		/*
		 * process command line arguments
		 */


		try
		{
			/*
			 * Initialize Cryptoki so that the library takes care
			 * of multithread locking
			 */
			CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));

			/*
			 * Open a session
			 */
			CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);

			CryptokiEx.C_Login(session, CKU.USER, pwd_4, pwd_4.length);



			
			
			//localte the ECC key TODO change the label of the key here
			String keyName = "commonAESKey_2";
			boolean bPrivate = true;
			CK_OBJECT_HANDLE hKey = null;
			//Find symmetric key for unwrapping
			hKey = findKey(session, CKO.SECRET_KEY, CKK.AES, keyName, bPrivate);
			//hKey = findKey(session, CKO.SECRET_KEY, 0x80000012, keyName, bPrivate);
			//System.out.println("value of key = " + hKey.longValue());
			
			
			//create the mechanism
	        // Setup mechanism. we wrap the key with IV 1234567812345678 so need to prepare the mechanism so that the unwrap is step the same way.
			CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_CBC_PAD,"1234567812345678".getBytes());
			
			CK_OBJECT_HANDLE hAesUnWrapKey = new CK_OBJECT_HANDLE();

            CryptokiEx.C_UnwrapKey(session, mechanism, hKey, wrappedKey, wrappedKey.length,
            		privateTemplate, privateTemplate.length, hAesUnWrapKey);
            System.out.println("Unwrap wrapped ECC Edward key with AES key: symmetric handle (" +
            		hKey.longValue() +") - Unwrapped AES handle (" +
            		hAesUnWrapKey.longValue() + ")");

		}
		catch (CKR_Exception ex)
		{
			/*
			 * A Cryptoki related exception was thrown
			 */
			ex.printStackTrace();
		}
		catch (Exception ex)
		{
			ex.printStackTrace();
		}
		finally
		{
			/*
			 * Logout in case we logged in.
			 *
			 * Note that we are not using CryptokiEx and we are not checking the
			 * return value. This is because if we did not log in then an error
			 * will be reported - and we don't really care because we are shutting down.
			 */
			Cryptoki.C_Logout(session);

			/*
			 * Close the session.
			 *
			 * Note that we are not using CryptokiEx.
			 */
			Cryptoki.C_CloseSession(session);

			/*
			 * All done with Cryptoki
			 *
			 * Note that we are not using CryptokiEx.
			 */
			Cryptoki.C_Finalize(null);
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
	/**
     * Locate the specified key.
     *
     * @param session
     *  handle to an open session
     *
     * @param keyClass
     *  {@link com.safenetinc.jcprov.constants.CKO} class of the key to locate
     *
     * @param keyName
     *  name (label) of the key to locate
     *
     * @param bPrivate
     *  true if the key to locate is a private object
     */
    static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session,
                                    CK_OBJECT_CLASS keyClass,
                                    CK_KEY_TYPE keyType,
                                    String keyName,
                                    boolean bPrivate)
    {
        /* array of one object handles */
        CK_OBJECT_HANDLE[] hObjects = {new CK_OBJECT_HANDLE()};

        /* to receive the number of objects located */
        LongRef objectCount = new LongRef();

        /* setup the template of the object to search for */
        CK_ATTRIBUTE[] template =
        {
            new CK_ATTRIBUTE(CKA.CLASS,     keyClass),
            new CK_ATTRIBUTE(CKA.KEY_TYPE,  keyType),
            new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
            new CK_ATTRIBUTE(CKA.LABEL,     keyName.getBytes()),
            new CK_ATTRIBUTE(CKA.PRIVATE,   new CK_BBOOL(bPrivate))
        };

        CryptokiEx.C_FindObjectsInit(session, template, template.length);

        CryptokiEx.C_FindObjects(session, hObjects, hObjects.length, objectCount);

        CryptokiEx.C_FindObjectsFinal(session);

        if (objectCount.value == 1)
        {
            /* return the handle of the located object */
            return hObjects[0];
        }
        else
        {
            /* return an object handle which is invalid */
            return new CK_OBJECT_HANDLE();
        }
    }

	



}
