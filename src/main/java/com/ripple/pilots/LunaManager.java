package com.ripple.pilots;

import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;
import com.safenetinc.luna.LunaSlotManager;

public class LunaManager {

    static String importedKeyLabel = "test_imported_ed25519_04";
    private static final CK_KEY_TYPE EDWARD_KEY_VALUE = new CK_KEY_TYPE(0x80000012);
    private static final long EDDSA_MECHANISM_VALUE = 0x80000c03L;
    private static final int SIGNATURE_LENGTH = 64;


    static CK_ATTRIBUTE[] privateTemplate =
            {
                    new CK_ATTRIBUTE(CKA.CLASS,     CKO.PRIVATE_KEY),
                    new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
                    //No object for Edward key need to specify the long value
                    new CK_ATTRIBUTE(CKA.KEY_TYPE,  EDWARD_KEY_VALUE),
                    new CK_ATTRIBUTE(CKA.SENSITIVE, CK_BBOOL.TRUE),
                    new CK_ATTRIBUTE(CKA.LABEL,    importedKeyLabel.getBytes()),
                    new CK_ATTRIBUTE(CKA.PRIVATE,   CK_BBOOL.TRUE),
                    new CK_ATTRIBUTE(CKA.DECRYPT,   CK_BBOOL.TRUE),
                    new CK_ATTRIBUTE(CKA.DERIVE,    CK_BBOOL.TRUE),
                    new CK_ATTRIBUTE(CKA.UNWRAP,    CK_BBOOL.TRUE),
                    new CK_ATTRIBUTE(CKA.SIGN,      CK_BBOOL.TRUE),
            };
    private static final byte[] pwd_4  = "crypto1".getBytes();	/* Partition 1 password */
    private static final int slot = 0;		/* Partition 1 name */
    private static LunaSlotManager lunaSlotManager = LunaSlotManager.getInstance();
    
    public synchronized static boolean detectToken() {
        boolean istokenPresent = false;
        try {
            lunaSlotManager.detectTokenConnectionProblem(slot);
            istokenPresent = true;
        } catch (Exception e) { }
        return istokenPresent;
    }
    
    public synchronized  static boolean requiresInitialization() {
        return lunaSlotManager.getReconnectRequired();
    }

    public synchronized  static boolean initializeHSM() {
        boolean isInitialized = false;
        if(requiresInitialization()) {
            lunaSlotManager.reinitialize(true);
            isInitialized = true;
        }
        return isInitialized;
    }

    public static boolean importEd25519PrivateKey(byte[] wrappedKey, String aesWrappingKeyLabel, String importedKeyLabel)
    {
        boolean importSuccessful = false;
        CK_SESSION_HANDLE session = new CK_SESSION_HANDLE();
        long slotId = slot;
        try
        {
            /*
             * Initialize Cryptoki so that the library takes care
             * of multithread locking
             */
            try {
                CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
            }catch(CKR_Exception e){
                if(401 != e.ckrv.intValue()) {
                    throw e;
                }
            }

            /*
             * Open a session
             */
            CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null, session);
            CryptokiEx.C_Login(session, CKU.USER, pwd_4, pwd_4.length);

            //localte the ECC key TODO change the label of the key here
            boolean bPrivate = true;
            CK_OBJECT_HANDLE hKey = null;
            //Find symmetric key for unwrapping
            hKey = findKey(session, CKO.SECRET_KEY, CKK.AES, aesWrappingKeyLabel, bPrivate);
            //create the mechanism
            // Setup mechanism. we wrap the key with IV 1234567812345678 so need to prepare the mechanism so that the unwrap is step the same way.
            CK_MECHANISM mechanism = new CK_MECHANISM(CKM.AES_CBC_PAD,"1234567812345678".getBytes());
            CK_OBJECT_HANDLE hAesUnWrapKey = new CK_OBJECT_HANDLE();

            //privateTemplate[4] = new CK_ATTRIBUTE(CKA.LABEL, importedKeyLabel.getBytes());
            CryptokiEx.C_UnwrapKey(session, mechanism, hKey, wrappedKey, wrappedKey.length,
                    privateTemplate, privateTemplate.length, hAesUnWrapKey);
            System.out.println("Unwrap wrapped ECC Edward key with AES key: symmetric handle (" +
                    hKey.longValue() +") - Unwrapped AES handle (" +
                    hAesUnWrapKey.longValue() + ")");
            importSuccessful = true;

        }
        catch (CKR_Exception ex)
        {
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
            //Cryptoki.C_Logout(session);

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
            //Cryptoki.C_Finalize(null);
        }
        return importSuccessful;
    }

    public static CK_OBJECT_HANDLE findKey(CK_SESSION_HANDLE session,
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
                        //new CK_ATTRIBUTE(CKA.KEY_TYPE,  keyType),
                        new CK_ATTRIBUTE(CKA.KEY_TYPE, 0x80000012),
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


    private static byte[] doSignature(CK_SESSION_HANDLE session,
                               CK_OBJECT_HANDLE privateKey,
                               byte[] data) {

        byte[] signature = new byte[SIGNATURE_LENGTH];
        CK_MECHANISM mechanism = new CK_MECHANISM(new CK_MECHANISM_TYPE(EDDSA_MECHANISM_VALUE));
        CryptokiEx.C_SignInit(session, mechanism, privateKey);
        CryptokiEx.C_SignUpdate(session, data, data.length);
        CryptokiEx.C_SignFinal(session, signature, new LongRef(SIGNATURE_LENGTH));
        return signature;
    }

    public static byte[] getSignature(String keyLabel, String data) {
        CK_SESSION_HANDLE session = JcprovSessionManager.openSession();
        if(session == null) return null;
        CK_OBJECT_HANDLE privateKey = findKey(session, CKO.PRIVATE_KEY, EDWARD_KEY_VALUE,
                                            keyLabel, true);
        if(privateKey == null) return null;
        byte[] signature = doSignature(session, privateKey, data.getBytes());
        return signature;
    }

    private static int doverify(CK_SESSION_HANDLE session, CK_OBJECT_HANDLE publickey,
                                    byte[] dataToVerify, byte[] signature) {
        CK_MECHANISM mechanism = new CK_MECHANISM(new CK_MECHANISM_TYPE(EDDSA_MECHANISM_VALUE));
        CryptokiEx.C_VerifyInit(session, mechanism, publickey);
        CryptokiEx.C_VerifyUpdate(session, dataToVerify, dataToVerify.length);
        CK_RV ret = CryptokiEx.C_VerifyFinal(session, signature, signature.length);
        return ret.intValue();
    }

    public static int verifySignature(String keyLabel, String data, byte[] signature) {
        CK_SESSION_HANDLE session = JcprovSessionManager.openSession();
        if(session == null) return -1;
        CK_OBJECT_HANDLE publicKey = findKey(session, CKO.PUBLIC_KEY, EDWARD_KEY_VALUE,
                keyLabel, false);
        if(publicKey == null) return -1;
        int r = doverify(session, publicKey, data.getBytes(), signature);
        return r;
    }


}
