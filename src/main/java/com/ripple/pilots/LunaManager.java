package com.ripple.pilots;

import com.safenetinc.jcprov.*;
import com.safenetinc.jcprov.constants.*;
import com.safenetinc.luna.LunaSlotManager;

public class LunaManager {

    static String importedKeyLabel = "test_default_key_01";
    static CK_ATTRIBUTE[] privateTemplate =
            {
                    new CK_ATTRIBUTE(CKA.CLASS,     CKO.PRIVATE_KEY),
                    new CK_ATTRIBUTE(CKA.TOKEN,     CK_BBOOL.TRUE),
                    //No object for Edward key need to specify the long value
                    new CK_ATTRIBUTE(CKA.KEY_TYPE,  0x80000012),
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

    public static void importEd25519PrivateKey(byte[] wrappedKey, String aesWrappingKeyLabel, String importedKeyLabel)
    {
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

            privateTemplate[4] = new CK_ATTRIBUTE(CKA.LABEL, importedKeyLabel.getBytes());
            CryptokiEx.C_UnwrapKey(session, mechanism, hKey, wrappedKey, wrappedKey.length,
                    privateTemplate, privateTemplate.length, hAesUnWrapKey);
            System.out.println("Unwrap wrapped ECC Edward key with AES key: symmetric handle (" +
                    hKey.longValue() +") - Unwrapped AES handle (" +
                    hAesUnWrapKey.longValue() + ")");

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
    }

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
