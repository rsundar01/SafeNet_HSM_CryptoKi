package com.ripple.pilots;

import com.safenetinc.jcprov.CKR_Exception;
import com.safenetinc.jcprov.CK_SESSION_HANDLE;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.jcprov.constants.CKU;
import com.safenetinc.luna.LunaSlotManager;

public class JcprovSessionManager {

    private static CK_SESSION_HANDLE session = null;
    private static int slotId = 0;
    private static String password = "crypto1";

    public static CK_SESSION_HANDLE openSession() {

        if (!isValidSession()){
            if(!JcprovManager.isInitialized()){
                JcprovManager.initializeJcprov();
            }
            try {
                session = new CK_SESSION_HANDLE();
                CryptokiEx.C_OpenSession(slotId, CKF.RW_SESSION | CKF.SERIAL_SESSION, null, null,
                        session);
                CryptokiEx.C_Login(session, CKU.USER, password.getBytes(), password.length());
            }catch(CKR_Exception ckre) {
                closeSession();
            }
        }

        return session;
    }

    public static void closeSession() {
        Cryptoki.C_Logout(session);
        Cryptoki.C_CloseSession(session);
        session = null;
    }

    public static boolean isValidSession() {
        boolean validSession = false;
        if(session != null) {
            validSession = session.isValidHandle();
        }
        return validSession;
    }

}
