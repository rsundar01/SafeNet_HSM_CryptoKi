package com.ripple.pilots;

import com.safenetinc.jcprov.CKR_Exception;
import com.safenetinc.jcprov.CK_C_INITIALIZE_ARGS;
import com.safenetinc.jcprov.Cryptoki;
import com.safenetinc.jcprov.CryptokiEx;
import com.safenetinc.jcprov.constants.CKF;
import com.safenetinc.luna.LunaSlotManager;

public class JcprovManager {

    private static boolean initialized = false;

    public static boolean initializeJcprov() {

        try {
            CryptokiEx.C_Initialize(new CK_C_INITIALIZE_ARGS(CKF.OS_LOCKING_OK));
            initialized = true;
        } catch(CKR_Exception ex){
            if(ex.ckrv.intValue() != 0x191) {
                initialized = false;
                Cryptoki.C_Finalize(null);
            }
        }

        return initialized;
    }


    public static void finalizeJcprov() {
        Cryptoki.C_Finalize(null);
    }

    public static boolean reInitializeJcprov() {
        if(initialized) finalizeJcprov();
        return initializeJcprov();
    }

    public static boolean isInitialized() {
        if(initialized){
            initialized = LunaSlotManager.getInstance().getReconnectRequired();
        }
        return initialized;
    }

}
