package com.ripple.pilots;

import java.util.Enumeration;

public class KeyDeletionMain {

    public static void main(String[] args) {
        System.out.println("Starting excecution...");
        try {
            // Log into HSM
            KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
            keyStoreManager.keyStoreLogin();
            Enumeration<String> keys = keyStoreManager.listContents();
            while(keys.hasMoreElements()){
                System.out.println(keys.nextElement());
            }

        } catch (Exception e) {
            System.out.println(e.getMessage());
        }
    }
}
