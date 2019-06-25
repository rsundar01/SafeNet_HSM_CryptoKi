package com.ripple.pilots;

import org.bouncycastle.util.encoders.Hex;
import java.nio.charset.StandardCharsets;
import java.util.concurrent.*;
import java.util.concurrent.atomic.AtomicBoolean;

public class MTCryptoOperations {

    private static LinkedBlockingQueue<Future<Signature>> fq = new LinkedBlockingQueue<>();
    private static KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
    private static boolean producerFlag = false;
    private static boolean stopProduceFlag = false;
    private static AtomicBoolean requireInitialization = new AtomicBoolean(true);

    public static class Signature {
        final private byte[] signature;
        Signature(byte[] signature) {
            this.signature = signature;
        }
        public byte[] getSignature() {
            return signature;
        }
    }

    public static class Producer implements Runnable {
        private ThreadPoolExecutor executor = null;
        private long count = 0;
        Producer(ThreadPoolExecutor executor) {
            this.executor = executor;
        }

        public void run() {
            while(true) {
                if(Thread.interrupted()) break;
                if(!stopProduceFlag) {
                    Future<Signature> result = (Future<Signature>) executor.submit(
                            (Callable) new SignerTask(Long.toString(count), keyStoreManager, "test_imported_ed25519_01"));
                    fq.add(result);
                    System.out.println("Producing " + Long.toString(count) + "...");
                    count++;
                }
                try {
                    Thread.sleep(500);
                }catch (InterruptedException e) {
                    System.out.println("Breaking from producer...");
                    break;
                }
            }

            System.out.println("Breaking from producer1....");
        }
    }

    public static class Consumer implements Runnable {

        public void run() {
            while(!(producerFlag && fq.isEmpty())) {
                Future<Signature> result = fq.poll();
                if(result != null ) {
                    try {
                        Signature signature = result.get();
                        if(signature == null) {
                            System.out.println("Signature is null");
                            if(!requireInitialization.get()) requireInitialization.set(true);
                        }
                    } catch (Exception e) {
                        if(!requireInitialization.get()) requireInitialization.set(true);
                        System.out.println("Exception captured: " + e.getMessage());
                    }
                    System.out.println("Is done: " + result.isDone());
                    System.out.println("Is cancelled: " + result.isCancelled());
                }
                try {
                    Thread.sleep(500);
                } catch (InterruptedException ie) {
                    System.out.println("Breaking from consumer...");
                    break;
                }
            }
            System.out.println("Exiting from consumer...");
        }
    }


    private static class MonitorTask implements  Callable<Integer> {
        private static final int MAX_WAIT_TIME = 5000; //5 seconds
        private static final int INCREMENT_FACTOR = 1;
        private static final int INTITIAL_WAIT_TIME = 1000; //1 Second
        private static final int MONITOR_TIME = 1000;
        private ThreadPoolExecutor monitered = null;

        MonitorTask(ThreadPoolExecutor monitered) {
            this.monitered = monitered;
        }

        public void doInit() {
            boolean hsmInitializationReq = false;
            boolean tokenDetectable = false;
            requireInitialization.set(true);
            System.out.println("Monitor Thread: Doing Init....");

            try {
                // wait till all the threads are drained
                if(!stopProduceFlag) stopProduceFlag = true;
                System.out.println("Active counts: " + monitered.getQueue().size());
                while(monitered.getQueue().size() != 0) {
                    System.out.println("Active counts: " + monitered.getQueue().size());
                    try {
                        Thread.sleep(1000);
                    }catch(InterruptedException ie) {

                    }
                }
                System.out.println("Active counts: " + monitered.getQueue().size());
                if(LunaManager.requiresInitialization()) {
                    LunaManager.initializeHSM();
                }

                boolean loginResult = false;
                if(LunaManager.detectToken()){
                    loginResult = keyStoreManager.keyStoreLogin();
                } else {
                    System.out.println("Token cannot be detected");
                }

                if(loginResult) System.out.println("Login successful");
                requireInitialization.set(!loginResult);
                if(loginResult) stopProduceFlag = false;
            } catch (Exception e) {
                requireInitialization.set(true);
            }

        }


        public Integer call() {
           int waitTime = 0;
           while(true) {
               System.out.println("Monitor Thread: Monitoring...");
                waitTime = INTITIAL_WAIT_TIME;
                while (requireInitialization.get()){
                    doInit();
                    if(requireInitialization.get()) {
                        // wait for few seconds and retry
                        try {
                            Thread.sleep(waitTime);
                        } catch (InterruptedException ie) {return -1;}
                    }
                    waitTime = waitTime * INCREMENT_FACTOR;
                    if(waitTime > MAX_WAIT_TIME) waitTime = MAX_WAIT_TIME;
                }

                // wait for some time
               try {
                   Thread.sleep(MONITOR_TIME);
               } catch (InterruptedException ie) {
                   System.out.println("Monitor Thread: Breaking from monitor");
                   break;
               }
           }

           return 0;
        }

    }

    private static  class SignerTask implements Runnable, Callable<Signature> {
        private String name = null;
        private KeyStoreManager keyStoreManager = null;
        private String keyLabel = null;
        private byte[] dataToSign = "Hello World, How are you doing?".getBytes(StandardCharsets.UTF_8);
        private Ed25519Signer signer = new Ed25519Signer();
        private byte[] signature = null;
        SignerTask(String name, KeyStoreManager keyStoreManager, String keyLabel) {
            this.name = name;
            this.keyStoreManager = keyStoreManager;
            this.keyLabel = keyLabel;
        }
        public void run() {
            try {
                signature = signer.sign(keyStoreManager, keyLabel, dataToSign);
                //if(name.equals("2")) throw new RuntimeException("My runtime exception");
                System.out.format("%s : Signature - %s\n", name, Hex.toHexString(signature));
            } catch (RuntimeException re) {
                System.out.println("Runtime Exception: " + re.getMessage());
                throw re;
            } catch (Exception e) {
                System.out.println("Exception: " + e.getMessage());
            }
        }

        public Signature call() {
            Signature signatureResult = null;
            try {
                signature = signer.sign(keyStoreManager, keyLabel, dataToSign);
                System.out.format("%s : Signature - %s\n", name, Hex.toHexString(signature));
                //if(name.equals("2")) throw new RuntimeException("My runtime exception");
                signatureResult = new Signature(signature);
            } catch (RuntimeException re) {
                System.out.println("Runtime Exception: " + re.getMessage());
                throw re;
            } catch (Exception e) {
                System.out.println("Exception: " + e.getMessage());
            }
            return signatureResult;
        }
    }
    public static void main(String[] args) throws Exception {
        System.out.println("Invoking signer and verification threads");
        if(keyStoreManager.keyStoreLogin()) {
            stopProduceFlag = false;
            requireInitialization.set(false);
        }
        /*Thread t1 = new Thread(new SignerTask("t1", keyStoreManager,"test_imported_ed25519_01"));
        t1.start();
        Thread t2 = new Thread(new SignerTask("t2", keyStoreManager, "test_imported_ed25519_01"));
        t2.start();*/
        ThreadPoolExecutor executor = (ThreadPoolExecutor)Executors.newFixedThreadPool(2);
        ThreadPoolExecutor monitor = (ThreadPoolExecutor) Executors.newFixedThreadPool(1);
        monitor.submit((Callable) new MonitorTask(executor));
        Thread producerTh = new Thread(new Producer(executor));
        Thread consumerTh = new Thread(new Consumer());

        //Starting producer thread
        producerFlag = false;
        System.out.println("Starting producer...");
        producerTh.start();

        System.out.println("Getting results");
        consumerTh.start();

        //HSM goes down and get up
        TimeUnit.HOURS.sleep(2);
        producerTh.interrupt();
        //producerTh.join(60000);
        producerFlag = true;
        System.out.println("Finished producing....");
        consumerTh.join();
        System.out.println("Finished consuming...");

        System.out.println("Shutting down executor");
        executor.shutdown();
        System.out.println("Shutdown completed");

        System.out.println("Shutting down monitor...");
        monitor.shutdownNow();
        System.out.println("Monitor shutdown completed");

    }

    /*public static void main(String[] args) throws Exception {
        System.out.println("Invoking signer and verification threads");
        if(keyStoreManager.keyStoreLogin()) stopProduceFlag = false;
        ThreadPoolExecutor executor = (ThreadPoolExecutor)Executors.newFixedThreadPool(2);
        Thread producerTh = new Thread(new Producer(executor));
        Thread consumerTh = new Thread(new Consumer());

        //Starting producer thread
        producerFlag = false;
        System.out.println("Starting producer...");
        producerTh.start();

        System.out.println("Getting results");
        consumerTh.start();

        TimeUnit.SECONDS.sleep(2);
        producerTh.interrupt();
        //producerTh.join(60000);
        producerFlag = true;
        System.out.println("Finished producing....");
        consumerTh.join();
        System.out.println("Finished consuming...");

        System.out.println("Shutting down executor");
        executor.shutdown();
        System.out.println("Shutdown completed");

    }*/

    /*public static void main(String[] args) throws Exception {
        System.out.println("Invoking signer and verification threads");
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
        ThreadPoolExecutor executor = (ThreadPoolExecutor)Executors.newFixedThreadPool(2);

        int count = 0;
        Set<Future<Signature>> resultSet = new HashSet<>();
        while(count < 5) {
            Future<Signature> result = (Future<Signature>)executor.submit(

    /*public static void main(String[] args) throws Exception {
        System.out.println("Invoking signer and verification threads");
        KeyStoreManager keyStoreManager = KeyStoreManager.getInstance();
        ThreadPoolExecutor executor = (ThreadPoolExecutor)Executors.newFixedThreadPool(2);

        int count = 0;
        Set<Future<Signature>> resultSet = new HashSet<>();
        while(count < 5) {
            Future<Signature> result = (Future<Signature>)executor.submit(
                    (Callable)new SignerTask(Integer.toString(count), keyStoreManager, "test_imported_ed25519_01"));
            resultSet.add(result);
            count++;
        }

        System.out.println("Getting results");
        System.out.println("Size of resultset: " + Integer.toString(resultSet.size()));
        for(Future<Signature> result : resultSet) {
            if(result == null ) break;
            try {
                Signature signature = result.get();
                System.out.println(Hex.toHexString(signature.getSignature()));
            } catch(Exception e) {
                System.out.println("Exception captured: " + e.getMessage());
            }
            System.out.println("Is done: " + result.isDone());
            System.out.println("Is cancelled: " + result.isCancelled());
        }

        System.out.println("Shutting down executor");
        executor.shutdown();
        System.out.println("Shutdown completed");

    }*/



}
