package com.company.Protocols;

import com.company.Utils.Encrypt;
import com.company.Utils.Number;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class ThreePKD {
    static String preString = "[3PKD]:";
    static int sizeI = 2;
    static int sizeN = 8;
    static int AESSizeKey = 16;
    static class ClientA{
        static String prePreString = "ClientA:";
        static String id = "1";
        static String idB = "2";
        static byte[] nA = Number.generateBytes(sizeN);
        static byte[] keyToTAlpha = null;
        static byte[] keyToTE = null;
        static byte[] keyToB = null;
        static StringBuffer logBuffer = new StringBuffer();
        ClientA(){

        }
        static void startSession(){
            step1();

        }
        static void step1(){
            byte[] rA = Number.generateBytes(sizeN);
            logBuffer.append(preString + prePreString+ "Send to B: idA - " + id + ", rA - " + Number.bytesToHex(rA) + "\n");
            ThreePKD.ClientB.step1Handle(rA, id);
            CT dataCT = T.getCTA();
            if (dataCT == null){
                logBuffer.append(preString + prePreString+ "Failed. Exit..." + "\n");
                return;
            }
            try {
                if (!Arrays.equals(dataCT.t, Encrypt.hmac(keyToTAlpha, Number.concatArrays(dataCT.id.getBytes(), rA, dataCT.r, dataCT.c)))){
                    logBuffer.append(preString + prePreString+ "Failed compare. Exit..." + "\n");
                    return;
                }
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed hmac. Exit..." + "\n");
                return;
            }
            try {
                keyToB = Encrypt.decrypt(keyToTE, dataCT.c);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return ;
            }
            logBuffer.append(preString + prePreString+ "General key:" + Number.bytesToHex(keyToB) + "\n");

        }

        static void printLogger(){
            System.out.println(logBuffer);
        }
    }

    static class ClientB{
        static StringBuffer logBuffer = new StringBuffer();
        static String prePreString = "ClientB:";
        static String id = "2";
        static String idA = "1";
        static byte[] nB = Number.generateBytes(sizeN);
        static byte[] keyToTAlpha = null;
        static byte[] keyToTE = null;
        static byte[] keyToA = null;
        ClientB() {

        }

        static void step1Handle(byte[] rA, String idA){
            logBuffer.append(preString + prePreString+ "Get from A: message idA - " + idA + ", rA - " +  Number.bytesToHex(rA) + "\n");
            byte[] rB = Number.generateBytes(sizeN);
            logBuffer.append(preString + prePreString+ "Generate rB - "  +  Number.bytesToHex(rB) + "\n");
            CT dataCT = T.step1Handle(rA, rB, idA, id);
            if (dataCT == null){
                logBuffer.append(preString + prePreString+ "Failed. Exit..." + "\n");
                return;
            }
            try {
                if (!Arrays.equals(dataCT.t, Encrypt.hmac(keyToTAlpha, Number.concatArrays(idA.getBytes(), rA, rB, dataCT.c)))){
                    logBuffer.append(preString + prePreString+ "Failed compare. Exit..." + "\n");
                    return;
                }
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed hmac. Exit..." + "\n");
                return;
            }
            try {
                keyToA = Encrypt.decrypt(keyToTE, dataCT.c);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return;
            }
            logBuffer.append(preString + prePreString+ "General key:" + Number.bytesToHex(keyToA) + "\n");

        }




        static void printLogger(){
            System.out.println(logBuffer);
        }


    }

    static class T{

        static String prePreString = "T:";
        static StringBuffer logBuffer = new StringBuffer();
        static byte[] keyToAE = null;
        static byte[] keyToAAlpha = null;
        static byte[] keyToBE = null;
        static byte[] keyToBAlpha = null;
        static CT ct = null;
        T(){

        }

        static CT step1Handle(byte[] rA, byte[] rB, String idA, String idB){
            if (keyToBE == null || keyToAE == null || keyToBAlpha == null || keyToAAlpha == null){
                logBuffer.append(preString + prePreString+ "No keys. Exit..." + "\n");
                return null;
            }
            logBuffer.append(preString + prePreString+ "Get from B: idA - " + idA + ", idB - " + idB + ".etc..." + "\n");
            byte[] k = Number.generateBytes(AESSizeKey);
            byte[] cA = new byte[0];
            try {
                cA = Encrypt.encrypt(keyToAE, k);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return null;
            }
            byte[] tA = new byte[0];
            try {
                tA = Encrypt.hmac(keyToAAlpha, Number.concatArrays(idB.getBytes(), rA, rB, cA));
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed hmac. Exit..." + "\n");
                return null;
            }
            ct = new CT(cA, tA, idB, rB); //Change to error

            byte[] cB = new byte[0];
            try {
                cB = Encrypt.encrypt(keyToBE, k);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return null;
            }
            byte[] tB = new byte[0];
            try {
                tB = Encrypt.hmac(keyToBAlpha, Number.concatArrays(idA.getBytes(), rA, rB, cB));
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed hmac. Exit..." + "\n");
                return null;
            }
            return new CT(cB, tB);

        }

        static CT getCTA(){
            logBuffer.append(preString + prePreString+ "Send to A: CTA: id - " + ct.id + ",  - C" + Number.bytesToHex(ct.c) + ".etc..." + "\n");
            return ct;
        }


        static void printLogger(){
            System.out.println(logBuffer);
        }

    }

    public static void main(String[] args) {
        byte[] ClientAtoTE = Number.generateBytes(AESSizeKey);
        byte[] ClientAtoTAlpha = Number.generateBytes(AESSizeKey);
        byte[] ClientBtoTE = Number.generateBytes(AESSizeKey);
        byte[] ClientBtoTAlpha = Number.generateBytes(AESSizeKey);
        ClientA.keyToTAlpha = ClientAtoTAlpha; //
        ClientA.keyToTE = ClientAtoTE;
        T.keyToAAlpha = ClientAtoTAlpha;
        T.keyToAE = ClientAtoTE;
        ClientB.keyToTAlpha = ClientBtoTAlpha;
        ClientB.keyToTE = ClientBtoTE;
        T.keyToBAlpha = ClientBtoTAlpha;
        T.keyToBE = ClientBtoTE;

        ThreePKD.ClientA.startSession();
        ThreePKD.ClientA.printLogger();
        ThreePKD.ClientB.printLogger();
        ThreePKD.T.printLogger();

        System.out.println();
    }

}
class CT{
    byte[] c = null;
    byte[] t = null;
    String id = null;
    byte[] r = null;
    CT(){

    }
    CT(byte[] c, byte[] t) {
        this.c = c;
        this.t = t;
    }
    CT(byte[] c, byte[] t, String id, byte[] r){
        this.c = c;
        this.t = t;
        this.id = id;
        this.r = r;
    }
}