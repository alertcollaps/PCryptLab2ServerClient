package com.company.Protocols;

import com.company.Utils.Encrypt;
import com.company.Utils.Number;

import java.nio.charset.StandardCharsets;
import java.util.Arrays;

public class Otway_Rees {
    static String preString = "[Otway_Rees]:";
    static int sizeI = 2;
    static int sizeN = 8;
    static int AESSizeKey = 16;
    static class ClientA{
        static String prePreString = "ClientA:";
        static String id = "1";
        static String idB = "2";
        static byte[] nA = Number.generateBytes(sizeN);
        static byte[] keyToT = null;
        static byte[] keyToB = null;
        static StringBuffer logBuffer = new StringBuffer();
        ClientA(){

        }
        static void startSession(){
            step1();

        }
        static void step1(){
            byte[] I = Number.generateBytes(sizeI);
            logBuffer.append(preString + prePreString+ "Send to B: idA - " + id + ", idB - " + idB + ", I = " + Number.bytesToHex(I) + "\n");
            byte[] data = Number.concatArrays(nA, I, id.getBytes(), idB.getBytes());
            byte[] encodedData = new byte[0];
            try {
                encodedData = Encrypt.encrypt(keyToT, data);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return ;
            }
            byte[] getMessage = Otway_Rees.ClientB.step1Handle(I, id, idB, encodedData);
            if (getMessage.length == 0){
                logBuffer.append(preString + prePreString+ "Error..." + "\n");
                return ;
            }
            logBuffer.append(preString + prePreString+ "Get from T: message - " + Number.bytesToHex(getMessage) + "\n");
            try {
                keyToB = Encrypt.decrypt(keyToT, getMessage);
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
        static byte[] keyToT = null;
        static byte[] keyToA = null;
        ClientB() {

        }

        static byte[] step1Handle(byte[] I, String idA, String idB, byte[] data){
            logBuffer.append(preString + prePreString+ "Get from A: message idA - " + idA + ", idB - " + idB + ", I = "
                    + Number.bytesToHex(I) + ", data - " + Number.bytesToHex(data) + "\n");

            byte[] dataEnc = Number.concatArrays(nB, I, idA.getBytes(), id.getBytes());
            byte[] encodedData = new byte[0];
            try {
                encodedData = Encrypt.encrypt(keyToT, dataEnc);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
            byte[] tRequest = T.step1Handle(I, idA, idB, data, encodedData);
            if (tRequest.length == 0){
                logBuffer.append(preString + prePreString+ "Failed protocol. Exit..." + "\n");
                return new byte[0];
            }

            keyToA = new byte[AESSizeKey];
            byte[] encKeyS = new byte[tRequest.length/2];
            System.arraycopy(tRequest, encKeyS.length, encKeyS, 0, encKeyS.length);
            try {
                keyToA = Encrypt.decrypt(keyToT, encKeyS);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
            logBuffer.append(preString + prePreString+ "General key:" + Number.bytesToHex(keyToA) + "\n");
            byte[] encKeyStoB = new byte[encKeyS.length];
            System.arraycopy(tRequest, 0, encKeyStoB, 0, encKeyStoB.length);
            return encKeyStoB;
        }




        static void printLogger(){
            System.out.println(logBuffer);
        }


    }
    static class T{

        static String prePreString = "T:";
        static StringBuffer logBuffer = new StringBuffer();
        static byte[] keyToA = null;
        static byte[] keyToB = null;
        static byte[] keyToAB = null;
        T(){

        }

        static byte[] step1Handle(byte[] I, String idA, String idB, byte[] encA, byte[] encB){
            logBuffer.append(preString + prePreString+ "Get from B: idA - " + idA + ", idB - " + idB + ".etc..." + "\n");

            byte[] decrA = new byte[0];
            try {
                decrA = Encrypt.decrypt(keyToA, encA);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
            if (!checkValues(I, idA, idB, decrA)){
                logBuffer.append(preString + prePreString+ "Failed check values. Exit..." + "\n");
                return new byte[0];
            }

            byte[] decrB = new byte[0];
            try {
                decrB = Encrypt.decrypt(keyToB, encB);
            } catch (Exception e) {
                e.printStackTrace();
            }
            if (!checkValues(I, idA, idB, decrB)){
                logBuffer.append(preString + prePreString+ "Failed check values. Exit..." + "\n");
                return new byte[0];
            }

            byte[] s = Number.generateBytes(AESSizeKey);
            logBuffer.append(preString + prePreString+ "Generate s - " + Number.bytesToHex(s) + "\n");
            byte[] data = new byte[0];
            try {
                data = Number.concatArrays(Encrypt.encrypt(keyToA, s), Encrypt.encrypt(keyToB, s));
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
            logBuffer.append(preString + prePreString+ "Send data to B:" + Number.bytesToHex(data) + "\n");
            return data;
        }

        static boolean checkValues(byte[] I, String idA, String idB, byte[] data){
            byte[] testI = new byte[sizeI];
            byte[] testIdA = new byte[1];
            byte[] testIdB = new byte[1];
            System.arraycopy(data, sizeN, testI, 0, sizeI);
            System.arraycopy(data, sizeN+sizeI, testIdA, 0, 1);
            System.arraycopy(data, sizeN+sizeI + 1, testIdB, 0, 1);
            return Arrays.equals(I, testI) && Arrays.equals(idA.getBytes(), testIdA) && Arrays.equals(idB.getBytes(), testIdB);
        }

        static void printLogger(){
            System.out.println(logBuffer);
        }

    }

    public static void main(String[] args) {
        byte[] ClientAtoT = Number.generateBytes(AESSizeKey);
        byte[] ClientBtoT = Number.generateBytes(AESSizeKey);
        Otway_Rees.ClientA.keyToT = ClientAtoT; //
        Otway_Rees.T.keyToA = ClientAtoT;
        Otway_Rees.ClientB.keyToT = ClientBtoT;
        Otway_Rees.T.keyToB = ClientBtoT;

        Otway_Rees.ClientA.startSession();
        Otway_Rees.ClientA.printLogger();
        Otway_Rees.ClientB.printLogger();
        Otway_Rees.T.printLogger();

        System.out.println();
    }


}
