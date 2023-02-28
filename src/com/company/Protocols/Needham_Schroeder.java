package com.company.Protocols;

import com.company.Utils.Encrypt;
import com.company.Utils.Number;

import java.util.Arrays;

public class Needham_Schroeder {
    static String preString = "[Needham_Schroeder]:";
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
            byte[] encodedMessage = step1();
            byte[] decodedMessage = new byte[0];
            try {
                decodedMessage = Encrypt.decrypt(keyToT, encodedMessage);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed decrypt. Exit..." + "\n");
                return;
            }
            byte[] nAGet = new byte[sizeN];
            System.arraycopy(decodedMessage, 0, nAGet, 0, sizeN);
            if (!Arrays.equals(nAGet, nA)){
                logBuffer.append(preString + prePreString+ "Failed nA: " + Number.bytesToHex(nAGet) + "\n");
                System.out.println(logBuffer);
                return;
            }
            byte[] idBGet = new byte[1];
            System.arraycopy(decodedMessage, sizeN, idBGet, 0, 1);
            if (!Arrays.equals(idBGet, idB.getBytes())){
                logBuffer.append(preString + prePreString+ "Warning idB not compared. Continue..." + "\n");
            }
            keyToB = new byte[AESSizeKey];
            System.arraycopy(decodedMessage, sizeN + 1, keyToB, 0, AESSizeKey);
            logBuffer.append(preString + prePreString+ "Get SecretKey to B: " + Number.bytesToHex(keyToB) + "\n");
            byte[] sendMessageForB = new byte[decodedMessage.length-sizeN-1-AESSizeKey];
            System.arraycopy(decodedMessage, sizeN + 1 + AESSizeKey, sendMessageForB, 0, sendMessageForB.length);

            byte[] getMessageFromB = step2(sendMessageForB);
            byte[] nB = new byte[0];
            try {
                nB = Encrypt.decrypt(keyToB, getMessageFromB);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed decrypt. Exit..." + "\n");
                return;
            }
            logBuffer.append(preString + prePreString+ "Get nB from B: " + Number.bytesToHex(nB) + "\n");
            nB[nB.length-1] -= 1;
            byte[] encNB = new byte[0];
            try {
                encNB = Encrypt.encrypt(keyToB, nB);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed decrypt. Exit..." + "\n");
                return;
            }
            String response = step3(encNB);
            logBuffer.append(preString + prePreString + response + "\n");

        }
        static byte[] step1(){
            logBuffer.append(preString + prePreString+ "Send to T: idA - " + id + ", idB - " + idB + ", number = " + Number.bytesToHex(nA) + "\n");
            byte[] getMessage = T.step1Handle(id, idB, Number.bytesToHex(nA));
            logBuffer.append(preString + prePreString+ "Get from T: message - " + Number.bytesToHex(getMessage) + "\n");
            return getMessage;
        }

        static byte[] step2(byte[] data){
            logBuffer.append(preString + prePreString+ "Send to B: message - " + Number.bytesToHex(data) + "\n");
            byte[] getMessage = ClientB.getPair(Number.bytesToHex(data));
            logBuffer.append(preString + prePreString+ "Get from T: message - " + Number.bytesToHex(getMessage) + "\n");
            return getMessage;
        }
        static String step3(byte[] data){
            logBuffer.append(preString + prePreString+ "Send to B: message(nB) - " + Number.bytesToHex(data) + "\n");
            String getMessage = ClientB.checkNB(Number.bytesToHex(data));
            logBuffer.append(preString + prePreString+ "Get from T: message - " + getMessage + "\n");
            if (getMessage.contains("Successful")){
                return "OK";
            }
            return "Fail response";
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
        static byte[] getPair(String encodedMessageHex){
            byte[] encodedMessage = Number.hexStringToByteArray(encodedMessageHex);
            logBuffer.append(preString + prePreString+ "Get from A: message - " + encodedMessageHex + "\n");
            byte[] decodedMessage = new byte[0];
            try {
                decodedMessage = Encrypt.decrypt(keyToT, encodedMessage);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
            keyToA = new byte[AESSizeKey];
            System.arraycopy(decodedMessage, 0, keyToA, 0, AESSizeKey);
            logBuffer.append(preString + prePreString+ "EvaluateKey:" + Number.bytesToHex(keyToA) + "\n");

            try {
                return Encrypt.encrypt(keyToA, nB);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
        }

        static String checkNB(String encodedMessageHex){
            byte[] encodedMessage = Number.hexStringToByteArray(encodedMessageHex);
            logBuffer.append(preString + prePreString+ "Get from A: message - " + encodedMessageHex + "\n");
            byte[] decodedMessage = new byte[0];
            try {
                decodedMessage = Encrypt.decrypt(keyToA, encodedMessage);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return "Failed encrypt/decrypt. Exit...";
            }
            logBuffer.append(preString + prePreString+ "nB-1 from A:" + Number.bytesToHex(decodedMessage) + "\n");
            byte[] nBCheck = new byte[nB.length];
            System.arraycopy(nB, 0, nBCheck, 0, nBCheck.length);
            nBCheck[nBCheck.length-1] -= 1;
            if (!Arrays.equals(nBCheck, decodedMessage)){
                logBuffer.append(preString + prePreString+ "Error nB check. Fail identification." + "\n");
                return "Error nB check. Fail identification.";
            }
            logBuffer.append(preString + prePreString+ "Successful!!!" + "\n");
            return "Successful!!!";
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

        static byte[] step1Handle(String idA, String idB, String hexNum){
            logBuffer.append(preString + prePreString+ "Get from A: idA - " + idA + ", idB - " + idB + ", number = " + hexNum + "\n");

            byte[] nA = Number.hexStringToByteArray(hexNum);
            byte[] K = Number.generateBytes(AESSizeKey);
            logBuffer.append(preString + prePreString+ "Generate K: " + Number.bytesToHex(K) + "\n");
            byte[] encToB = new byte[0]; //
            try {
                encToB = Encrypt.encrypt(keyToB, Number.concatArrays(K, idA.getBytes()));
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
            //nA[0]=123;

            byte[] data = Number.concatArrays(nA, idB.getBytes(), K, encToB);
            byte[] enc = new byte[0];
            try {
                enc = Encrypt.encrypt(keyToA, data);
            } catch (Exception e) {
                logBuffer.append(preString + prePreString+ "Failed encrypt/decrypt. Exit..." + "\n");
                return new byte[0];
            }
            logBuffer.append(preString + prePreString + "Send to A: encoded message: " + Number.bytesToHex(enc) + "\n");
            return enc;
        }
        static void printLogger(){
            System.out.println(logBuffer);
        }

    }

    public static void main(String[] args) {
        byte[] ClientAtoT = Number.generateBytes(AESSizeKey);
        byte[] ClientBtoT = Number.generateBytes(AESSizeKey);
        ClientA.keyToT = ClientAtoT; //
        T.keyToA = ClientAtoT;
        ClientB.keyToT = ClientBtoT;
        T.keyToB = ClientBtoT;

        ClientA.startSession();
        ClientA.printLogger();
        ClientB.printLogger();
        T.printLogger();

        System.out.println();
    }


}
