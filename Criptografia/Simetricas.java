package Criptografia;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.MessageDigest;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Arrays;
import java.util.Base64;
import java.util.Scanner;

import javax.crypto.Cipher;
import javax.crypto.Mac;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

public class Simetricas {

    public static void generarLlaves(Scanner scanner) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair llaves = keyPairGenerator.generateKeyPair();
            System.out.println("Ingrese el nombre de las llaves:");
            String nombreLlaves = scanner.nextLine();
            try (FileOutputStream publicOut = new FileOutputStream("Public" + nombreLlaves + ".txt")) {
                publicOut.write(llaves.getPublic().getEncoded());
                System.out.println("Llave pública guardada en Public" + nombreLlaves + ".txt");
            }
            File directorio = new File("LogicaServidor");
            if (!directorio.exists()) {
                directorio.mkdir();
            }
            try (FileOutputStream privateOut = new FileOutputStream("LogicaServidor/Private" + nombreLlaves + ".txt")) {
                privateOut.write(llaves.getPrivate().getEncoded());
                System.out.println("Llave privada guardada en LogicaServidor/Private" + nombreLlaves + ".txt");
            }

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: Algoritmo no encontrado - " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Error de escritura en archivo - " + e.getMessage());
        }
    }
    public static PublicKey leerLlavePublica(String ruta) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ruta));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public static PrivateKey leerLlavePrivada(String ruta) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ruta));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }

    public static byte[] generarDigest(BigInteger claveSimetrica) throws NoSuchAlgorithmException {
        MessageDigest sha512 = MessageDigest.getInstance("SHA-512");
        byte[] digest = sha512.digest(claveSimetrica.toByteArray());

        return digest;
    }
    public static SecretKeySpec obtenerClaveCifrado(byte[] digest){
        byte[] claveCifradoBytes = Arrays.copyOfRange(digest, 0, 32);
        return new SecretKeySpec(claveCifradoBytes, "AES");
    }
    public static SecretKeySpec obtenerClaveHMAC(byte[] digest){
        byte[] claveHMACBytes = Arrays.copyOfRange(digest, 32, 64);
        return new SecretKeySpec(claveHMACBytes, "AES");
    }


    public static String cifrar(String texto, SecretKeySpec clave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.ENCRYPT_MODE, clave, iv);
        byte[] textoCifrado = cipher.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(textoCifrado);
    }

    public static String generarHMAC(String texto, SecretKeySpec claveHMAC) throws Exception {
        Mac mac = Mac.getInstance("HmacSHA384");
        mac.init(claveHMAC);
        byte[] hmacBytes = mac.doFinal(texto.getBytes());
        return Base64.getEncoder().encodeToString(hmacBytes);
    }

    public static boolean verificarHMAC(String texto, String hmacRecibido, SecretKeySpec claveHMAC) throws Exception {
        String hmacCalculado = generarHMAC(texto, claveHMAC);
        return hmacCalculado.equals(hmacRecibido);
    }

    public static String descifrar(String textoCifrado, SecretKeySpec clave, IvParameterSpec iv) throws Exception {
        Cipher cipher = Cipher.getInstance("AES/CBC/PKCS5Padding");
        cipher.init(Cipher.DECRYPT_MODE, clave, iv);
        byte[] textoDesencriptado = cipher.doFinal(Base64.getDecoder().decode(textoCifrado));
        return new String(textoDesencriptado);
    }

}
