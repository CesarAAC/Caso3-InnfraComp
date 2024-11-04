package Criptografia;

import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;
import java.util.Scanner;

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

}
