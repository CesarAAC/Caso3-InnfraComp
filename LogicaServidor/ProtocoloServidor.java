package LogicaServidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;

import Criptografia.DiffieHellman;
import Criptografia.RSA;

public class ProtocoloServidor {

    public static void procesar(BufferedReader pIn, PrintWriter pOut, PublicKey publica, PrivateKey privada)
            throws Exception {
        ProtocoloServidor servidor = new ProtocoloServidor();
        int estado = 0;
        String inputLine;
        BigInteger[] dhParameters = DiffieHellman.generarDiffieHellman();
        BigInteger P = dhParameters[0];
        BigInteger G = dhParameters[1];
        BigInteger x = new BigInteger(P.bitLength() - 1, new SecureRandom()).add(BigInteger.ONE);
        BigInteger Gx = G.modPow(x, P);
        BigInteger llaveSimetrica;

        while (estado < 10 && (inputLine = pIn.readLine()) != null) {
            System.out.println("Entrada a procesar: " + inputLine);
            switch (estado) {
                case 0: // 1. Recibe "SECINIT"
                    if (inputLine.equalsIgnoreCase("SECINIT")) {
                        estado++;
                    }
                    break;
                case 1:
                    estado = servidor.procesarEstado1(inputLine, pOut, privada);
                    break;
                case 2:
                    estado = servidor.procesarEstado2(inputLine, pOut, privada, P, G, Gx);
                    break;
                case 3:
                    estado = servidor.procesarEstado3(inputLine, pOut, privada);
                    break;
                case 4:
                    llaveSimetrica=servidor.procesarEstado4(inputLine, pOut, privada, P, x);
                    estado=5;
                    break;
                case 5:
                default:
                    pOut.println("ERROR");
                    estado = 0;
                    break;
            }
        }
    }

    private int procesarEstado1(String inputLine, PrintWriter pOut, PrivateKey privada) {
        try {
            BigInteger Rta = RSA.desencriptar(inputLine, privada);
            System.out.println("Respuesta enviada: " + Rta);
            pOut.println(Rta);
            return 2;
        } catch (Exception e) {
            e.printStackTrace();
            return 0;
        }
    }

    private int procesarEstado2(String inputLine, PrintWriter pOut, PrivateKey privada, BigInteger P, BigInteger G,
            BigInteger Gx) {
        if (inputLine.equalsIgnoreCase("OK")) {
            try {
                String mensajeFirmado = P + ":EstoEsUnSeparador:" + G + ":EstoEsUnSeparador:" + Gx;
                byte[] firmaBytes = RSA.firmar(mensajeFirmado, privada);
                pOut.println(mensajeFirmado);
                pOut.println(Base64.getEncoder().encodeToString(firmaBytes));

                return 3;
            } catch (Exception e) {
                e.printStackTrace();
            }
        }
        pOut.println("ERROR. Esperaba OK");
        return 0;
    }

    private int procesarEstado3(String inputLine, PrintWriter pOut, PrivateKey privada) {
        if (inputLine.equalsIgnoreCase("OK")) {
            System.out.println("Estado 3 procesado con éxito.");
            return 4;
        }
        return 0;
    }
    private BigInteger procesarEstado4(String inputLine, PrintWriter pOut, PrivateKey privada,BigInteger P, BigInteger x) {
        // Recibir G^y del cliente
        BigInteger Gy = new BigInteger(inputLine);
        BigInteger claveSimetrica=Gy.modPow(x, P);
        System.out.println("Clave Simetrica del Servidor:" + claveSimetrica);

        return claveSimetrica;
    }

    

    
}
