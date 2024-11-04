package LogicaServidor;

import java.io.BufferedReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.util.Base64;
import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;
import Criptografia.DiffieHellman;
import Criptografia.RSA;
import Criptografia.Simetricas;

public class ProtocoloServidor {

    public static void procesar(BufferedReader pIn, PrintWriter pOut, PublicKey publica, PrivateKey privada)
            throws Exception {
        ProtocoloServidor servidor = new ProtocoloServidor();
        int estado = 0;
        String inputLine;
        long startTimeDiffieHellman = System.currentTimeMillis();
        BigInteger[] dhParameters = DiffieHellman.generarDiffieHellman();
        BigInteger P = dhParameters[0];
        BigInteger G = dhParameters[1];
        BigInteger x = new BigInteger(P.bitLength() - 1, new SecureRandom()).add(BigInteger.ONE);
        BigInteger Gx = G.modPow(x, P);
        long endTimeDiffieHellman = System.currentTimeMillis();
        System.out.println("El tiempo en generar G, P Y Gx fue:" + (endTimeDiffieHellman - startTimeDiffieHellman) + " milisegundos");
        BigInteger llaveSimetrica;
        Boolean ejecutar = true;
        SecretKeySpec claveCifrado;
        SecretKeySpec claveHMAC;
        IvParameterSpec iv;
        int uid;
        Boolean uidHMAC;
        int idPaquete;
        Boolean idPaqueteHMAC;

        while (estado < 5 && (inputLine = pIn.readLine()) != null) {
            switch (estado) {
                case 0:
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
                    llaveSimetrica = servidor.procesarEstado4(inputLine, pOut, privada, P, x);
                    byte[] digest = Simetricas.generarDigest(llaveSimetrica);
                    claveCifrado = Simetricas.obtenerClaveCifrado(digest);
                    claveHMAC = Simetricas.obtenerClaveHMAC(digest);
                    SecureRandom secureRandom = new SecureRandom();
                    byte[] ivRaw = new byte[16];
                    secureRandom.nextBytes(ivRaw);
                    String ivBase64 = Base64.getEncoder().encodeToString(ivRaw);
                    // Envia iv
                    pOut.println(ivBase64);
                    iv = new IvParameterSpec(ivRaw);
                    long startTimeEjecuciones = System.currentTimeMillis();
                    while (ejecutar) {
                        long startTimeEjecucion = System.currentTimeMillis();
                        inputLine = pIn.readLine();
                        if (!inputLine.equalsIgnoreCase("TERMINAR")) {
                            String[] parametros = inputLine.split(":ESTO ES UN SEPARADOR:");
                            uid = Integer.parseInt(Simetricas.descifrar(parametros[0], claveCifrado, iv));
                            uidHMAC = Simetricas.verificarHMAC("" + uid, parametros[1], claveHMAC);
                            idPaquete = Integer.parseInt(Simetricas.descifrar(parametros[2], claveCifrado, iv));
                            idPaqueteHMAC = Simetricas.verificarHMAC("" + idPaquete, parametros[3], claveHMAC);
                            int estadoPaquete = Servidor.matriz[uid][idPaquete];
                            System.out.println("El cliente: " + uid + " consulta el paquete: " + idPaquete
                                    + " con estado: " + estadoPaquete);
                            // Respuesta
                            String estadoPaqueteCifrado = Simetricas.cifrar("" + estadoPaquete, claveCifrado, iv);
                            String estadoPaqueteHMAC = Simetricas.generarHMAC("" + estadoPaquete, claveHMAC);
                            String respuesta = (estadoPaqueteCifrado + ":ESTO ES UN SEPARADOR:" + estadoPaqueteHMAC);
                            pOut.println(respuesta);
                            long endTimeEjecucion = System.currentTimeMillis();
                            System.out.println("El tiempo en atender la solicitud fue:" + (endTimeEjecucion - startTimeEjecucion) + " milisegundos");
                        } else {
                            System.out.println("El cliente termino sus peticiones");
                            long endTimeEjecuciones = System.currentTimeMillis();
                            System.out.println("El tiempo en atender todas las solicitudes:" + (endTimeEjecuciones - startTimeEjecuciones) + " milisegundos");
                            ejecutar = false;
                        }
                    }
                    estado = 5;
                    break;
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
            System.out.println("Respuesta enviada: ");
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
            return 4;
        }
        return 0;
    }

    private BigInteger procesarEstado4(String inputLine, PrintWriter pOut, PrivateKey privada, BigInteger P,
            BigInteger x) {
        BigInteger Gy = new BigInteger(inputLine);
        BigInteger claveSimetrica = Gy.modPow(x, P);
        return claveSimetrica;
    }

}
