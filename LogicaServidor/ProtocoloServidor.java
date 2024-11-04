package LogicaServidor;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.regex.Matcher;
import java.util.regex.Pattern;
import javax.crypto.Cipher;

public class ProtocoloServidor {
    public static void procesar(BufferedReader pIn, PrintWriter pOut, PublicKey publica, PrivateKey privada)
            throws IOException {
        int estado = 0;
        String inputLine;

        while (estado < 4 && (inputLine = pIn.readLine()) != null) {
            System.out.println("Entrada a procesar: " + inputLine);
            switch (estado) {
                case 0: // 1. Recibe "SECINIT"
                    if (inputLine.equalsIgnoreCase("SECINIT")) {
                        estado++;
                    }
                    break;
                case 1:
                    procesarEstado1(inputLine, pOut, privada);
                    estado++;
                    break;
                case 2:
                    estado = procesarEstado2(inputLine, pOut, privada, estado);
                    break;
                case 3:
                    estado = procesarEstado3(inputLine, pOut, privada, estado);
                    break;
                default:
                    pOut.println("ERROR");
                    estado = 0;
                    break;
            }
        }

        recibirYEnviarRta(pIn, pOut, privada);
    }

    private static void procesarEstado1(String inputLine, PrintWriter pOut, PrivateKey privada) {
        try {
            BigInteger Rta = desencriptar(inputLine, privada);
            // 4. Envia Rta
            System.out.println(Rta);
            pOut.println(Rta);
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static int procesarEstado2(String inputLine, PrintWriter pOut, PrivateKey privada, int estado) {
        if (inputLine.equalsIgnoreCase("OK")) {
            try {
                BigInteger[] dhParameters = generarDiffieHellman();
                BigInteger P = dhParameters[0];
                BigInteger G = dhParameters[1];
                BigInteger Gx = calcularGx(P, G);

                String mensajeFirmado = P + ":EstoEsUnSeparador:" + G + ":EstoEsUnSeparador:" + Gx;

                Signature signature = Signature.getInstance("SHA1withRSA");
                signature.initSign(privada);
                signature.update(mensajeFirmado.getBytes());
                byte[] firmaBytes = signature.sign();
                String firmaBase64 = Base64.getEncoder().encodeToString(firmaBytes);

                pOut.println(mensajeFirmado);
                pOut.println(firmaBase64);
            } catch (IOException e) {
                System.err.println("Error al generar parámetros de Diffie-Hellman: " + e.getMessage());
            } catch (Exception e) {
                e.printStackTrace();
            }
            return estado + 1;
        } else {
            pOut.println("ERROR. Esperaba OK");
            return 0;
        }
    }
    private static int procesarEstado3(String inputLine, PrintWriter pOut, PrivateKey privada, int estado){
        if(inputLine.equalsIgnoreCase("OK")){

        }
        return estado+1;
    }

    private static BigInteger[] generarDiffieHellman() throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(
                "D:\\Programación\\6to_Semestre\\Infraestructura Computacional\\OpenSSL-1.1.1h_win32\\openssl dhparam -text 1024");
        BufferedReader reader = new BufferedReader(new InputStreamReader(process.getInputStream()));
        StringBuilder output = new StringBuilder();
        String line;
        while ((line = reader.readLine()) != null) {
            output.append(line).append("\n");
        }
        reader.close();
        process.waitFor();

        // Extraer P y G
        Pattern primePattern = Pattern.compile("prime:\\s*((?:[0-9a-fA-F]{2}:?)+)", Pattern.MULTILINE);
        Matcher primeMatcher = primePattern.matcher(output);
        Pattern generatorPattern = Pattern.compile("generator:\\s*(\\d+)\\s*\\(0x[0-9a-fA-F]+\\)", Pattern.MULTILINE);
        Matcher generatorMatcher = generatorPattern.matcher(output);

        if (primeMatcher.find() && generatorMatcher.find()) {
            String primeHex = primeMatcher.group(1).replace(":", "");
            String generatorValue = generatorMatcher.group(1);
            BigInteger P = new BigInteger(primeHex, 16);
            BigInteger G = new BigInteger(generatorValue);
            return new BigInteger[] { P, G };
        } else {
            throw new IllegalStateException("No se pudieron extraer los parámetros de DH.");
        }
    }

    private static BigInteger calcularGx(BigInteger P, BigInteger G) {
        BigInteger x = new BigInteger(P.bitLength() - 1, new SecureRandom()).add(BigInteger.ONE);
        return G.modPow(x, P);
    }

    private static byte[][] firmarValores(BigInteger P, BigInteger G, BigInteger Gx, PrivateKey privada)
            throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privada);

        // Firmar los valores uno por uno
        signature.update(P.toByteArray());
        byte[] signatureP = signature.sign();

        signature.update(G.toByteArray());
        byte[] signatureG = signature.sign();

        signature.update(Gx.toByteArray());
        byte[] signatureGx = signature.sign();

        return new byte[][] { signatureP, signatureG, signatureGx };
    }

    private static void recibirYEnviarRta(BufferedReader pIn, PrintWriter pOut, PrivateKey privada) {
        try {
            // 2b. Recibe R
            String inputLine = pIn.readLine();
            // 3. Calcula Rta
            BigInteger Rta = desencriptar(inputLine, privada);
            // 4. Envia Rta
            pOut.println(Rta);
            // 6. Recibe la verificación
            pIn.readLine();
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    public static BigInteger desencriptar(String encryptedData, PrivateKey privateKey) throws Exception {
        // Decodificar el texto encriptado desde Base64
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

        // Configurar el cifrador en modo DECRYPT y desencriptar
        Cipher cipher = Cipher.getInstance("RSA");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        // Convertir los bytes desencriptados de vuelta a BigInteger
        return new BigInteger(decryptedBytes);
    }
}
