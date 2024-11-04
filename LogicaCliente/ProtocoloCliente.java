package LogicaCliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Random;

import javax.crypto.spec.IvParameterSpec;
import javax.crypto.spec.SecretKeySpec;

import Criptografia.RSA;
import Criptografia.Simetricas;

public class ProtocoloCliente {
  public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, PublicKey publica,
      int peticiones, int idCliente) throws IOException {
    String fromServer;
    // 1. Envia "SECINIT"
    pOut.println("SECINIT");
    // 2a. Cifrar R=C(K_w+, Reto)
    BigInteger reto = new BigInteger(128, new Random());
    String R = RSA.encriptar(publica, reto);
    // 2b. envia R
    if (R != null) {
      pOut.println(R);
    }
    // 4. Recibe Rta
    fromServer = pIn.readLine();
    // 5. Verifica Rta==reto
    if (new BigInteger(fromServer).equals(reto)) {
      pOut.println("OK");
    } else {
      pOut.println("ERROR");
    }
    System.out.println(new BigInteger(fromServer).equals(reto));
    // 9. recibe y verifica DiffieHellman
    String mensajeFirmado = pIn.readLine();
    String firmaBase64 = pIn.readLine();

    String[] valores = mensajeFirmado.split(":EstoEsUnSeparador:");
    BigInteger P = new BigInteger(valores[0]);
    BigInteger G = new BigInteger(valores[1]);
    BigInteger Gx = new BigInteger(valores[2]);

    byte[] firmaBytes = Base64.getDecoder().decode(firmaBase64);

    try {
      Signature signature = Signature.getInstance("SHA1withRSA");
      signature.initVerify(publica);
      signature.update(mensajeFirmado.getBytes());
      boolean firmaValida = signature.verify(firmaBytes);

      if (firmaValida) {
        pOut.println("OK");
        BigInteger y = new BigInteger(P.bitLength() - 1, new SecureRandom()).add(BigInteger.ONE);
        BigInteger Gy = G.modPow(y, P);
        BigInteger claveSimetrica = Gx.modPow(y, P);
        byte[] digest = Simetricas.generarDigest(claveSimetrica);
        SecretKeySpec claveCifrado = Simetricas.obtenerClaveCifrado(digest);
        SecretKeySpec claveHMAC = Simetricas.obtenerClaveHMAC(digest);
        pOut.println("" + Gy);
        // Recibe iv
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(pIn.readLine()));
        // Hacer las peticiones
        // IdCliente Cifrado
        String uidCifrado = Simetricas.cifrar(("" + idCliente), claveCifrado, iv);
        // IdCliente HMAC
        String uidHMAC = Simetricas.generarHMAC(("" + idCliente), claveHMAC);
        if (peticiones == 1) {
          pOut.println(uidCifrado);
          pOut.println(uidHMAC);
          hacerPeticion(pIn, pOut, idCliente, idCliente, claveCifrado, claveHMAC, iv);
        } else {
          for (int i = 0; i < peticiones; i++) {
            pOut.println(uidCifrado);
            pOut.println(uidHMAC);
            hacerPeticion(pIn, pOut, idCliente, i, claveCifrado, claveHMAC, iv);
          }
        }
        pOut.println("TERMINAR");
      } else {
        pOut.println("ERROR");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void hacerPeticion(BufferedReader pIn, PrintWriter pOut, int idCliente, int IdPaquete,
      SecretKeySpec claveCifrado, SecretKeySpec claveHMAC, IvParameterSpec iv) throws Exception {
    // IdPaquete Cifrado
    pOut.println(Simetricas.cifrar(("" + IdPaquete), claveCifrado, iv));
    // IdPaquete HMAC
    pOut.println(Simetricas.generarHMAC(("" + IdPaquete), claveHMAC));

    String estado = Simetricas.descifrar(pIn.readLine(), claveCifrado, iv);
    Boolean estadoHMAC = Simetricas.verificarHMAC(estado, pIn.readLine(), claveHMAC);
    int estadoNum = Integer.parseInt(estado);

    if (estadoNum == 0) {
      System.out.println("El estado del paquete es: DESCONOCIDO");
    } else if (estadoNum == 1) {
      System.out.println("El estado del paquete es: ENOFICINA");
    } else if (estadoNum == 2) {
      System.out.println("El estado del paquete es: RECOGIDO");
    } else if (estadoNum == 3) {
      System.out.println("El estado del paquete es: ENCLASIICACION");
    } else if (estadoNum == 4) {
      System.out.println("El estado del paquete es: DESPACHADO");
    } else if (estadoNum == 5) {
      System.out.println("El estado del paquete es: ENENTREGA");
    } else if (estadoNum == 6) {
      System.out.println("El estado del paquete es: ENTREGADO");
    }
  }
}