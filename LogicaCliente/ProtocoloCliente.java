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
    long startTimeReto = System.currentTimeMillis();
    // 2a. Cifrar R=C(K_w+, Reto)
    BigInteger reto = new BigInteger(128, new Random());
    String R = RSA.encriptar(publica, reto);
    // 2b. envia R
    if (R != null) {
      pOut.println(R);
    }
    long endTimeReto = System.currentTimeMillis();
    System.out.println("El tiempo en cumplir el Reto fue:" + (endTimeReto-startTimeReto)+" milisegundos");
    // 4. Recibe Rta
    fromServer = pIn.readLine();
    // 5. Verifica Rta==reto y Devuelve la respuesta correspondiente
    if (new BigInteger(fromServer).equals(reto)) {
      pOut.println("OK");
    } else {
      pOut.println("ERROR");
    }
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
      // Verifica la firma y responde
      if (firmaValida) {
        pOut.println("OK");
        //Calcular la llave Simetrica junto con Gy
        BigInteger[] claveSimetricaGy= calcularLlaveSimetrica(P, G, Gx);
        BigInteger claveSimetrica= claveSimetricaGy[0];
        BigInteger Gy=claveSimetricaGy[1];
        //Hacer el Digest
        byte[] digest = Simetricas.generarDigest(claveSimetrica);
        //Obtener las claes de cifrado y HMAC
        SecretKeySpec claveCifrado = Simetricas.obtenerClaveCifrado(digest);
        SecretKeySpec claveHMAC = Simetricas.obtenerClaveHMAC(digest);
        //Enviar El Gy al servidor
        pOut.println("" + Gy);
        // Recibe iv
        IvParameterSpec iv = new IvParameterSpec(Base64.getDecoder().decode(pIn.readLine()));
        // Hacer las peticiones
        // IdCliente Cifrado
        String uidCifrado = Simetricas.cifrar(("" + idCliente), claveCifrado, iv);
        // IdCliente HMAC
        String uidHMAC = Simetricas.generarHMAC(("" + idCliente), claveHMAC);
        if (peticiones == 1) {
          System.out.println("El cliente "+ idCliente + " Acaba de hacer su peticion");
          hacerPeticion(pIn, pOut, idCliente, idCliente, claveCifrado, claveHMAC, iv, uidCifrado, uidHMAC);
        } else {
          for (int i = 0; i < peticiones; i++) {
            System.out.println("Van "+i+" Peticiones de: "+peticiones);
            hacerPeticion(pIn, pOut, idCliente, i, claveCifrado, claveHMAC, iv, uidCifrado, uidHMAC);
          }
        }
        pOut.println("TERMINAR");
        System.out.println("Soy el cliente: "+ idCliente+ " y quiero terminar");
      } else {
        pOut.println("ERROR");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }
  }

  private static void hacerPeticion(BufferedReader pIn, PrintWriter pOut, int idCliente, int idPaquete,
      SecretKeySpec claveCifrado, SecretKeySpec claveHMAC, IvParameterSpec iv, String uidCifrado, String uidHMAC)
      throws Exception {
    // IdPaquete Cifrado
    String idPaqueteCifrado = Simetricas.cifrar(("" + idPaquete), claveCifrado, iv);
    // IdPaquete HMAC
    String idPaqueteHMAC = Simetricas.generarHMAC(("" + idPaquete), claveHMAC);
    // Enviar la peticion
    String peticion = (uidCifrado + ":ESTO ES UN SEPARADOR:" + uidHMAC + ":ESTO ES UN SEPARADOR:" + idPaqueteCifrado
        + ":ESTO ES UN SEPARADOR:" + idPaqueteHMAC);
    
    pOut.println(peticion);
    // Recibir la respuesta;
    String[] fromServer = pIn.readLine().split(":ESTO ES UN SEPARADOR:");
    String estado = Simetricas.descifrar(fromServer[0], claveCifrado, iv);
    System.out.println("El cliente: " +idCliente+ " consulta el paquete: "+ idPaquete+" y su estado es: "+estado);
    Boolean estadoHMAC = Simetricas.verificarHMAC(estado, fromServer[1], claveHMAC);
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

  private static BigInteger[] calcularLlaveSimetrica(BigInteger P, BigInteger G, BigInteger Gx) {
    BigInteger y = new BigInteger(P.bitLength() - 1, new SecureRandom()).add(BigInteger.ONE);
    BigInteger Gy = G.modPow(y, P);
    BigInteger claveSimetrica = Gx.modPow(y, P);
    BigInteger[] respuesta= {claveSimetrica,Gy};
    return respuesta;
  }
}