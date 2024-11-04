package LogicaCliente;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.PrintWriter;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PublicKey;
import java.security.SecureRandom;
import java.security.Signature;
import java.util.Base64;
import java.util.Random;
import java.security.PrivateKey;
import java.security.InvalidKeyException;
import javax.crypto.Cipher;
import javax.crypto.NoSuchPaddingException;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.BadPaddingException;

public class ProtocoloCliente {
  public static void procesar(BufferedReader stdIn, BufferedReader pIn, PrintWriter pOut, PublicKey publica,
      int peticiones) throws IOException {
    String fromServer;
    // 1. Envia "SECINIT"
    pOut.println("SECINIT");
    // 2a. Cifrar R=C(K_w+, Reto)
    BigInteger reto = new BigInteger(128, new Random());
    String R = encriptar(publica, reto);
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

      } else {
        pOut.println("ERROR");
      }
    } catch (Exception e) {
      e.printStackTrace();
    }

  }

  public static String encriptar(PublicKey publicKey, BigInteger reto) {
    try {

      byte[] bigIntBytes = reto.toByteArray();
      Cipher cipher = Cipher.getInstance("RSA");
      cipher.init(Cipher.ENCRYPT_MODE, publicKey);
      byte[] encriptados = cipher.doFinal(bigIntBytes);
      return Base64.getEncoder().encodeToString(encriptados);
    } catch (NoSuchAlgorithmException | NoSuchPaddingException | InvalidKeyException | IllegalBlockSizeException
        | BadPaddingException e) {
      e.printStackTrace();
      return null;
    }
  }
}