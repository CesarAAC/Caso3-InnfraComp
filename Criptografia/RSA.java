package Criptografia;

import java.math.BigInteger;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.Signature;
import java.util.Base64;

import javax.crypto.BadPaddingException;
import javax.crypto.Cipher;
import javax.crypto.IllegalBlockSizeException;
import javax.crypto.NoSuchPaddingException;

public class RSA {

    public static byte[] firmar(String mensaje, PrivateKey privada) throws Exception {
        Signature signature = Signature.getInstance("SHA1withRSA");
        signature.initSign(privada);
        signature.update(mensaje.getBytes());
        return signature.sign();
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

    public static BigInteger desencriptar(String encryptedData, PrivateKey privateKey) throws Exception {
        // Decodificar el texto encriptado desde Base64
        byte[] encryptedBytes = Base64.getDecoder().decode(encryptedData);

        Cipher cipher = Cipher.getInstance("RSA/ECB/PKCS1Padding");
        cipher.init(Cipher.DECRYPT_MODE, privateKey);
        byte[] decryptedBytes = cipher.doFinal(encryptedBytes);

        return new BigInteger(decryptedBytes);
    }

}
