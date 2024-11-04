package LogicaServidor;

import java.io.BufferedReader;
import java.io.InputStreamReader;
import java.io.PrintWriter;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

public class ThreadServidor extends Thread {
     private Socket sktCliente = null;
     private int id;
     private PublicKey publica;
     private PrivateKey privada;

     public ThreadServidor(Socket pSocket, int pId, PublicKey publica, PrivateKey privada) {
          this.sktCliente = pSocket;
          this.id = pId;
          this.publica=publica;
          this.privada=privada;

     }

     public void run() {
          System.out.println("Inicio de un nuevo thread: " + id);

          try {
               PrintWriter escritor = new PrintWriter(sktCliente.getOutputStream(), true);
               BufferedReader lector = new BufferedReader(new InputStreamReader(sktCliente.getInputStream()));
               ProtocoloServidor.procesar(lector, escritor, publica, privada);
               escritor.close();
               lector.close();
               sktCliente.close();
          } catch (Exception e) {
               e.printStackTrace();
          }
     }
}