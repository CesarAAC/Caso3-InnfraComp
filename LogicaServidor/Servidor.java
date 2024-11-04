package LogicaServidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;

import LogicaCliente.Cliente;

public class Servidor {
     public static void correrServidor(PublicKey publica, PrivateKey privada, int clientes) throws IOException {
          ServerSocket ss = null;
          int numeroThreads = 0;
          System.out.println("Main Server ...");
          try {
               ss = new ServerSocket(Cliente.PUERTO);
          } catch (IOException e) {
               System.err.println("No se pudo crear el socket en el puerto: "
                         + Cliente.PUERTO);
               System.exit(-1);
          }
          while (numeroThreads<clientes) {
               Socket socket = ss.accept();
               ThreadServidor thread = new ThreadServidor(socket,numeroThreads, publica, privada);
               numeroThreads++;
               thread.start();
          }

          ss.close();
     }

}