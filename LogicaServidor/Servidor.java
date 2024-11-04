package LogicaServidor;

import java.io.IOException;
import java.net.ServerSocket;
import java.net.Socket;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.util.Random;

import LogicaCliente.Cliente;

public class Servidor {
     public static int[][] matriz=generarMatriz(32,32);
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
     public static int[][] generarMatriz(int filas, int columnas) {
        int[][] matriz = new int[filas][columnas];
        Random random = new Random();
        for (int i = 0; i < filas; i++) {
            for (int j = 0; j < columnas; j++) {
                matriz[i][j] = random.nextInt(7);
            }
        }
        return matriz;
    }
}