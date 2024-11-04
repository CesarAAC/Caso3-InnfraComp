import java.util.Scanner;
import LogicaCliente.Cliente;
import LogicaServidor.Servidor;
import java.io.File;
import java.io.FileOutputStream;
import java.io.IOException;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.KeyFactory;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.NoSuchAlgorithmException;
import java.security.PrivateKey;
import java.security.PublicKey;
import java.security.spec.PKCS8EncodedKeySpec;
import java.security.spec.X509EncodedKeySpec;

public class Main {
    public static void main(String[] args) {
        Scanner scanner = new Scanner(System.in);
        boolean ejecutar1 = true;
        Main main = new Main();

        while (ejecutar1) {
            System.out.println("Ingrese la opción que desea usar");
            System.out.println("1. Generar llaves públicas y privadas");
            System.out.println("2. Entrar al menú de ejecución");
            System.out.println("3. Salir");
            int opcion = scanner.nextInt();
            scanner.nextLine();

            if (opcion == 1) {
                main.generarLlaves(scanner);
            } else if (opcion == 2) {
                boolean ejecutar2 = true;
                System.out.println("Ingrese el nombre del par de llaves que desea usar (sin el private/public ni el .txt)");
                String llaves= scanner.nextLine();
                while (ejecutar2) {
                    System.out.println("Seleccione las opción que desea usar:");
                    System.out.println("1. Servidor-Cliente Iterativos");
                    System.out.println("2. Servidor-Cliente Concurrentes");
                    System.out.println("3. Salir");

                    if (scanner.hasNextInt()) {
                        int opcion2 = scanner.nextInt();
                        scanner.nextLine();
                        if (opcion2 == 1) {
                            try {
                                main.ejecutarClientes(1, llaves);
                            } catch (IOException e) {
                                e.printStackTrace();
                            }
                        } else if (opcion2 == 2) {
                            System.out.println("Seleccione el numero de clientes");
                            System.out.println("4 clientes");
                            System.out.println("8 clientes");
                            System.out.println("32 clientes");
                            System.out.println("4. Salir");

                            if (scanner.hasNextInt()) {
                                int numeroClientes = scanner.nextInt();
                                scanner.nextLine();
                                if (numeroClientes == 4) {
                                    try {
                                        main.ejecutarClientes(4, llaves);
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                } else if (numeroClientes == 8) {
                                    try {
                                        main.ejecutarClientes(8, llaves);
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                } else if (numeroClientes == 32) {
                                    try {
                                        main.ejecutarClientes(32, llaves);
                                    } catch (IOException e) {
                                        e.printStackTrace();
                                    }
                                } else if (numeroClientes == 4) {
                                    ejecutar2 = false;
                                } else {
                                    System.out.println("Opción no válida. Intente de nuevo.");
                                }
                            } else {
                                System.out.println("Por favor, ingrese un número válido.");
                                scanner.nextLine();
                            }
                        } else if (opcion2 == 3) {
                            ejecutar2 = false;
                        } else {
                            System.out.println("Opción no válida. Intente de nuevo.");
                        }
                    } else {
                        System.out.println("Por favor, ingrese un número válido.");
                        scanner.nextLine();
                    }
                }
            } else if (opcion == 3) {
                System.out.println("Saliendo del programa...");
                ejecutar1 = false;
            } else {
                System.out.println("Opción no válida. Intente de nuevo.");
            }
        }
        scanner.close();
    }

    public void ejecutarServidor(int clientes, PublicKey publica, PrivateKey privada) {
        String[] args = { String.valueOf(clientes) };
        Thread servidorThread = new Thread(() -> {
            try {
                Servidor.correrServidor(publica, privada, clientes);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        servidorThread.start();
        try {
            Thread.sleep(3000);
        } catch (InterruptedException e) {
            e.printStackTrace();
        }
    }

    public void ejecutarClientes(int clientes, String llaves) throws IOException {
        try {
            PublicKey publica=leerLlavePublica("Public" + llaves + ".txt");
            PrivateKey privada=leerLlavePrivada("LogicaServidor/Private" + llaves + ".txt");
            if (clientes == 1) {
                String[] args = { "1" };/////////////////////////////////CAMBIAR ESTO a 32
                Cliente.correrCliente(publica, clientes);
                ejecutarServidor(clientes, publica, privada);
            } else {
                ejecutarServidor(clientes, publica, privada);
                for (int i = 0; i < clientes; i++) {
                    String[] args = { "1" };
                    Cliente.correrCliente(publica, clientes);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        
    }

    public void generarLlaves(Scanner scanner) {
        try {
            KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
            keyPairGenerator.initialize(1024);
            KeyPair llaves = keyPairGenerator.generateKeyPair();
            System.out.println("Ingrese el nombre de las llaves:");
            String nombreLlaves = scanner.nextLine();
            try (FileOutputStream publicOut = new FileOutputStream("Public" + nombreLlaves + ".txt")) {
                publicOut.write(llaves.getPublic().getEncoded());
                System.out.println("Llave pública guardada en Public" + nombreLlaves + ".txt");
            }
            File directorio = new File("LogicaServidor");
            if (!directorio.exists()) {
                directorio.mkdir();
            }
            try (FileOutputStream privateOut = new FileOutputStream("LogicaServidor/Private" + nombreLlaves + ".txt")) {
                privateOut.write(llaves.getPrivate().getEncoded());
                System.out.println("Llave privada guardada en LogicaServidor/Private" + nombreLlaves + ".txt");
            }

        } catch (NoSuchAlgorithmException e) {
            System.err.println("Error: Algoritmo no encontrado - " + e.getMessage());
        } catch (IOException e) {
            System.err.println("Error de escritura en archivo - " + e.getMessage());
        }
    }
    public PublicKey leerLlavePublica(String ruta) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ruta));
        X509EncodedKeySpec spec = new X509EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePublic(spec);
    }

    public PrivateKey leerLlavePrivada(String ruta) throws Exception {
        byte[] keyBytes = Files.readAllBytes(Paths.get(ruta));
        PKCS8EncodedKeySpec spec = new PKCS8EncodedKeySpec(keyBytes);
        KeyFactory keyFactory = KeyFactory.getInstance("RSA");
        return keyFactory.generatePrivate(spec);
    }
}
