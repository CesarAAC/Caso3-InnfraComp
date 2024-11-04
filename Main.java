import java.util.Scanner;

import Criptografia.Simetricas;
import LogicaCliente.Cliente;
import LogicaServidor.Servidor;
import java.io.IOException;
import java.security.PrivateKey;
import java.security.PublicKey;

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
                Simetricas.generarLlaves(scanner);
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
        Thread servidorThread = new Thread(() -> {
            try {
                Servidor.correrServidor(publica, privada, clientes);
            } catch (IOException e) {
                e.printStackTrace();
            }
        });
        servidorThread.start();
    }

    public void ejecutarClientes(int clientes, String llaves) throws IOException {
        try {
            PublicKey publica=Simetricas.leerLlavePublica("Public" + llaves + ".txt");
            PrivateKey privada=Simetricas.leerLlavePrivada("LogicaServidor/Private" + llaves + ".txt");
            if (clientes == 1) {
                Cliente.correrCliente(publica, 32);
                ejecutarServidor(clientes, publica, privada);
            } else {
                ejecutarServidor(clientes, publica, privada);
                for (int i = 0; i < clientes; i++) {
                    Cliente.correrCliente(publica, 1);
                }
            }
        } catch (Exception e) {
            e.printStackTrace();
        }
        
        
    }
}
