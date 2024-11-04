package Criptografia;

import java.io.BufferedReader;
import java.io.IOException;
import java.io.InputStreamReader;
import java.math.BigInteger;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

public class DiffieHellman {
    public static BigInteger[] generarDiffieHellman() throws IOException, InterruptedException {
        Process process = Runtime.getRuntime().exec(
                "OpenSSL-1.1.1h_win32\\openssl dhparam -text 1024");
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

}
