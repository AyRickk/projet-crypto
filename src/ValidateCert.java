import java.io.*;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.InvalidKeyException;
import java.security.NoSuchAlgorithmException;
import java.security.NoSuchProviderException;
import java.security.SignatureException;
import java.security.Signature;
import java.security.cert.*;
import java.util.Base64;
import java.util.HashMap;
import java.util.Map;
import java.util.Optional;

public class ValidateCert {
    public static void main(String[] args) {
    Optional<String[]> parsedArgsOpt = parseArguments(args);
    if (parsedArgsOpt.isEmpty()) {
        System.err.println("Invalid arguments.");
        return;
    }

    String[] parsedArgs = parsedArgsOpt.get();
    String format = parsedArgs[0];
    String certPath = parsedArgs[1];

    try {
        X509Certificate cert = loadCertificate(Path.of(certPath), format);
        if (cert == null) {
            System.err.println("Error loading certificate.");
            return;
        }

        verifySignature(cert);
        System.out.println("Issuer: " + cert.getIssuerX500Principal().getName());
        System.out.println("Subject: " + cert.getSubjectX500Principal().getName());
        checkAndDisplayKeyUsage(cert);
        checkValidityPeriod(cert);
        checkSignatureAndAlgorithm(cert);
    } catch (Exception e) {
        e.printStackTrace();
        System.err.println("Error processing certificate: " + e.getMessage());
    }
}

    public static X509Certificate loadCertificate(Path path, String format) {
    try {
        byte[] certBytes = Files.readAllBytes(path);

        CertificateFactory certFactory = CertificateFactory.getInstance("X.509");

        if (format.equalsIgnoreCase("DER")) {
            try (InputStream in = Files.newInputStream(path)) {
                return (X509Certificate) certFactory.generateCertificate(in);
            }
        } else if (format.equalsIgnoreCase("PEM")) {
            StringBuilder pemContent = new StringBuilder();
            try (BufferedReader reader = Files.newBufferedReader(path)) {
                String line;
                while ((line = reader.readLine()) != null) {
                    if (!line.startsWith("-----")) {
                        pemContent.append(line);
                    }
                }
            }
            byte[] decodedBytes = Base64.getDecoder().decode(pemContent.toString());
            try (InputStream in = new ByteArrayInputStream(decodedBytes)) {
                return (X509Certificate) certFactory.generateCertificate(in);
            }
        } else {
            throw new IllegalArgumentException("Unsupported certificate format: " + format);
        }
    } catch (IOException e) {
        System.err.println("Error reading certificate file: " + e.getMessage());
        return null;
    } catch (CertificateException e) {
        System.err.println("Error generating certificate: " + e.getMessage());
        return null;
    }
}

    public static Optional<String[]> parseArguments(String[] args) throws IllegalArgumentException {
    String format = "DER"; // Default format
    String certPath = null;

    // Analyse des arguments
    for (int i = 0; i < args.length; i++) {
        switch (args[i]) {
            case "-format":
                if (i + 1 < args.length && ("DER".equalsIgnoreCase(args[i + 1]) || "PEM".equalsIgnoreCase(args[i + 1]))) {
                    format = args[++i].toUpperCase();
                } else {
                    throw new IllegalArgumentException("Format specifier -format must be followed by DER or PEM");
                }
                break;
            default:
                if (certPath == null) {
                    certPath = args[i];
                } else {
                    throw new IllegalArgumentException("Usage: validate-cert [-format DER|PEM] <myCertFile>");
                }
                break;
        }
    }

    if (certPath == null) {
        throw new IllegalArgumentException("Certificate file path is required. Usage: validate-cert [-format DER|PEM] <myCertFile>");
    }

    return Optional.of(new String[]{format, certPath});
}

    public static void verifySignature(X509Certificate cert) {
        try {
            cert.verify(cert.getPublicKey());
            System.out.println("Certificate signature verified.");
        } catch (SignatureException sigEx) {
            System.err.println("Signature verification failed: " + sigEx.getMessage());
        } catch (InvalidKeyException ikEx) {
            System.err.println("Invalid public key: " + ikEx.getMessage());
        } catch (CertificateException | NoSuchAlgorithmException | NoSuchProviderException ex) {
            System.err.println("Error verifying certificate: " + ex.getMessage());
        } catch (Exception e) {
            System.err.println("Unexpected error: " + e.getMessage());
        }
    }

    private static void checkValidityPeriod(X509Certificate cert) {
        try {
            cert.checkValidity();
            System.out.println("Certificate is within its valid period.");
        } catch (CertificateExpiredException e) {
            System.err.println("Certificate has expired: " + e.getMessage());
        } catch (CertificateNotYetValidException e) {
            System.err.println("Certificate is not yet valid: " + e.getMessage());
        }
    }

    private static void checkAndDisplayKeyUsage(X509Certificate cert) {
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            Map<Integer, String> keyUsageNames = new HashMap<>();
            keyUsageNames.put(0, "digitalSignature");
            keyUsageNames.put(1, "nonRepudiation");
            keyUsageNames.put(2, "keyEncipherment");
            keyUsageNames.put(3, "dataEncipherment");
            keyUsageNames.put(4, "keyAgreement");
            keyUsageNames.put(5, "keyCertSign");
            keyUsageNames.put(6, "cRLSign");
            keyUsageNames.put(7, "encipherOnly");
            keyUsageNames.put(8, "decipherOnly");

            StringBuilder sb = new StringBuilder();
            sb.append("Key Usage:\n");
            for (int i = 0; i < keyUsage.length; i++) {
                if (keyUsage[i]) {
                    sb.append("- ").append(keyUsageNames.get(i)).append("\n");
                }
            }
            System.out.println(sb.toString());
        } else {
            System.out.println("No KeyUsage available.");
        }
    }

    private static void checkSignatureAndAlgorithm(X509Certificate cert) {
        try {
            String sigAlg = cert.getSigAlgName();
            Signature sig = Signature.getInstance(sigAlg);
            sig.initVerify(cert.getPublicKey());
            sig.update(cert.getTBSCertificate());
            boolean verifies = sig.verify(cert.getSignature());
            System.out.println("Signature algorithm: " + sigAlg);
            System.out.println("Signature verifies: " + (verifies ? "SUCCESS" : "FAILED"));
        } catch (NoSuchAlgorithmException e) {
            System.err.println("Failed to get the instance of Signature object: " + e.getMessage());
        } catch (InvalidKeyException e) {
            System.err.println("Failed to initialize the Signature object: " + e.getMessage());
        } catch (SignatureException e) {
            System.err.println("Failed to verify the certificate signature: " + e.getMessage());
        } catch (CertificateEncodingException e) {
            System.err.println("Failed to get the certificate encoding: " + e.getMessage());
        }
    }
}
