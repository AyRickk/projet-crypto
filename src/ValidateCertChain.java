import java.io.BufferedReader;
import java.io.ByteArrayInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.security.cert.X509Certificate;


public class ValidateCertChain {
    public static void main(String[] args) {
        // Assurez-vous qu'au moins deux certificats sont fournis
        Optional<String[]> parsedArgsOpt = parseArguments(args);
        if (parsedArgsOpt.isEmpty()) {
            System.err.println("Invalid arguments.");
            return;
        }
        String[] parsedArgs = parsedArgsOpt.get();
        String format = parsedArgs[0];
        try {
            // Charger tous les certificats
            List<X509Certificate> certs = new ArrayList<>();
            for (int i = 1; i < parsedArgs.length; i++) {
                X509Certificate cert = loadCertificate(Path.of(parsedArgs[i]), format);
                certs.add(cert);
            }
            // Valider la chaîne
            validateCertificateChain(certs);

        } catch (Exception e) {
            System.err.println("Error processing certificate chain: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static Optional<String[]> parseArguments(String[] args) throws IllegalArgumentException {
        String format = "DER"; // Default format
        List<String> certPaths = new ArrayList<>();

        // Analyze arguments
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
                    // Collect all certificate paths
                    certPaths.add(args[i]);
                    break;
            }
        }

        if (certPaths.isEmpty()) {
            throw new IllegalArgumentException("At least one certificate file path is required. Usage: validate-cert [-format DER|PEM] <myCertFile>...");
        }

        // Convert list to array and prepend the format
        String[] result = new String[certPaths.size() + 1];
        result[0] = format;
        for (int i = 0; i < certPaths.size(); i++) {
            result[i + 1] = certPaths.get(i);
        }

        return Optional.of(result);
    }

    private static void validateCertificateChain(List<X509Certificate> certs) throws Exception {
        // Vérifier le certificat racine (auto-signé)
        System.out.println("############### ROOT CERTIFICATE ###############\n");
        X509Certificate rootCert = certs.get(0);
        checkSignatureAndAlgorithm(rootCert, rootCert);
        if (!rootCert.getIssuerX500Principal().equals(rootCert.getSubjectX500Principal())) {
            throw new IllegalArgumentException("Root certificate is not self-signed");
        }
        System.out.println("Root certificate is autosigned ");
        for (int i = 1; i < certs.size() ; i++) {
            X509Certificate cert = certs.get(i);
            X509Certificate issuerCert = certs.get(i - 1);
            if(i==1){
                checkValidityPeriod(issuerCert);
                checkAndDisplayKeyUsage(issuerCert);
            }
            System.out.println("\n\n############### CERTIFICATE " + (i+1) + " ###############\n");
            // Vérifier que l'émetteur du certificat correspond au sujet du certificat précédent
            if (!cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                System.out.println("Issuer of cert " + (i) + " does not match subject of cert " + (i+1));
                continue;
            }else {
                System.out.println("Issuer of cert " + (i) + " matches subject of cert " + (i+1));
            }

            // Vérifier la signature du certificat avec la clé publique de l'émetteur
            checkSignatureAndAlgorithm(cert, issuerCert);
            System.out.println("Cert " + (i) + " signature verified against issuer cert " + (i+1));


            checkValidityPeriod(cert);
            checkAndDisplayKeyUsage(cert);
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

    private static void checkSignatureAndAlgorithm(X509Certificate cert, X509Certificate issuerCert) {
        try {
            String sigAlg = cert.getSigAlgName();
            if (sigAlg.contains("RSA")){
                if(verifyRSASignature(cert, issuerCert)){
                    System.out.println("RSA Signature verifies: SUCCESS");
                }else{
                    System.out.println("RSA Signature verifies: FAILED");
                }

            }

            Signature sig = Signature.getInstance(sigAlg);
            sig.initVerify(issuerCert.getPublicKey());
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

    public static X509Certificate loadCertificate(Path path, String format) {
        try {
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

    public static boolean verifyRSASignature(X509Certificate cert, X509Certificate issuerCert) {
        try {
            PublicKey publicKey = issuerCert.getPublicKey();
            if (publicKey instanceof RSAPublicKey rsaPublicKey) {

                BigInteger modulus = rsaPublicKey.getModulus();
                BigInteger exponent = rsaPublicKey.getPublicExponent();

                byte[] signatureBytes = cert.getSignature();
                BigInteger signature = new BigInteger(1, signatureBytes);

                // Déchiffrement de la signature pour obtenir le hash
                BigInteger signatureCheck = signature.modPow(exponent, modulus);

                // Calcul du hash du TBSCertificate
                MessageDigest crypt = MessageDigest.getInstance("SHA-256");
                crypt.update(cert.getTBSCertificate());
                byte[] certHash = crypt.digest();

                byte[] signatureCheckBytes = signatureCheck.toByteArray();
                String sigAlg = cert.getSigAlgName();
                int hashLength = 0;

                // Determine the SHA type and set the hash length accordingly
                if (sigAlg.contains("SHA1")) {
                    hashLength = 20; // SHA-1 produces a 160-bit (20-byte) hash value
                } else if (sigAlg.contains("SHA256")) {
                    hashLength = 32; // SHA-256 produces a 256-bit (32-byte) hash value
                } else if (sigAlg.contains("SHA384")) {
                    hashLength = 48; // SHA-384 produces a 384-bit (48-byte) hash value
                } else if (sigAlg.contains("SHA512")) {
                    hashLength = 64; // SHA-512 produces a 512-bit (64-byte) hash value
                }

                // Take the last 'hashLength' bytes
                signatureCheckBytes = Arrays.copyOfRange(signatureCheckBytes, signatureCheckBytes.length - hashLength, signatureCheckBytes.length);


                return java.util.Arrays.equals(certHash, signatureCheckBytes);
            }
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false;
    }

    public static void verifyBasicConstraints(X509Certificate cert) {
        // Get the Basic Constraints extension
        int basicConstraints = cert.getBasicConstraints();
        if (basicConstraints != -1) {
            System.out.println("Basic Constraints: " + basicConstraints);
        } else {
            System.out.println("No Basic Constraints available.");
        }
    }
}