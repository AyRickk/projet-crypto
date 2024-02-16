import java.io.FileInputStream;
import java.io.InputStream;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ValidateCert {
    public static void main(String[] args) {
        String format = "DER"; // Default format
        String certPath = null;

        // Analyse des arguments
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-format":
                    if (i + 1 < args.length && ("DER".equalsIgnoreCase(args[i + 1]) || "PEM".equalsIgnoreCase(args[i + 1]))) {
                        format = args[++i].toUpperCase();
                    } else {
                        System.out.println("Format specifier -format must be followed by DER or PEM");
                        return;
                    }
                    break;
                default:
                    if (certPath == null) {
                        certPath = args[i];
                    } else {
                        System.out.println("Usage: validate-cert [-format DER|PEM] <myCertFile>");
                        return;
                    }
                    break;
            }
        }

        if (certPath == null) {
            System.out.println("Certificate file path is required.");
            System.out.println("Usage: validate-cert [-format DER|PEM] <myCertFile>");
            return;
        }

        try {
            CertificateFactory cf = CertificateFactory.getInstance("X.509");
            X509Certificate cert;

            if ("DER".equals(format)) {
                try (InputStream inStream = new FileInputStream(certPath)) {
                    cert = (X509Certificate) cf.generateCertificate(inStream);
                }
            } else { // PEM format
                byte[] pemData = java.nio.file.Files.readAllBytes(java.nio.file.Paths.get(certPath));
                String pemString = new String(pemData);
                String base64Encoded = pemString.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");
                byte[] decoded = Base64.getDecoder().decode(base64Encoded);
                try (InputStream inStream = new java.io.ByteArrayInputStream(decoded)) {
                    cert = (X509Certificate) cf.generateCertificate(inStream);
                }
            }

            System.out.println("Certificate loaded successfully.");
            // Further processing (validation, display, etc.) goes here.
        } catch (Exception e) {
            e.printStackTrace();
            System.out.println("Error loading certificate: " + e.getMessage());
        }
    }
}
