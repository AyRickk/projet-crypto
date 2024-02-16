import java.io.ByteArrayInputStream;
import java.io.FileInputStream;
import java.io.InputStream;
import java.nio.file.Files;
import java.nio.file.Paths;
import java.security.PublicKey;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.util.Base64;

public class ValidateCert {
    public static void main(String[] args) {
        try {
            if (args.length != 2) {
                System.out.println("Usage: validate-cert <format DER|PEM> <myRCAcertfile>");
                System.exit(1);
            }
            String format = args[0];
            String certPath = args[1];
            X509Certificate cert = loadCertificate(certPath, format);

            // Vérification de la signature
            PublicKey pubKey = cert.getPublicKey();
            cert.verify(pubKey);

            // Affichage du sujet et de l'émetteur
            System.out.println("Subject: " + cert.getSubjectDN());
            System.out.println("Issuer: " + cert.getIssuerDN());

            // Vérification de l'extension KeyUsage
            boolean[] keyUsage = cert.getKeyUsage();
            // Supposons que l'usage de clé 5 (keyCertSign) est celui qui nous intéresse
            if (!keyUsage[5]) {
                System.out.println("Le certificat n'est pas autorisé à signer d'autres certificats.");
            }

            // Vérification de la période de validité
            cert.checkValidity();

            System.out.println("Le certificat est valide.");
        } catch (Exception e) {
            e.printStackTrace();
        }
    }

    private static X509Certificate loadCertificate(String certPath, String format) throws Exception {
        CertificateFactory factory = CertificateFactory.getInstance("X.509");
        try (InputStream certStream = format.equalsIgnoreCase("PEM") ?
                Files.newInputStream(Paths.get(certPath)) :
                new FileInputStream(certPath)) {
            if (format.equalsIgnoreCase("PEM")) {
                String pemContent = new String(Files.readAllBytes(Paths.get(certPath)));
                pemContent = pemContent.replace("-----BEGIN CERTIFICATE-----", "")
                        .replace("-----END CERTIFICATE-----", "")
                        .replaceAll("\\s", "");
                byte[] decoded = Base64.getDecoder().decode(pemContent);
                return (X509Certificate) factory.generateCertificate(new ByteArrayInputStream(decoded));
            } else {
                return (X509Certificate) factory.generateCertificate(certStream);
            }
        }
    }
}
