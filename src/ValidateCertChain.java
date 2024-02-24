import java.io.*;
import java.math.BigInteger;
import java.net.HttpURLConnection;
import java.net.URL;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.nio.file.StandardOpenOption;
import java.security.*;
import java.security.cert.*;
import java.security.interfaces.RSAPublicKey;
import java.util.*;
import java.security.cert.X509Certificate;

import org.bouncycastle.asn1.*;
import org.bouncycastle.asn1.x509.*;

import org.bouncycastle.asn1.ASN1Integer;
import org.bouncycastle.asn1.ASN1Sequence;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.math.ec.ECCurve;
import org.bouncycastle.math.ec.ECPoint;
import org.bouncycastle.crypto.signers.ECDSASigner;
import org.bouncycastle.crypto.params.ECPublicKeyParameters;
import org.bouncycastle.crypto.params.ECDomainParameters;

import java.security.spec.ECParameterSpec;
import java.security.interfaces.ECPublicKey;

import static org.bouncycastle.asn1.x509.Extension.cRLDistributionPoints;

import org.bouncycastle.cert.ocsp.*;
import org.bouncycastle.cert.jcajce.JcaX509CertificateHolder;
import org.bouncycastle.operator.DigestCalculator;
import org.bouncycastle.operator.DigestCalculatorProvider;
import org.bouncycastle.operator.OperatorCreationException;
import org.bouncycastle.operator.jcajce.JcaDigestCalculatorProviderBuilder;

public class ValidateCertChain {
    public static void main(String[] args) {
        try {
            Optional<String[]> parsedArgsOpt = parseArguments(args);
            if (parsedArgsOpt.isEmpty()) {
                throw new IllegalArgumentException("Invalid arguments.");
            }
            String[] parsedArgs = parsedArgsOpt.get();
            String format = parsedArgs[0];

            List<X509Certificate> certs = new ArrayList<>();
            for (int i = 1; i < parsedArgs.length; i++) {
                certs.add(loadCertificate(Path.of(parsedArgs[i]), format));
            }

            // Charger tous les certificats et valider la chaîne
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
                    certPaths.add(args[i]);
                    break;
            }
        }

        if (certPaths.isEmpty()) {
            throw new IllegalArgumentException("At least one certificate file path is required. Usage: validate-cert [-format DER|PEM] <myCertFile>...");
        }

        String[] result = new String[certPaths.size() + 1];
        result[0] = format;
        for (int i = 0; i < certPaths.size(); i++) {
            result[i + 1] = certPaths.get(i);
        }

        return Optional.of(result);
    }

    private static void validateCertificateChain(List<X509Certificate> certs) throws Exception {
        for (int i = 0; i < certs.size(); i++) {
            System.out.println("\n\n########## Certificate " + (i + 1) + " ##########\n");
            X509Certificate cert = certs.get(i);
            X509Certificate issuerCert = (i == 0) ? cert : certs.get(i - 1);

            // Vérifier le certificat racine (auto-signé)
            if (i == 0 && !cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                throw new IllegalArgumentException("Root certificate is not self-signed");
            }

            // Vérifier que l'émetteur du certificat correspond au sujet du certificat précédent
            if (i != 0 && !cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                continue;
            }

            // Vérifier la signature du certificat avec la clé publique de l'émetteur
            checkSignatureAndAlgorithm(cert, issuerCert);

            // Vérifier la période de validité et l'utilisation de la clé
            checkValidityPeriod(cert);
            checkAndDisplayKeyUsage(cert);
            verifyBasicConstraints(cert);

            // Vérifier les points de distribution de la liste de révocation (CRL)
            List<String> crlUrls = getCrlDistributionPoints(cert);
            if (!crlUrls.isEmpty()) {
                System.out.println("CRL Distribution Points:");
                for (String url : crlUrls) {
                    System.out.println("- " + url);
                }
            } else {
                System.out.println("No CRL Distribution Points available.");
            }

            verifyCRL(cert, crlUrls);

            if (i > 0) { // Pas besoin de vérifier le certificat racine avec OCSP
                try {
                    verifyOCSP(cert, issuerCert);
                } catch (Exception e) {
                    System.err.println("OCSP verification failed: " + e.getMessage());
                }
            }

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
            if (sigAlg.contains("RSA")) {
                if (verifyRSASignature(cert, issuerCert)) {
                    System.out.println("RSA Signature verifies: SUCCESS");
                } else {
                    System.out.println("RSA Signature verifies: FAILED");
                }

            }
            if (sigAlg.contains("ECDSA")) {
                if (verifyECDSASignature(cert, issuerCert)) {
                    System.out.println("ECDSA Signature verifies: SUCCESS");
                } else {
                    System.out.println("ECDSA Signature verifies: FAILED");
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
        } catch (Exception e) {
            throw new RuntimeException(e);
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
            System.out.println("This certificate is a CA with basic constraints of : " + basicConstraints);
        } else {
            System.out.println("This certificate is not a CA.");
        }

    }

    private static boolean verifyECDSASignature(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        Security.addProvider(new BouncyCastleProvider());

        // Extrait les composants r et s de la signature ECDSA
        byte[] signature = cert.getSignature();
        BigInteger[] rs = decodeECDSASignature(signature);

        PublicKey publicKey = issuerCert.getPublicKey();
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Public key must be instance of ECPublicKey for ECDSA verification.");
        }

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECParameterSpec spec = ecPublicKey.getParams();
        System.out.println("Curve: " + spec);
        // Utilisez les informations de la clé publique et de la spécification de courbe directement
        ECCurve curve = null;
        if (cert.getSigAlgName().contains("SHA384")) {
            curve = new org.bouncycastle.math.ec.custom.sec.SecP384R1Curve(); // Adaptez à la courbe utilisée si nécessaire
        } else if (cert.getSigAlgName().contains("SHA256")) {
            curve = new org.bouncycastle.math.ec.custom.sec.SecP256R1Curve(); // Adaptez à la courbe utilisée si nécessaire
        }
        assert curve != null;
        ECPoint point = curve.createPoint(ecPublicKey.getW().getAffineX(), ecPublicKey.getW().getAffineY(), false);
        ECDomainParameters domainParameters = new ECDomainParameters(
                curve,
                curve.createPoint(spec.getGenerator().getAffineX(), spec.getGenerator().getAffineY()),
                spec.getOrder(),
                BigInteger.valueOf(spec.getCofactor()));
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(point, domainParameters);

        // Utiliser l'algorithme approprié pour hasher les données avant vérification
        // Calcul du hash du TBSCertificate
        MessageDigest crypt = null;
        if (cert.getSigAlgName().contains("SHA384")) {
            crypt = MessageDigest.getInstance("SHA-384");
        } else if (cert.getSigAlgName().contains("SHA256")) {
            crypt = MessageDigest.getInstance("SHA-256");
        }
        assert crypt != null;
        crypt.update(cert.getTBSCertificate());
        byte[] certHash = crypt.digest();

        // Initialise le vérificateur ECDSA avec la clé publique
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKeyParameters);
        return signer.verifySignature(certHash, rs[0], rs[1]);
    }

    // Méthode pour décoder une signature ECDSA de ASN.1 DER format à BigInteger r et s
    private static BigInteger[] decodeECDSASignature(byte[] signature) throws IOException {
        ASN1Sequence sequence = (ASN1Sequence) ASN1Sequence.fromByteArray(signature);
        BigInteger r = ((ASN1Integer) sequence.getObjectAt(0)).getValue();
        BigInteger s = ((ASN1Integer) sequence.getObjectAt(1)).getValue();
        return new BigInteger[]{r, s};
    }

    private static List<String> getCrlDistributionPoints(X509Certificate cert) throws CertificateParsingException {
        try {
            byte[] crlDPExtensionValue = cert.getExtensionValue(cRLDistributionPoints.getId());
            System.out.println("CRL Distribution Points extension: " + crlDPExtensionValue);
            if (crlDPExtensionValue == null) {
                return Collections.emptyList();
            }
            ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDPExtensionValue));
            ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            byte[] crlDPsExtOctets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crlDPsExtOctets));
            ASN1Primitive derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

            List<String> crlUrls = new ArrayList<>();
            for (DistributionPoint dp : distPoint.getDistributionPoints()) {
                DistributionPointName dpn = dp.getDistributionPoint();
                if (dpn != null && dpn.getType() == DistributionPointName.FULL_NAME) {
                    GeneralName[] genNames = GeneralNames.getInstance(dpn.getName()).getNames();
                    for (GeneralName genName : genNames) {
                        if (genName.getTagNo() == GeneralName.uniformResourceIdentifier) {
                            String url = ((DERIA5String) genName.getName()).getString();
                            crlUrls.add(url);
                        }
                    }
                }
            }
            return crlUrls;
        } catch (IOException e) {
            throw new CertificateParsingException(e.getMessage(), e);
        }
    }

    private static Date getLastModified(String url) throws IOException {
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("HEAD");
        return new Date(conn.getLastModified());
    }

    private static String sanitizeUrl(String url) {
        return url.replaceAll("[:/]", "_");
    }

    private static void verifyCRL(X509Certificate cert, List<String> crlUrls) {
    for (String url : crlUrls) {
        try {
            String sanitizedUrl = sanitizeUrl(url);
            List<String> cachedUrls = Files.readAllLines(Paths.get("crlCache.txt"));
            File crlFile = new File("./cache", sanitizedUrl);
            X509CRL crl = null;
            if (cachedUrls.contains(url) && crlFile.exists()) {
                // Charger la CRL du fichier cache
                try (InputStream in = new FileInputStream(crlFile)) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    crl = (X509CRL) cf.generateCRL(in);
                }
                // Vérifier si la CRL est toujours valide
                if (crl.getNextUpdate().after(new Date())) {
                    System.out.println("CRL loaded from cache: " + url);
                } else {
                    crl = null; // La CRL est obsolète
                }
            }
            if (crl == null || getLastModified(url).after(new Date(crlFile.lastModified()))) {
                // Télécharger la CRL
                URL crlUrl = new URL(url);
                InputStream crlStream = crlUrl.openStream();
                CertificateFactory cf = CertificateFactory.getInstance("X.509");
                crl = (X509CRL) cf.generateCRL(crlStream);
                // Mise à jour du cache
                try (FileOutputStream out = new FileOutputStream(crlFile)) {
                    out.write(crl.getEncoded());
                }
                if (!cachedUrls.contains(url)) {
                    Files.write(Paths.get("crlCache.txt"), (url + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
                }
                System.out.println("CRL downloaded and cached: " + url);
            }
            if (crl.isRevoked(cert)) {
                System.out.println("CRL : Certificate is revoked by CRL: " + url);
            } else {
                System.out.println("CRL : Certificate is not revoked by CRL: " + url);
            }
        } catch (Exception e) {
            System.err.println("Error verifying CRL: " + e.getMessage());
        }
    }
}


    private static void verifyOCSP(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        try {
            String ocspUrl = extractOcspUrl(cert);
            if (ocspUrl == null) {
                System.out.println("OCSP URL not found in certificate. Skipping OCSP verification.");
                return;
            }

            // Préparation de la requête OCSP
            OCSPReqBuilder builder = new OCSPReqBuilder();
            try {
                CertificateID id = generateCertificateID(cert, issuerCert);
                builder.addRequest(id);

                OCSPReq req = builder.build();

                // Envoi de la requête OCSP
                URL url = new URL(ocspUrl);
                HttpURLConnection con = (HttpURLConnection) url.openConnection();
                con.setRequestProperty("Content-Type", "application/ocsp-request");
                con.setRequestProperty("Accept", "application/ocsp-response");
                con.setDoOutput(true);
                OutputStream out = con.getOutputStream();
                out.write(req.getEncoded());
                out.flush();


                // Réception et analyse de la réponse OCSP
                if (con.getResponseCode() == HttpURLConnection.HTTP_OK) {
                    OCSPResp response = new OCSPResp(con.getInputStream());
                    BasicOCSPResp basicResponse = (BasicOCSPResp) response.getResponseObject();
                    if (basicResponse == null) {
                        return;
                    }
                    SingleResp[] responses = basicResponse.getResponses();
                    for (SingleResp resp : responses) {
                        Object status = resp.getCertStatus();
                        if (status == CertificateStatus.GOOD) {
                            System.out.println("OCSP : Certificate is not revoked");
                        } else if (status instanceof RevokedStatus) {
                            System.out.println("OCSP : Certificate is revoked");
                        } else if (status instanceof UnknownStatus) {
                            System.out.println("OCSP : Certificate status is unknown");
                        }
                    }
                } else {
                    throw new Exception("Received HTTP error code from OCSP server: " + con.getResponseCode());
                }
            } catch (OperatorCreationException e) {
                System.err.println("Error creating DigestCalculator: " + e.getMessage());
            } catch (Exception e) {
                System.err.println("Error verifying OCSP: " + e.getMessage());
                throw e;
            }
        } catch (Exception e) {
            System.err.println("Error verifying OCSP : " + e.getMessage());
            throw e;
        }
    }


    private static String extractOcspUrl(X509Certificate cert) throws Exception {
        byte[] aiaBytes = cert.getExtensionValue(Extension.authorityInfoAccess.getId());
        if (aiaBytes == null) {
            return null;
        }

        ASN1InputStream aiaAIS = new ASN1InputStream(aiaBytes);
        ASN1OctetString aiaOctetString = (ASN1OctetString) aiaAIS.readObject();
        aiaAIS.close();

        aiaAIS = new ASN1InputStream(aiaOctetString.getOctets());
        ASN1Sequence aiaSequence = (ASN1Sequence) aiaAIS.readObject();
        aiaAIS.close();

        AuthorityInformationAccess authorityInformationAccess = AuthorityInformationAccess.getInstance(aiaSequence);
        for (AccessDescription accessDescription : authorityInformationAccess.getAccessDescriptions()) {
            if (accessDescription.getAccessMethod().equals(AccessDescription.id_ad_ocsp)) {
                GeneralName gn = accessDescription.getAccessLocation();
                if (gn.getTagNo() == GeneralName.uniformResourceIdentifier) {
                    return gn.getName().toString();
                }
            }
        }
        return null;
    }

    private static CertificateID generateCertificateID(X509Certificate cert, X509Certificate issuerCert) throws OperatorCreationException, IOException, CertificateEncodingException, OCSPException {
        DigestCalculatorProvider digCalcProv = new JcaDigestCalculatorProviderBuilder().build();
        DigestCalculator digestCalculator = digCalcProv.get(CertificateID.HASH_SHA1);

        X509CertificateHolder issuerCertHolder = new JcaX509CertificateHolder(issuerCert);

        // Utilisation du numéro de série du certificat
        BigInteger serialNumber = cert.getSerialNumber();

        // Création de l'ID du certificat
        CertificateID id = new CertificateID(digestCalculator, issuerCertHolder, serialNumber);

        return id;
    }
}