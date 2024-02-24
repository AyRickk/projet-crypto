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
            // Analyse des arguments passés au programme pour déterminer le format des certificats et les chemins d'accès
            Optional<String[]> parsedArgsOpt = parseArguments(args);
            if (parsedArgsOpt.isEmpty()) {
                throw new IllegalArgumentException("Invalid arguments."); // Si aucun argument valide n'est fourni
            }

            // Récupération des arguments analysés
            String[] parsedArgs = parsedArgsOpt.get();

            // Le premier argument spécifie le format des certificats (DER ou PEM)
            String format = parsedArgs[0];

            // Initialisation d'une liste pour stocker les certificats chargés
            List<X509Certificate> certs = new ArrayList<>();
            for (int i = 1; i < parsedArgs.length; i++) {
                certs.add(loadCertificate(Path.of(parsedArgs[i]), format));  // Chargement de chaque certificat selon le chemin et le format spécifiés, puis ajout à la liste des certificats
            }

            // Validation de la chaîne de certificats à l'aide de la liste des certificats chargés
            validateCertificateChain(certs);

        } catch (Exception e) {
            System.err.println("Error processing certificate chain: " + e.getMessage());
            e.printStackTrace();
        }
    }

    public static Optional<String[]> parseArguments(String[] args) throws IllegalArgumentException {
        String format = "DER"; // format par défaut
        List<String> certPaths = new ArrayList<>(); // Initialisation d'une liste pour stocker les chemins des certificats

        // Boucle de parcours des arguments passés au programme
        for (int i = 0; i < args.length; i++) {
            switch (args[i]) {
                case "-format":
                    // Si l'argument "-format" est trouvé, vérifier que le prochain argument est "DER" ou "PEM"
                    if (i + 1 < args.length && ("DER".equalsIgnoreCase(args[i + 1]) || "PEM".equalsIgnoreCase(args[i + 1]))) {
                        // Mise à jour du format avec la valeur spécifiée
                        format = args[++i].toUpperCase();
                    } else {
                        throw new IllegalArgumentException("Format specifier -format must be followed by DER or PEM");
                    }
                    break;
                default:
                    certPaths.add(args[i]); // Ajout du chemin de certificat à la liste
                    break;
            }
        }

        // Vérifier que la liste des chemins de certificats n'est pas vide
        if (certPaths.isEmpty()) {
            throw new IllegalArgumentException("At least one certificate file path is required. Usage: validate-cert [-format DER|PEM] <myCertFile>...");
        }

        // Création d'un tableau pour stocker le format et les chemins des certificats
        String[] result = new String[certPaths.size() + 1];
        result[0] = format; // Le premier élément est le format des certificats
        // Ajout des chemins des certificats au tableau
        for (int i = 0; i < certPaths.size(); i++) {
            result[i + 1] = certPaths.get(i);
        }

        // Retourne un Optional contenant le tableau des arguments analysés
        return Optional.of(result);
    }

    private static void validateCertificateChain(List<X509Certificate> certs) throws Exception {
        for (int i = 0; i < certs.size(); i++) {     // Parcours de chaque certificat dans la liste fournie pour validation
            System.out.println("\n\n########## Certificate " + (i + 1) + " ##########\n");
            X509Certificate cert = certs.get(i);

            // L'émetteur est le certificat précédent dans la liste, sauf pour le premier certificat qui est auto-signé
            X509Certificate issuerCert = (i == 0) ? cert : certs.get(i - 1);

            // Pour le premier certificat (racine), vérifier qu'il est bien auto-signé
            if (i == 0 && !cert.getIssuerX500Principal().equals(cert.getSubjectX500Principal())) {
                throw new IllegalArgumentException("Root certificate is not self-signed");
            }

            // Pour les certificats suivants, vérifier que l'émetteur correspond bien au certificat précédent
            if (i != 0 && !cert.getIssuerX500Principal().equals(issuerCert.getSubjectX500Principal())) {
                continue;
            }

            // Vérification de la signature et de l'algorithme utilisé pour signer le certificat
            checkSignatureAndAlgorithm(cert, issuerCert);

            checkValidityPeriod(cert); // Vérification de la période de validité du certificat
            checkAndDisplayKeyUsage(cert); // Vérification de l'utilisation correcte de la clé du certificat
            verifyBasicConstraints(cert); // Vérification des contraintes de base du certificat (par exemple, s'il peut être utilisé comme CA)


            // Extraction et affichage des points de distribution de la liste de révocation (CRL) du certificat
            List<String> crlUrls = getCrlDistributionPoints(cert);
            if (!crlUrls.isEmpty()) {
                System.out.println("CRL Distribution Points:");
                for (String url : crlUrls) {
                    System.out.println("- " + url);
                }
            } else {
                System.out.println("No CRL Distribution Points available.");
            }

            // Vérification de la révocation du certificat en utilisant les CRL
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

    // Vérifie si le certificat est dans sa période de validité
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
        // Récupère les informations sur l'utilisation de la clé du certificat
        boolean[] keyUsage = cert.getKeyUsage();
        if (keyUsage != null) {
            Map<Integer, String> keyUsageNames = new HashMap<>(); // Initialisation d'une correspondance entre les indices de l'utilisation de la clé et leur signification
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
            String sigAlg = cert.getSigAlgName(); // Récupération du nom de l'algorithme de signature du certificat
            if (sigAlg.contains("RSA")) {  // Vérification de la signature RSA, si applicable
                if (verifyRSASignature(cert, issuerCert)) {
                    System.out.println("RSA Signature verifies: SUCCESS");
                } else {
                    System.out.println("RSA Signature verifies: FAILED");
                }

            }
            if (sigAlg.contains("ECDSA")) { // Vérification de la signature ECDSA, si applicable
                if (verifyECDSASignature(cert, issuerCert)) {
                    System.out.println("ECDSA Signature verifies: SUCCESS");
                } else {
                    System.out.println("ECDSA Signature verifies: FAILED");
                }
            }

            //Vérification de la signature du certificat sans utiliser les algorithmes spécifiques
            Signature sig = Signature.getInstance(sigAlg);
            sig.initVerify(issuerCert.getPublicKey());
            sig.update(cert.getTBSCertificate());  // Mise à jour de l'objet Signature avec les données à signer
            boolean verifies = sig.verify(cert.getSignature()); // Vérification de la signature du certificat
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

            if (format.equalsIgnoreCase("DER")) { // Chargement d'un certificat au format DER
                try (InputStream in = Files.newInputStream(path)) {
                    return (X509Certificate) certFactory.generateCertificate(in);
                }
            } else if (format.equalsIgnoreCase("PEM")) { // Chargement d'un certificat au format PEM
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
            PublicKey publicKey = issuerCert.getPublicKey(); // Récupération de la clé publique de l'émetteur du certificat
            if (publicKey instanceof RSAPublicKey rsaPublicKey) {

                // Extraction du module et de l'exposant de la clé publique RSA
                BigInteger modulus = rsaPublicKey.getModulus();
                BigInteger exponent = rsaPublicKey.getPublicExponent();

                // Conversion de la signature du certificat en BigInteger
                byte[] signatureBytes = cert.getSignature();
                BigInteger signature = new BigInteger(1, signatureBytes);

                // Déchiffrement de la signature avec la clé publique pour obtenir le hash
                BigInteger signatureCheck = signature.modPow(exponent, modulus);

                // Calcul du hash du certificat (TBSCertificate) à l'aide de SHA-256
                MessageDigest crypt = MessageDigest.getInstance("SHA-256");
                crypt.update(cert.getTBSCertificate());
                byte[] certHash = crypt.digest();

                // Extraction des octets correspondant à la longueur du hash attendu
                byte[] signatureCheckBytes = signatureCheck.toByteArray();

                String sigAlg = cert.getSigAlgName();
                int hashLength = 0;

                // Détermination de la longueur du hash en fonction de l'algorithme utilisé
                if (sigAlg.contains("SHA1")) {
                    hashLength = 20;
                } else if (sigAlg.contains("SHA256")) {
                    hashLength = 32;
                } else if (sigAlg.contains("SHA384")) {
                    hashLength = 48;
                } else if (sigAlg.contains("SHA512")) {
                    hashLength = 64;
                }

                // Sélection des derniers octets du hash déchiffré correspondant à la longueur attendue du hash
                signatureCheckBytes = Arrays.copyOfRange(signatureCheckBytes, signatureCheckBytes.length - hashLength, signatureCheckBytes.length);

                // Comparaison du hash calculé avec le hash obtenu après déchiffrement de la signature
                return java.util.Arrays.equals(certHash, signatureCheckBytes);
            }
        } catch (CertificateEncodingException | NoSuchAlgorithmException e) {
            e.printStackTrace();
        }
        return false; // Retourne faux si la vérification échoue ou en cas d'exception
    }

    public static void verifyBasicConstraints(X509Certificate cert) {
        // Récupération de l'extension des contraintes de base du certificat
        int basicConstraints = cert.getBasicConstraints();
        if (basicConstraints != -1) { // Vérification si le certificat peut agir comme une autorité de certification (CA)
            System.out.println("This certificate is a CA with basic constraints of : " + basicConstraints);
        } else {
            System.out.println("This certificate is not a CA.");
        }

    }

    private static boolean verifyECDSASignature(X509Certificate cert, X509Certificate issuerCert) throws Exception {
        Security.addProvider(new BouncyCastleProvider());    // Ajout de Bouncy Castle comme fournisseur de sécurité pour les opérations cryptographiques

        // Extraction et décodage des composants r et s de la signature ECDSA du certificat
        byte[] signature = cert.getSignature();
        BigInteger[] rs = decodeECDSASignature(signature);

        PublicKey publicKey = issuerCert.getPublicKey(); // Vérification que la clé publique de l'émetteur est de type EC (Courbe Elliptique)
        if (!(publicKey instanceof ECPublicKey)) {
            throw new IllegalArgumentException("Public key must be instance of ECPublicKey for ECDSA verification.");
        }

        ECPublicKey ecPublicKey = (ECPublicKey) publicKey;
        ECParameterSpec spec = ecPublicKey.getParams();     // Récupération des paramètres de la courbe elliptique utilisée pour la clé publique
        System.out.println("Curve: " + spec);
        // Sélection de la courbe elliptique basée sur l'algorithme de signature du certificat
        ECCurve curve = null;
        if (cert.getSigAlgName().contains("SHA384")) {
            curve = new org.bouncycastle.math.ec.custom.sec.SecP384R1Curve(); // Adaptez à la courbe utilisée si nécessaire
        } else if (cert.getSigAlgName().contains("SHA256")) {
            curve = new org.bouncycastle.math.ec.custom.sec.SecP256R1Curve(); // Adaptez à la courbe utilisée si nécessaire
        }
        assert curve != null;
        // Création du point sur la courbe à partir de la clé publique
        ECPoint point = curve.createPoint(ecPublicKey.getW().getAffineX(), ecPublicKey.getW().getAffineY(), false);
        // Configuration des paramètres du domaine EC utilisés pour la vérification
        ECDomainParameters domainParameters = new ECDomainParameters(
                curve,
                curve.createPoint(spec.getGenerator().getAffineX(), spec.getGenerator().getAffineY()),
                spec.getOrder(),
                BigInteger.valueOf(spec.getCofactor()));
        ECPublicKeyParameters publicKeyParameters = new ECPublicKeyParameters(point, domainParameters);

        // Préparation de l'algorithme de hash pour calculer le hash du TBSCertificate
        MessageDigest crypt = null;
        if (cert.getSigAlgName().contains("SHA384")) {
            crypt = MessageDigest.getInstance("SHA-384");
        } else if (cert.getSigAlgName().contains("SHA256")) {
            crypt = MessageDigest.getInstance("SHA-256");
        }
        assert crypt != null;
        crypt.update(cert.getTBSCertificate());
        byte[] certHash = crypt.digest();

        // Initialisation du vérificateur ECDSA avec la clé publique
        ECDSASigner signer = new ECDSASigner();
        signer.init(false, publicKeyParameters);
        // Vérification de la signature ECDSA avec les composants r et s
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
            // Extraction de la valeur de l'extension des points de distribution CRL du certificat
            byte[] crlDPExtensionValue = cert.getExtensionValue(cRLDistributionPoints.getId());
            System.out.println("CRL Distribution Points extension: " + crlDPExtensionValue);
            if (crlDPExtensionValue == null) {
                return Collections.emptyList(); // Retourne une liste vide si l'extension n'est pas présente
            }
            // Lecture et décodage de la valeur de l'extension pour obtenir les points de distribution CRL
            ASN1InputStream oAsnInStream = new ASN1InputStream(new ByteArrayInputStream(crlDPExtensionValue));
            ASN1Primitive derObjCrlDP = oAsnInStream.readObject();
            DEROctetString dosCrlDP = (DEROctetString) derObjCrlDP;
            byte[] crlDPsExtOctets = dosCrlDP.getOctets();
            ASN1InputStream oAsnInStream2 = new ASN1InputStream(new ByteArrayInputStream(crlDPsExtOctets));
            ASN1Primitive derObj2 = oAsnInStream2.readObject();
            CRLDistPoint distPoint = CRLDistPoint.getInstance(derObj2);

            // Compilation des URL des points de distribution CRL à partir de l'objet distPoint
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
        // Établissement d'une connexion HTTP pour récupérer la date de dernière modification de la CRL
        HttpURLConnection conn = (HttpURLConnection) new URL(url).openConnection();
        conn.setRequestMethod("HEAD");
        return new Date(conn.getLastModified());
    }

    private static String sanitizeUrl(String url) {
        // Nettoyage de l'URL pour utilisation dans un système de fichiers
        return url.replaceAll("[:/]", "_");
    }

    private static void verifyCRL(X509Certificate cert, List<String> crlUrls) {
    for (String url : crlUrls) {
        try {
            String sanitizedUrl = sanitizeUrl(url); // Nettoyage de l'URL pour éviter les problèmes de nommage de fichiers

            // Lecture de la liste des URLs en cache
            List<String> cachedUrls = Files.readAllLines(Paths.get("crlCache.txt"));
            File crlFile = new File("./cache", sanitizedUrl);
            X509CRL crl = null;
            if (cachedUrls.contains(url) && crlFile.exists()) { // Si la CRL est en cache et toujours valide, elle est chargée du fichier
                try (InputStream in = new FileInputStream(crlFile)) {
                    CertificateFactory cf = CertificateFactory.getInstance("X.509");
                    crl = (X509CRL) cf.generateCRL(in);
                }
                // Vérifier si la CRL est toujours valide
                if (crl.getNextUpdate().after(new Date())) {
                    System.out.println("CRL loaded from cache: " + url);
                } else {
                    crl = null; // La CRL est obsolète et doit être rafraîchie
                }
            }
            // Si la CRL n'est pas en cache ou est obsolète, elle est téléchargée
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
                // Ajout de l'URL au fichier de cache si nécessaire
                if (!cachedUrls.contains(url)) {
                    Files.write(Paths.get("crlCache.txt"), (url + System.lineSeparator()).getBytes(), StandardOpenOption.APPEND);
                }
                System.out.println("CRL downloaded and cached: " + url);
            }
            // Vérification si le certificat est révoqué par la CRL
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
            String ocspUrl = extractOcspUrl(cert); // Extraction de l'URL OCSP à partir du certificat
            if (ocspUrl == null) {
                System.out.println("OCSP URL not found in certificate. Skipping OCSP verification.");
                return;
            }

            // Construction de la requête OCSP
            OCSPReqBuilder builder = new OCSPReqBuilder();
            try {
                // Génération de l'identifiant du certificat pour la requête OCSP
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


                // Traitement de la réponse OCSP
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
        // Extraction de l'URL OCSP depuis l'extension Authority Information Access du certificat
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
        // Création de l'identifiant du certificat pour la requête OCSP en utilisant le digest SHA-1
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