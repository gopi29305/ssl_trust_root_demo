package com.example.ssltrust.pki;

import org.bouncycastle.asn1.x509.BasicConstraints;
import org.bouncycastle.asn1.x509.ExtendedKeyUsage;
import org.bouncycastle.asn1.x509.Extension;
import org.bouncycastle.asn1.x509.GeneralName;
import org.bouncycastle.asn1.x509.GeneralNames;
import org.bouncycastle.asn1.x509.KeyPurposeId;
import org.bouncycastle.asn1.x509.KeyUsage;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509ExtensionUtils;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;

import java.io.ByteArrayInputStream;
import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.CertificateFactory;
import java.security.cert.X509Certificate;
import java.time.Instant;
import java.time.temporal.ChronoUnit;
import java.util.Date;
import javax.security.auth.x500.X500Principal;

/**
 * Builds a throwaway Root → Intermediate → Leaf hierarchy with BouncyCastle.
 *
 * <p>Nothing here is written to disk. Every process start gets a fresh PKI so the
 * demo never depends on pre-generated files or {@code openssl} being on the PATH.
 *
 * <p>The important modeling choices, which match real CAs:
 * <ul>
 *   <li>Root and intermediate have {@code basicConstraints CA:true} and
 *       {@code keyCertSign}.</li>
 *   <li>The intermediate has {@code pathLen=0} (it may sign end-entity certs only).</li>
 *   <li>The leaf has {@code CA:false}, {@code EKU = serverAuth}, and a SAN for
 *       {@code localhost} / {@code 127.0.0.1} so Java hostname verification passes.</li>
 * </ul>
 */
public final class DemoPki {

    private static final String SIGNATURE_ALGORITHM = "SHA256WithRSA";
    private static final int KEY_SIZE = 2048;

    static {
        if (Security.getProvider(BouncyCastleProvider.PROVIDER_NAME) == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
    }

    private DemoPki() {
    }

    public static DemoCertificates generate() {
        try {
            KeyPair rootKeys = rsaKeyPair();
            KeyPair intermediateKeys = rsaKeyPair();
            KeyPair leafKeys = rsaKeyPair();

            X509Certificate root = selfSignedCa(
                    "CN=Demo Root CA,O=SSL Trust Demo",
                    rootKeys,
                    /* pathLenConstraint */ 1,
                    3650
            );

            X509Certificate intermediate = signedCa(
                    "CN=Demo Intermediate CA,O=SSL Trust Demo",
                    intermediateKeys,
                    root,
                    rootKeys,
                    /* pathLenConstraint */ 0,
                    1825
            );

            X509Certificate leaf = signedServer(
                    "CN=localhost,O=SSL Trust Demo",
                    leafKeys,
                    intermediate,
                    intermediateKeys,
                    365
            );

            // Fail fast if issuer/subject DNs or signatures do not actually chain.
            // A mismatch here is the #1 reason JSSE reports "Certificate chain is not valid".
            root.verify(rootKeys.getPublic());
            intermediate.verify(rootKeys.getPublic());
            leaf.verify(intermediateKeys.getPublic());

            // Re-parse as JDK X509Certificate so JSSE KeyStores do not have to
            // deal with BouncyCastle's certificate implementation class.
            return new DemoCertificates(
                    toJca(root), rootKeys.getPrivate(),
                    toJca(intermediate), intermediateKeys.getPrivate(),
                    toJca(leaf), leafKeys.getPrivate()
            );
        } catch (Exception ex) {
            throw new IllegalStateException("Failed to generate demo PKI", ex);
        }
    }

    private static X509Certificate selfSignedCa(
            String distinguishedName,
            KeyPair keyPair,
            int pathLenConstraint,
            int daysValid
    ) throws Exception {
        return issueCertificate(
                distinguishedName,
                keyPair.getPublic(),
                keyPair,
                null,
                true,
                pathLenConstraint,
                false,
                daysValid
        );
    }

    private static X509Certificate signedCa(
            String subjectDn,
            KeyPair subjectKeys,
            X509Certificate issuerCert,
            KeyPair issuerKeys,
            int pathLenConstraint,
            int daysValid
    ) throws Exception {
        return issueCertificate(
                subjectDn,
                subjectKeys.getPublic(),
                issuerKeys,
                issuerCert,
                true,
                pathLenConstraint,
                false,
                daysValid
        );
    }

    private static X509Certificate signedServer(
            String subjectDn,
            KeyPair subjectKeys,
            X509Certificate issuerCert,
            KeyPair issuerKeys,
            int daysValid
    ) throws Exception {
        return issueCertificate(
                subjectDn,
                subjectKeys.getPublic(),
                issuerKeys,
                issuerCert,
                false,
                0,
                true,
                daysValid
        );
    }

    private static X509Certificate issueCertificate(
            String subjectDn,
            java.security.PublicKey subjectPublicKey,
            KeyPair issuerKeys,
            X509Certificate issuerCert,
            boolean certificateAuthority,
            int pathLenConstraint,
            boolean serverAuth,
            int daysValid
    ) throws Exception {
        Instant now = Instant.now();
        Date notBefore = Date.from(now.minus(1, ChronoUnit.HOURS));
        Date notAfter = Date.from(now.plus(daysValid, ChronoUnit.DAYS));
        BigInteger serial = new BigInteger(80, new SecureRandom());
        X500Principal subject = new X500Principal(subjectDn);

        // Use the issuer certificate object (not a re-parsed DN string) so the
        // child cert's issuer field is byte-for-byte the parent's subject.
        // Re-parsing "CN=...,O=..." as an X500Name can change string types and
        // break chain validation in PKCS12 / PKIX.
        X509v3CertificateBuilder builder = issuerCert == null
                ? new JcaX509v3CertificateBuilder(subject, serial, notBefore, notAfter, subject, subjectPublicKey)
                : new JcaX509v3CertificateBuilder(issuerCert, serial, notBefore, notAfter, subject, subjectPublicKey);

        JcaX509ExtensionUtils ext = new JcaX509ExtensionUtils();
        builder.addExtension(
                Extension.subjectKeyIdentifier,
                false,
                ext.createSubjectKeyIdentifier(subjectPublicKey)
        );
        if (issuerCert != null) {
            builder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    ext.createAuthorityKeyIdentifier(issuerCert)
            );
        } else {
            builder.addExtension(
                    Extension.authorityKeyIdentifier,
                    false,
                    ext.createAuthorityKeyIdentifier(subjectPublicKey)
            );
        }

        // CA certs must be marked CA:true or Java PKIX will refuse to use them as issuers.
        builder.addExtension(
                Extension.basicConstraints,
                true,
                certificateAuthority
                        ? new BasicConstraints(pathLenConstraint)
                        : new BasicConstraints(false)
        );

        if (certificateAuthority) {
            builder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.keyCertSign | KeyUsage.cRLSign)
            );
        } else {
            builder.addExtension(
                    Extension.keyUsage,
                    true,
                    new KeyUsage(KeyUsage.digitalSignature | KeyUsage.keyEncipherment)
            );
        }

        if (serverAuth) {
            builder.addExtension(
                    Extension.extendedKeyUsage,
                    false,
                    new ExtendedKeyUsage(KeyPurposeId.id_kp_serverAuth)
            );
            // Java HTTPS clients verify the hostname against SAN, not CN, on modern JDKs.
            builder.addExtension(
                    Extension.subjectAlternativeName,
                    false,
                    new GeneralNames(new GeneralName[]{
                            new GeneralName(GeneralName.dNSName, "localhost"),
                            new GeneralName(GeneralName.iPAddress, "127.0.0.1")
                    })
            );
        }

        ContentSigner signer = new JcaContentSignerBuilder(SIGNATURE_ALGORITHM)
                .build(issuerKeys.getPrivate());
        return new JcaX509CertificateConverter()
                .setProvider(BouncyCastleProvider.PROVIDER_NAME)
                .getCertificate(builder.build(signer));
    }

    private static X509Certificate toJca(X509Certificate certificate) throws Exception {
        return (X509Certificate) CertificateFactory.getInstance("X.509")
                .generateCertificate(new ByteArrayInputStream(certificate.getEncoded()));
    }

    private static KeyPair rsaKeyPair() throws Exception {
        KeyPairGenerator generator = KeyPairGenerator.getInstance("RSA");
        generator.initialize(KEY_SIZE, new SecureRandom());
        return generator.generateKeyPair();
    }
}
