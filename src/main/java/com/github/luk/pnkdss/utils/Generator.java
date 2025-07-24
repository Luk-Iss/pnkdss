package com.github.luk.pnkdss.utils;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.stereotype.Component;

import java.math.BigInteger;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.UUID;
import java.util.concurrent.TimeUnit;

@Component
public class Generator {

    public static final String DEFAULT_PASSWORD = UUID.randomUUID().toString();

    public static String xmlContent = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
            + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:com:github:luk:pnkdss\">\n"
            + "  <soapenv:Header />\n" + "  <soapenv:Body>\n" + "    <urn:data urn:id=\"signedData\">\n"
            + "      <urn:simpleElement>Hello World!</urn:simpleElement>\n" + "    </urn:data>\n" + "  </soapenv:Body>\n"
            + "</soapenv:Envelope>";

    /**
     * Creates a PKCS12 KeyStore with a self-signed certificate.
     *
     * @return A KeyStore containing a generated key pair and certificate.
     * @throws Exception If an error occurs during KeyStore creation.
     */
    public static KeyStore createP12KeyStore() throws Exception {
        KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
        keyPairGenerator.initialize(2048, new SecureRandom());
        KeyPair keyPair = keyPairGenerator.generateKeyPair();
        PrivateKey privateKey = keyPair.getPrivate();

        X500Name issuer = new X500Name("C=US, O=ExampleCorp, CN=Example Signer, E=signer@example.com");
        BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
        Date notBefore = new Date(System.currentTimeMillis());
        Date notAfter = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)); // 365 days validity

        X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, issuer,
                keyPair.getPublic());

        ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
        if (Security.getProvider("BC") == null) {
          Security.addProvider(new BouncyCastleProvider());
          System.out.println("Bouncy Castle provider registered.");
        }
        X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
                .getCertificate(certBuilder.build(contentSigner));

        KeyStore p12KeyStore = KeyStore.getInstance("PKCS12");
        p12KeyStore.load(null, null);

        String alias = "1";

        p12KeyStore.setKeyEntry(alias, privateKey, DEFAULT_PASSWORD.toCharArray(), new java.security.cert.Certificate[]{certificate});

        return p12KeyStore;
    }
}