package com.github.luk.pnkdss;

import java.io.FileOutputStream;
import java.io.InputStream;
import java.math.BigInteger;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.security.KeyPair;
import java.security.KeyPairGenerator;
import java.security.KeyStore;
import java.security.PrivateKey;
import java.security.SecureRandom;
import java.security.Security;
import java.security.cert.X509Certificate;
import java.util.Date;
import java.util.concurrent.TimeUnit;

import org.bouncycastle.asn1.x500.X500Name;
import org.bouncycastle.cert.X509v3CertificateBuilder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import org.bouncycastle.cert.jcajce.JcaX509v3CertificateBuilder;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.bouncycastle.operator.ContentSigner;
import org.bouncycastle.operator.jcajce.JcaContentSignerBuilder;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;

@SpringBootApplication
public class Main implements CommandLineRunner {

  public static final String DEFAULT_PASSWORD = "7T4W#+bjYY9wrS78";

  private final Signer signer;
  private final Validator validator;

  public Main(Signer signer, Validator validator) {
      this.signer = signer;
      this.validator = validator;
  }

  public static void main(String[] args) {
      if (Security.getProvider("BC") == null) {
          Security.addProvider(new BouncyCastleProvider());
          System.out.println("Bouncy Castle provider registrován.");
      }
      SpringApplication.run(Main.class, args);
  }
  
  @Override
  public void run(String... args) throws Exception {
      if (args.length < 1) {
          printUsage();
          return;
      }

      String command = args[0];
      try {
          switch (command) {
          case "gen":
              handleGenCommand(args);
              break;
          case "sign":
              handleSignCommand(args);
              break;
          case "verify":
              handleVerifyCommand(args);
              break;
          default:
              System.err.println("Neznámý příkaz: " + command);
              printUsage();
          }
      } catch (Exception e) {
          System.err.println("Došlo k chybě: " + e.getMessage());
          e.printStackTrace();
          System.exit(1);
      }
  }

  
  /**
   * Vypíše nápovědu k použití nástroje.
   */
  private static void printUsage() {
    System.out.println("Použití:");
    System.out.println("  java -jar pnkDss-1.0-SNAPSHOT.jar gen doc.xml keystore.p12 pass.txt");
    System.out.println("  java -jar pnkDss-1.0-SNAPSHOT.jar sign doc.xml sigdoc.xml keystore.p12 pass.txt");
    System.out.println("  java -jar pnkDss-1.0-SNAPSHOT.jar verify sigdoc.xml cert_output.pem");
  }

  /**
   * Zpracuje příkaz 'gen' pro generování souborů.
   * 
   * @param args Argumenty příkazové řádky.
   * @throws Exception Pokud dojde k chybě při generování.
   */
  private static void handleGenCommand(String[] args) throws Exception {
    if (args.length != 4) {
      System.err.println("Chybné použití pro 'gen'.");
      printUsage();
      return;
    }

    Path documentPath = Paths.get(args[1]);
    Path p12Path = Paths.get(args[2]);
    Path passPath = Paths.get(args[3]);

    System.out.println("Generuji soubory...");

    Files.write(documentPath, xmlContent.getBytes(StandardCharsets.UTF_8));
    System.out.println("Vygenerováno: " + documentPath);

    Files.write(passPath, DEFAULT_PASSWORD.getBytes(StandardCharsets.UTF_8));
    System.out.println("Vygenerováno: " + passPath);

    generateP12File(p12Path, DEFAULT_PASSWORD.toCharArray());
    System.out.println("Vygenerováno: " + p12Path);

    System.out.println("Generování dokončeno.");
  }

  /**
   * Pomocná metoda pro generování P12 souboru na disk.
   * 
   * @param outputPath Cesta, kam se má P12 soubor uložit.
   * @param password   Heslo pro P12 soubor.
   * @throws Exception Pokud dojde k chybě při generování P12.
   */
  private static void generateP12File(Path outputPath, char[] password) throws Exception {
    KeyStore p12KeyStore = p12();
    try (FileOutputStream fos = new FileOutputStream(outputPath.toFile())) {
      p12KeyStore.store(fos, DEFAULT_PASSWORD.toCharArray());
    }
  }

  public static String xmlContent = "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"no\"?>\n"
      + "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:urn=\"urn:com:github:luk:pnkdss\">\n"
      + "  <soapenv:Header />\n" + "  <soapenv:Body>\n" + "    <urn:data urn:id=\"signedData\">\n"
      + "      <urn:simpleElement>Hello World!</urn:simpleElement>\n" + "    </urn:data>\n" + "  </soapenv:Body>\n"
      + "</soapenv:Envelope>";

  /**
   * Zpracuje příkaz 'sign' pro podepsání dokumentu.
   * 
   * @param args Argumenty příkazové řádky.
   * @throws Exception Pokud dojde k chybě při podepisování.
   */
  private void handleSignCommand(String[] args) throws Exception {
    if (args.length != 5) {
      System.err.println("Chybné použití pro 'sign'.");
      printUsage();
      return;
    }

    Path inputDocumentPath = Paths.get(args[1]);
    Path outputDocumentPath = Paths.get(args[2]);
    Path p12Path = Paths.get(args[3]);
    Path passPath = Paths.get(args[4]);

    System.out.println("Podepisuji dokument '" + inputDocumentPath + "' a ukládám do '" + outputDocumentPath + "'...");

    new String(Files.readAllBytes(passPath), StandardCharsets.UTF_8).trim();

    try (InputStream documentIs = Files.newInputStream(inputDocumentPath);
        InputStream p12Is = Files.newInputStream(p12Path)) {

      String signedXml = signer.sign(documentIs, p12Is, DEFAULT_PASSWORD.toCharArray());

      Files.write(outputDocumentPath, signedXml.getBytes(StandardCharsets.UTF_8));
      System.out.println("Dokument podepsán a uložen do: " + outputDocumentPath);
    }
  }

  /**
   * Zpracuje příkaz 'verify' pro ověření dokumentu a vypsání certifikátu.
   * 
   * @param args Argumenty příkazové řádky.
   * @throws Exception Pokud dojde k chybě při ověřování.
   */
  private void handleVerifyCommand(String[] args) throws Exception {
    if (args.length != 3) { // Očekáváme 3 argumenty: příkaz, cesta k XML, cesta k výstupnímu certifikátu
      System.err.println("Chybné použití pro 'verify'.");
      printUsage();
      return;
    }

    Path documentPath = Paths.get(args[1]);
    Path certOutputPath = Paths.get(args[2]);

    System.out.println("Ověřuji dokument: " + documentPath);

    try (InputStream documentIs = Files.newInputStream(documentPath)) {
      SignatureResult sr = validator.check(documentIs);

      System.out.println("\n--- Výsledek ověření podpisu ---");
      if (sr.isResultOK()) {
        System.out.println("Podpis je matematicky platný.");
        if (sr.getPem() != null) {
          Files.write(certOutputPath, sr.getPem().getBytes(StandardCharsets.UTF_8));
          System.out.println("Podpisový certifikát uložen do: " + certOutputPath);
        } else {
          System.err.println("Chyba: Podpis je platný, ale certifikát v PEM formátu nebyl nalezen v SignatureResult.");
        }
      } else {
        System.out.println("Podpis NENÍ matematicky platný!");
      }
    }
  }

  public static KeyStore p12() throws Exception {
    KeyPairGenerator keyPairGenerator = KeyPairGenerator.getInstance("RSA");
    keyPairGenerator.initialize(2048, new SecureRandom());
    KeyPair keyPair = keyPairGenerator.generateKeyPair();
    PrivateKey privateKey = keyPair.getPrivate();

    X500Name issuer = new X500Name("C=CZ, O=Github, CN=DL, E=luk.iss@seznam.cz");
    BigInteger serial = BigInteger.valueOf(System.currentTimeMillis());
    Date notBefore = new Date(System.currentTimeMillis());
    Date notAfter = new Date(System.currentTimeMillis() + TimeUnit.DAYS.toMillis(365)); // Platnost 365 dní

    X509v3CertificateBuilder certBuilder = new JcaX509v3CertificateBuilder(issuer, serial, notBefore, notAfter, issuer,
        keyPair.getPublic());

    ContentSigner contentSigner = new JcaContentSignerBuilder("SHA256WithRSA").build(privateKey);
    X509Certificate certificate = new JcaX509CertificateConverter().setProvider("BC")
        .getCertificate(certBuilder.build(contentSigner));

    KeyStore p12KeyStore = KeyStore.getInstance("PKCS12");
    p12KeyStore.load(null, null);

    String alias = "1";
    char[] password = DEFAULT_PASSWORD.toCharArray();

    p12KeyStore.setKeyEntry(alias, privateKey, password, new java.security.cert.Certificate[] { certificate });

    return p12KeyStore;
  }
}