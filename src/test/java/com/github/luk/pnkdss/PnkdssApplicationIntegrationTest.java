package com.github.luk.pnkdss;

import com.github.luk.pnkdss.commands.GenerateCommand;
import com.github.luk.pnkdss.commands.SignCommand;
import com.github.luk.pnkdss.commands.VerifyCommand;
import com.github.luk.pnkdss.utils.Generator;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.io.TempDir;
import picocli.CommandLine;
import picocli.CommandLine.IFactory;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.io.StringReader;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.security.cert.X509Certificate;
import java.util.Arrays;
import java.util.List;

import org.bouncycastle.openssl.PEMParser;
import org.bouncycastle.cert.X509CertificateHolder;
import org.bouncycastle.cert.jcajce.JcaX509CertificateConverter;
import java.security.Security;
import org.bouncycastle.jce.provider.BouncyCastleProvider;


import static org.junit.jupiter.api.Assertions.*;

/**
 * Integration tests for the Pnkdss application.
 * Tests the entire workflow (generation, signing, verification)
 * and various command-line scenarios.
 */
@SpringBootTest
class PnkdssApplicationIntegrationTest {

    @Autowired
    private IFactory picocliFactory; // Injects Picocli factory for proper command creation

    @TempDir // Automatically creates and deletes a temporary directory for the test
    Path tempDir;

    private Path generatedDocumentPath;
    private Path generatedKeystorePath;
    private Path generatedPasswordPath;
    private Path signedDocumentPath;
    private Path extractedCertificatePath;

    private final ByteArrayOutputStream outContent = new ByteArrayOutputStream();
    private final ByteArrayOutputStream errContent = new ByteArrayOutputStream();
    private final PrintStream originalOut = System.out;
    private final PrintStream originalErr = System.err;

    @BeforeEach
    void setUp() {
        // Set up temporary paths for test files
        generatedDocumentPath = tempDir.resolve("generated-document.xml");
        generatedKeystorePath = tempDir.resolve("generated-keystore.p12");
        generatedPasswordPath = tempDir.resolve("generated-password.txt");
        signedDocumentPath = tempDir.resolve("signed-document.xml");
        extractedCertificatePath = tempDir.resolve("extracted-certificate.pem");

        // Redirect System.out and System.err to capture console output
        System.setOut(new PrintStream(outContent));
        System.setErr(new PrintStream(errContent));
    }

    @AfterEach
    void tearDown() {
        // Restore original System.out and System.err
        System.setOut(originalOut);
        System.setErr(originalErr);
        // Clear buffers in case tests are run within a single runner
        outContent.reset();
        errContent.reset();
    }

    /**
     * Tests the complete successful workflow: generation, signing, and verification.
     */
    @Test
    void testFullSuccessfulWorkflow() throws Exception {
        System.out.println("--- Running test: Full successful workflow ---");

        // 1. Generate files
        GenerateCommand genCommand = (GenerateCommand) picocliFactory.create(GenerateCommand.class);
        genCommand.setDocumentPath(generatedDocumentPath);
        genCommand.setP12Path(generatedKeystorePath);
        genCommand.setPassPath(generatedPasswordPath);
        int genExitCode = genCommand.call();
        assertEquals(0, genExitCode, "Command 'gen' should exit with code 0.");
        assertTrue(Files.exists(generatedDocumentPath), "Generated XML document should exist.");
        assertTrue(Files.exists(generatedKeystorePath), "Generated P12 keystore should exist.");
        assertTrue(Files.exists(generatedPasswordPath), "Generated password file should exist.");
        outContent.reset(); // Clear buffer

        // 2. Sign document
        SignCommand signCommand = (SignCommand) picocliFactory.create(SignCommand.class);
        signCommand.setInputDocumentPath(generatedDocumentPath);
        signCommand.setOutputDocumentPath(signedDocumentPath);
        signCommand.setP12Path(generatedKeystorePath);
        signCommand.setPassPath(generatedPasswordPath);
        int signExitCode = signCommand.call();
        assertEquals(0, signExitCode, "Command 'sign' should exit with code 0.");
        assertTrue(Files.exists(signedDocumentPath), "Signed XML document should exist.");
        assertTrue(Files.size(signedDocumentPath) > Files.size(generatedDocumentPath), "Signed document should be larger than original.");
        outContent.reset();

        // 3. Verify signed document
        VerifyCommand verifyCommand = (VerifyCommand) picocliFactory.create(VerifyCommand.class);
        verifyCommand.setDocumentPath(signedDocumentPath);
        verifyCommand.setCertOutputPath(extractedCertificatePath);
        int verifyExitCode = verifyCommand.call();
        assertEquals(0, verifyExitCode, "Command 'verify' should exit with code 0.");
        
        // Assert: Standard output contains "Signature is mathematically valid." on the second to last line
        List<String> outputLines = Arrays.asList(outContent.toString().split("\\r?\\n"));
        assertFalse(outputLines.isEmpty(), "Output should not be empty.");
        assertTrue(outputLines.size() >= 2, "Output should have at least two lines for verification message.");
        assertEquals("Signature is mathematically valid.", outputLines.get(outputLines.size() - 2).trim(),
                     "Second to last line of output should confirm valid signature.");
        
        assertTrue(Files.exists(extractedCertificatePath), "Extracted certificate file should exist.");
        assertTrue(Files.size(extractedCertificatePath) > 0, "Extracted certificate file should not be empty.");
        outContent.reset();

        // Assert: Certificate from keystore is cryptographically equivalent to the extracted certificate
        // Load certificate from generated keystore
        KeyStore p12KeyStore = KeyStore.getInstance("PKCS12");
        p12KeyStore.load(Files.newInputStream(generatedKeystorePath), Generator.DEFAULT_PASSWORD.toCharArray());
        X509Certificate generatedCert = (X509Certificate) p12KeyStore.getCertificate("1"); // Assuming alias "1" from Generator

        // Load certificate from extracted PEM file (Java 8 compatible)
        byte[] pemBytes = Files.readAllBytes(extractedCertificatePath);
        String pemContent = new String(pemBytes, StandardCharsets.UTF_8);
        
        // Ensure Bouncy Castle provider is available for PEM parsing if not already
        if (Security.getProvider("BC") == null) {
            Security.addProvider(new BouncyCastleProvider());
        }
        
        PEMParser pemParser = new PEMParser(new StringReader(pemContent));
        Object parsedObject = pemParser.readObject();
        X509Certificate extractedCert = null;
        if (parsedObject instanceof X509CertificateHolder) {
            extractedCert = new JcaX509CertificateConverter().setProvider("BC").getCertificate((X509CertificateHolder) parsedObject);
        }
        assertNotNull(extractedCert, "Extracted certificate should not be null after parsing PEM.");

        // Compare public keys for cryptographic equivalence
        assertEquals(generatedCert.getPublicKey(), extractedCert.getPublicKey(),
                     "Public keys of generated and extracted certificates should be identical.");
        System.out.println("Certificates are cryptographically equivalent.");
    }

    /**
     * Tests the scenario where a signed document is tampered with and then verified.
     * Expects the verification to fail.
     * @throws Exception
     */
    @Test
    void testVerifyTamperedSignedDocument() throws Exception {
        System.out.println("--- Running test: Verify tampered signed document ---");

        // 1. Generate and sign a document (setup for tampering)
        GenerateCommand genCommand = (GenerateCommand) picocliFactory.create(GenerateCommand.class);
        genCommand.setDocumentPath(generatedDocumentPath);
        genCommand.setP12Path(generatedKeystorePath);
        genCommand.setPassPath(generatedPasswordPath);
        genCommand.call();
        outContent.reset();

        SignCommand signCommand = (SignCommand) picocliFactory.create(SignCommand.class);
        signCommand.setInputDocumentPath(generatedDocumentPath);
        signCommand.setOutputDocumentPath(signedDocumentPath);
        signCommand.setP12Path(generatedKeystorePath);
        signCommand.setPassPath(generatedPasswordPath);
        signCommand.call();
        outContent.reset();

        // 2. Tamper with the signed document
        String originalSignedContent = new String(Files.readAllBytes(signedDocumentPath), StandardCharsets.UTF_8);
        String tamperedContent = originalSignedContent.replace("Hello World!", "Hell World!"); // Modify the content
        Files.write(signedDocumentPath, tamperedContent.getBytes(StandardCharsets.UTF_8));
        System.out.println("Document tampered: " + signedDocumentPath);

        // 3. Verify the tampered document
        VerifyCommand verifyCommand = (VerifyCommand) picocliFactory.create(VerifyCommand.class);
        verifyCommand.setDocumentPath(signedDocumentPath);
        verifyCommand.setCertOutputPath(extractedCertificatePath); // Certificate extraction might fail for tampered doc
        int verifyExitCode = verifyCommand.call();

        assertEquals(0, verifyExitCode, "Command 'verify' should exit with code 0 even for invalid signature.");
        
        // Assert: Standard output contains "Signature IS NOT mathematically valid!"
        assertTrue(outContent.toString().contains("Signature IS NOT mathematically valid!"),
                   "Verification output should indicate that the signature is NOT mathematically valid.");
        
        // Assert: Certificate file should NOT be created or should be empty for an invalid signature
        assertFalse(Files.exists(extractedCertificatePath) && Files.size(extractedCertificatePath) > 0, 
                    "Extracted certificate file should not exist or be empty for an invalid signature.");
        outContent.reset();
    }


    /**
     * Tests the scenario where an attempt is made to sign a non-existent document.
     * @throws Exception 
     */
    @Test
    void testSignNonExistentDocument() throws Exception {
        System.out.println("--- Running test: Signing a non-existent document ---");

        SignCommand signCommand = (SignCommand) picocliFactory.create(SignCommand.class);
        signCommand.setInputDocumentPath(tempDir.resolve("non-existent.xml")); // Non-existent file
        signCommand.setOutputDocumentPath(signedDocumentPath);
        signCommand.setP12Path(generatedKeystorePath); 
        signCommand.setPassPath(generatedPasswordPath); 

        // Expect an IOException because the input file does not exist
        assertThrows(java.io.IOException.class, () -> signCommand.call(),
                "Command 'sign' should throw IOException for a non-existent input document.");
        outContent.reset();
    }

    /**
     * Tests the scenario where an attempt is made to verify a non-existent document.
     * @throws Exception 
     */
    @Test
    void testVerifyNonExistentDocument() throws Exception {
        System.out.println("--- Running test: Verifying a non-existent document ---");

        VerifyCommand verifyCommand = (VerifyCommand) picocliFactory.create(VerifyCommand.class);
        verifyCommand.setDocumentPath(tempDir.resolve("non-existent-signed.xml")); // Non-existent file
        verifyCommand.setCertOutputPath(extractedCertificatePath);

        // Expect an IOException because the input file does not exist
        assertThrows(java.io.IOException.class, () -> verifyCommand.call(),
                "Command 'verify' should throw IOException for a non-existent input document.");
        outContent.reset();
    }

    /**
     * Tests running the application with invalid arguments for the 'gen' command.
     * This tests Picocli integration with the application.
     */
    @Test
    void testApplicationWithInvalidGenArguments() {
        System.out.println("--- Running test: Application with invalid 'gen' arguments ---");

        // Create a CommandLine instance for PnkdssApplication directly
        CommandLine commandLine = new CommandLine(new PnkdssApplication(picocliFactory), picocliFactory);

        // Missing required arguments for 'gen'
        String[] args = {"gen"}; 

        // Picocli.execute() typically returns a non-zero exit code for parsing errors
        // and prints errors to System.err, instead of throwing an exception from execute().
        int exitCode = commandLine.execute(args); 

        // Assert a non-zero exit code for the error
        assertNotEquals(0, exitCode, "Command 'gen' with missing arguments should return a non-zero exit code.");

        // Check System.err output for Picocli help message
        assertTrue(errContent.toString().contains("Missing required options"), "Error output should contain missing arguments information.");
        assertTrue(errContent.toString().contains("Usage: pnkdss gen"), "Error output should contain usage help for 'gen'.");
        errContent.reset();
    }
}