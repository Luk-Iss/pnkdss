package com.github.luk.pnkdss.commands;

import com.github.luk.pnkdss.utils.SignatureResult;
import com.github.luk.pnkdss.utils.Validator;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "verify", description = "Verifies a signed XML document and extracts the signing certificate.")
public class VerifyCommand implements Callable<Integer> {

    @Option(names = {"-s", "--signed"}, description = "Path to the signed XML document.", required = true)
    private Path documentPath;

    @Option(names = {"-c", "--certificate"}, description = "Path to the output certificate file (PEM format).", required = true)
    private Path certOutputPath;

    @Override
    public Integer call() throws Exception {
        System.out.println("Verifying document: " + documentPath);

        try (InputStream documentIs = Files.newInputStream(documentPath)) {
            SignatureResult sr = Validator.check(documentIs);

            System.out.println("\n--- Signature Verification Result ---");
            if (sr.isResultOK()) {
                System.out.println("Signature is mathematically valid.");
                if (sr.getPem() != null) {
                    Files.write(certOutputPath, sr.getPem().getBytes(StandardCharsets.UTF_8));
                    System.out.println("Signing certificate saved to: " + certOutputPath);
                } else {
                    System.err.println("Error: Signature is valid, but the certificate in PEM format was not found in SignatureResult.");
                }
            } else {
                System.out.println("Signature IS NOT mathematically valid!");
            }
        }
        return 0;
    }

    public Path getDocumentPath() {
      return documentPath;
    }

    public void setDocumentPath(Path documentPath) {
      this.documentPath = documentPath;
    }

    public Path getCertOutputPath() {
      return certOutputPath;
    }

    public void setCertOutputPath(Path certOutputPath) {
      this.certOutputPath = certOutputPath;
    }
}