package com.github.luk.pnkdss.commands;

import com.github.luk.pnkdss.utils.Signer;
import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.InputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.concurrent.Callable;

@Command(name = "sign", description = "Signs an XML document using a P12 keystore.")
public class SignCommand implements Callable<Integer> {

    @Option(names = {"-d", "--document"}, description = "Path to the input XML document.", required = true)
    private Path inputDocumentPath;

    @Option(names = {"-s", "--signed"}, description = "Path to the output signed XML document.", required = true)
    private Path outputDocumentPath;

    @Option(names = {"-k", "--keystore"}, description = "Path to the P12 keystore.", required = true)
    private Path p12Path;

    @Option(names = {"-p", "--password"}, description = "Path to the password file for the keystore.", required = true)
    private Path passPath;

    @Override
    public Integer call() throws Exception {
        System.out.println("Signing document '" + inputDocumentPath + "' and saving to '" + outputDocumentPath + "'...");

        char[] password = new String(Files.readAllBytes(passPath), StandardCharsets.UTF_8).trim().toCharArray();

        try (InputStream documentIs = Files.newInputStream(inputDocumentPath);
             InputStream p12Is = Files.newInputStream(p12Path)) {

            String signedXml = Signer.sign(documentIs, p12Is, password);

            Files.write(outputDocumentPath, signedXml.getBytes(StandardCharsets.UTF_8));
            System.out.println("Document signed and saved to: " + outputDocumentPath);
        }
        return 0;
    }

    public Path getInputDocumentPath() {
      return inputDocumentPath;
    }

    public void setInputDocumentPath(Path inputDocumentPath) {
      this.inputDocumentPath = inputDocumentPath;
    }

    public Path getOutputDocumentPath() {
      return outputDocumentPath;
    }

    public void setOutputDocumentPath(Path outputDocumentPath) {
      this.outputDocumentPath = outputDocumentPath;
    }

    public Path getP12Path() {
      return p12Path;
    }

    public void setP12Path(Path p12Path) {
      this.p12Path = p12Path;
    }

    public Path getPassPath() {
      return passPath;
    }

    public void setPassPath(Path passPath) {
      this.passPath = passPath;
    }
}