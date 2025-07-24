package com.github.luk.pnkdss.commands;

import com.github.luk.pnkdss.utils.Generator;

import picocli.CommandLine.Command;
import picocli.CommandLine.Option;

import java.io.FileOutputStream;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.KeyStore;
import java.util.concurrent.Callable;

@Command(name = "gen", description = "Generates a sample XML document, a P12 keystore, and a password file.")
public class GenerateCommand implements Callable<Integer> {

    @Option(names = {"-d", "--document"}, description = "Path to the output XML document.", required = true)
    private Path documentPath;

    @Option(names = {"-k", "--keystore"}, description = "Path to the output P12 keystore.", required = true)
    private Path p12Path;

    @Option(names = {"-p", "--password"}, description = "Path to the output password file.", required = true)
    private Path passPath;

    @Override
    public Integer call() throws Exception {
        System.out.println("Generating files...");

        Files.write(documentPath, Generator.xmlContent.getBytes(StandardCharsets.UTF_8));
        System.out.println("Generated: " + documentPath);

        Files.write(passPath, Generator.DEFAULT_PASSWORD.getBytes(StandardCharsets.UTF_8));
        System.out.println("Generated: " + passPath);

        generateP12File(p12Path, Generator.DEFAULT_PASSWORD.toCharArray());
        System.out.println("Generated: " + p12Path);

        System.out.println("Generation completed.");
        return 0;
    }
    
    /**
     * Pomocná metoda pro generování P12 souboru na disk.
     * 
     * @param outputPath Cesta, kam se má P12 soubor uložit.
     * @param password   Heslo pro P12 soubor.
     * @throws Exception Pokud dojde k chybě při generování P12.
     */
    private static void generateP12File(Path outputPath, char[] password) throws Exception {
      KeyStore p12KeyStore = Generator.createP12KeyStore();
      try (FileOutputStream fos = new FileOutputStream(outputPath.toFile())) {
        p12KeyStore.store(fos, Generator.DEFAULT_PASSWORD.toCharArray());
      }
    }

    public Path getDocumentPath() {
      return documentPath;
    }

    public void setDocumentPath(Path documentPath) {
      this.documentPath = documentPath;
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