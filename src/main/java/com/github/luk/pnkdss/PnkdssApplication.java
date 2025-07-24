package com.github.luk.pnkdss;

import com.github.luk.pnkdss.commands.GenerateCommand;
import com.github.luk.pnkdss.commands.SignCommand;
import com.github.luk.pnkdss.commands.VerifyCommand;
import org.bouncycastle.jce.provider.BouncyCastleProvider;
import org.springframework.boot.CommandLineRunner;
import org.springframework.boot.SpringApplication;
import org.springframework.boot.autoconfigure.SpringBootApplication;
import picocli.CommandLine;
import picocli.CommandLine.Command;
import picocli.CommandLine.IFactory;

import java.security.Security;

@SpringBootApplication
@Command(name = "pnkdss",
        subcommands = {
                GenerateCommand.class,
                SignCommand.class,
                VerifyCommand.class
        },
        description = "A command-line tool for generating, signing, and verifying XML documents.")
public class PnkdssApplication implements CommandLineRunner {

    private final IFactory picocliFactory;

    public PnkdssApplication(IFactory picocliFactory) {
        this.picocliFactory = picocliFactory;
    }

    public static void main(String[] args) {
        int exitCode = SpringApplication.exit(SpringApplication.run(PnkdssApplication.class, args));
        System.exit(exitCode);
    }

    @Override
    public void run(String... args) {
        new CommandLine(this, picocliFactory).execute(args);
        
    }
}