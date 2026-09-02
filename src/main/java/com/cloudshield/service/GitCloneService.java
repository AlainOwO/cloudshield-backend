package com.cloudshield.service;

import org.eclipse.jgit.api.Git;
import org.springframework.stereotype.Service;
import java.nio.file.Files;
import java.nio.file.Path;
import java.util.UUID;

@Service
public class GitCloneService {

    public Path cloneRepository(String repoUrl) throws Exception {
        // Generates a unique folder in Mac's secure temp directory
        Path tempDir = Files.createTempDirectory("cloudshield-scans-" + UUID.randomUUID().toString());

        System.out.println("Cloning " + repoUrl + " to " + tempDir.toString());

        // Clones the repo programmatically without using shell commands (avoids Command Injection risks)
        try (Git git = Git.cloneRepository()
                .setURI(repoUrl)
                .setDirectory(tempDir.toFile())
                .call()) {
            System.out.println("Clone completed securely.");
        }

        return tempDir;
    }
}