package com.cloudshield.controller;

import com.cloudshield.model.SecretFinding;
import com.cloudshield.repository.FindingRepository;
import com.cloudshield.service.AIPatchService;
import com.cloudshield.service.GitCloneService;
import com.cloudshield.service.SecretScannerService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.ResponseEntity;
import org.springframework.util.FileSystemUtils;
import org.springframework.web.bind.annotation.*;

import java.nio.file.Path;
import java.util.Map;
import java.util.List;

@RestController
@CrossOrigin(origins = "*") // Allow React to talk to this controller
public class ScanController {

    @Autowired
    private GitCloneService gitCloneService;

    @Autowired
    private SecretScannerService secretScannerService;

    @Autowired
    private AIPatchService aiPatchService;

    @Autowired
    private FindingRepository findingRepository; // DB Repository

    @PostMapping("/start")
    public ResponseEntity<?> startScan(@RequestBody Map<String, String> request) {
        String repoUrl = request.get("repoUrl");

        if (repoUrl == null || repoUrl.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "repoUrl is required"));
        }

        String repoPath = null;
        try {
            // 1. Clone the repository
            repoPath = gitCloneService.cloneRepository(repoUrl).toString();

            // 2. Run all four security scanners (CNAPP)
            List<SecretFinding> findings = new java.util.ArrayList<>(secretScannerService.runGitleaks(repoPath));
            findings.addAll(secretScannerService.runSemgrep(repoPath));
            findings.addAll(secretScannerService.runTrivy(repoPath));
            findings.addAll(secretScannerService.runCheckov(repoPath));

            // 3. AI Enrichment Loop
            for (SecretFinding finding : findings) {
                // Severity is passed through so low-confidence "test data" findings
                // get calibrated advice instead of a full incident-response essay.
                String aiFix = aiPatchService.generateFix(finding.getRuleName(), finding.getMatchSnippet(), finding.getSeverity());
                finding.setAiSuggestedPatch(aiFix);
            }

            // 4. Save everything to the database!
            findingRepository.saveAll(findings);

            // 5. Return the results
            return ResponseEntity.ok(Map.of(
                    "status", "success",
                    "message", "Scan completed and AI patches saved to database",
                    "findingsCount", findings.size(),
                    "findings", findings
            ));
        } catch (Exception e) {
            return ResponseEntity.internalServerError().body(Map.of(
                    "status", "error",
                    "message", "Failed to process scan: " + e.getMessage()
            ));
        } finally {
            // 6. Cleanup temporary files
            if (repoPath != null) {
                try {
                    FileSystemUtils.deleteRecursively(Path.of(repoPath));
                    System.out.println("Securely deleted temporary folder: " + repoPath);
                } catch (Exception e) {
                    System.err.println("Warning - failed to delete folder: " + repoPath);
                }
            }
        }
    }

    @GetMapping("/export/{id}")
    public ResponseEntity<?> exportFinding(@PathVariable Long id) {
        return findingRepository.findById(id)
                .map(finding -> ResponseEntity.ok()
                        .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=security-report-" + id + ".json")
                        .body(finding))
                .orElse(ResponseEntity.notFound().build());
    }

    // --- NEW ENDPOINTS FOR REACT DASHBOARD ---

    @GetMapping("/history")
    public ResponseEntity<?> getScanHistory() {
        List<SecretFinding> history = findingRepository.findAll();
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "count", history.size(),
                "findings", history
        ));
    }

    @DeleteMapping("/history/clear")
    public ResponseEntity<?> clearHistory() {
        findingRepository.deleteAll();
        return ResponseEntity.ok(Map.of(
                "status", "success",
                "message", "All scan history cleared"
        ));
    }
}