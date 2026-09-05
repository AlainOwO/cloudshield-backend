package com.cloudshield.service;

import com.cloudshield.model.ScanJob;
import com.cloudshield.model.SecretFinding;
import com.cloudshield.repository.FindingRepository;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.scheduling.annotation.Async;
import org.springframework.stereotype.Service;
import org.springframework.util.FileSystemUtils;

import java.nio.file.Path;
import java.util.ArrayList;
import java.util.List;

@Service
public class ScanOrchestratorService {

    @Autowired
    private GitCloneService gitCloneService;

    @Autowired
    private SecretScannerService secretScannerService;

    @Autowired
    private AIPatchService aiPatchService;

    @Autowired
    private FindingRepository findingRepository;

    @Autowired
    private ScanProgressService progressService;

    // Runs on a background thread (see AsyncConfig) so the controller can
    // return the jobId to the frontend immediately instead of blocking for
    // the full duration of the scan.
    @Async("taskExecutor")
    public void runScan(String jobId, String repoUrl) {
        String repoPath = null;
        try {
            progressService.updateStep(jobId, ScanJob.Status.CLONING, "Cloning repository");
            repoPath = gitCloneService.cloneRepository(repoUrl).toString();

            List<SecretFinding> findings = new ArrayList<>();

            progressService.updateStep(jobId, ScanJob.Status.SCANNING, "Scanning for hardcoded secrets", "gitleaks");
            findings.addAll(secretScannerService.runGitleaks(repoPath));

            progressService.updateStep(jobId, ScanJob.Status.SCANNING, "Running static analysis (SAST)", "semgrep");
            findings.addAll(secretScannerService.runSemgrep(repoPath));

            progressService.updateStep(jobId, ScanJob.Status.SCANNING, "Checking dependencies for known CVEs", "trivy");
            findings.addAll(secretScannerService.runTrivy(repoPath));

            progressService.updateStep(jobId, ScanJob.Status.SCANNING, "Checking infrastructure-as-code configuration", "checkov");
            findings.addAll(secretScannerService.runCheckov(repoPath));

            int total = findings.size();
            int i = 0;
            for (SecretFinding finding : findings) {
                i++;
                progressService.updateStep(jobId, ScanJob.Status.ENRICHING,
                        "Generating AI remediation patch (" + i + "/" + total + ")");
                String aiFix = aiPatchService.generateFix(
                        finding.getRuleName(), finding.getMatchSnippet(), finding.getSeverity());
                finding.setAiSuggestedPatch(aiFix);
            }

            progressService.updateStep(jobId, ScanJob.Status.SAVING, "Saving results");
            findingRepository.saveAll(findings);

            progressService.complete(jobId, findings);

        } catch (Exception e) {
            progressService.fail(jobId, "Failed to process scan: " + e.getMessage());
        } finally {
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
}