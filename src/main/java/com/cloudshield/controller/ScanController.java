package com.cloudshield.controller;

import com.cloudshield.model.ScanJob;
import com.cloudshield.model.SecretFinding;
import com.cloudshield.repository.FindingRepository;
import com.cloudshield.service.ScanOrchestratorService;
import com.cloudshield.service.ScanProgressService;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.http.HttpStatus;
import org.springframework.http.ResponseEntity;
import org.springframework.web.bind.annotation.*;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.util.Map;
import java.util.List;

@RestController
@CrossOrigin(origins = "*") // Allow React to talk to this controller
public class ScanController {

    @Autowired
    private ScanOrchestratorService scanOrchestratorService;

    @Autowired
    private ScanProgressService scanProgressService;

    @Autowired
    private FindingRepository findingRepository; // DB Repository

    // Kicks off the scan on a background thread and returns immediately with
    // a jobId, instead of blocking the request for the full scan duration.
    @PostMapping("/start")
    public ResponseEntity<?> startScan(@RequestBody Map<String, String> request) {
        String repoUrl = request.get("repoUrl");

        if (repoUrl == null || repoUrl.isEmpty()) {
            return ResponseEntity.badRequest().body(Map.of("error", "repoUrl is required"));
        }

        ScanJob job = scanProgressService.createJob();
        scanOrchestratorService.runScan(job.getId(), repoUrl);

        return ResponseEntity.status(HttpStatus.ACCEPTED).body(Map.of("jobId", job.getId()));
    }

    // Live progress stream for a running scan (Server-Sent Events).
    // Emits "progress" events as each stage runs, then a final "complete" or
    // "error" event. The frontend fetches the full result via GET /scan/{id}
    // once it receives "complete".
    @GetMapping("/scan/{jobId}/stream")
    public SseEmitter streamScan(@PathVariable String jobId) {
        return scanProgressService.subscribe(jobId);
    }

    // Snapshot of a job's current state - used as a fallback if SSE isn't
    // available, and to fetch the final findings once a scan completes.
    @GetMapping("/scan/{jobId}")
    public ResponseEntity<?> getScan(@PathVariable String jobId) {
        ScanJob job = scanProgressService.getJob(jobId);
        if (job == null) {
            return ResponseEntity.notFound().build();
        }

        Map<String, Object> body = new java.util.HashMap<>();
        body.put("jobId", job.getId());
        body.put("status", job.getStatus().name());
        body.put("currentStep", job.getCurrentStep());
        if (job.getFindings() != null) {
            body.put("findings", job.getFindings());
            body.put("findingsCount", job.getFindingsCount());
        }
        if (job.getErrorMessage() != null) {
            body.put("error", job.getErrorMessage());
        }
        return ResponseEntity.ok(body);
    }

    @GetMapping("/export/{id}")
    public ResponseEntity<?> exportFinding(@PathVariable Long id) {
        return findingRepository.findById(id)
                .map(finding -> ResponseEntity.ok()
                        .header(org.springframework.http.HttpHeaders.CONTENT_DISPOSITION, "attachment; filename=security-report-" + id + ".json")
                        .body(finding))
                .orElse(ResponseEntity.notFound().build());
    }

    // --- ENDPOINTS FOR REACT DASHBOARD ---

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