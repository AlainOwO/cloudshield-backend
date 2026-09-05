package com.cloudshield.service;

import com.cloudshield.model.ScanJob;
import com.cloudshield.model.SecretFinding;
import org.springframework.stereotype.Service;
import org.springframework.web.servlet.mvc.method.annotation.SseEmitter;

import java.io.IOException;
import java.util.List;
import java.util.Map;
import java.util.UUID;
import java.util.concurrent.ConcurrentHashMap;
import java.util.concurrent.CopyOnWriteArrayList;

@Service
public class ScanProgressService {

    private static final long EMITTER_TIMEOUT_MS = 5 * 60 * 1000; // 5 minutes

    private final Map<String, ScanJob> jobs = new ConcurrentHashMap<>();
    private final Map<String, CopyOnWriteArrayList<SseEmitter>> emitters = new ConcurrentHashMap<>();

    public ScanJob createJob() {
        String id = UUID.randomUUID().toString();
        ScanJob job = new ScanJob(id);
        jobs.put(id, job);
        return job;
    }

    public ScanJob getJob(String jobId) {
        return jobs.get(jobId);
    }

    public SseEmitter subscribe(String jobId) {
        SseEmitter emitter = new SseEmitter(EMITTER_TIMEOUT_MS);
        emitters.computeIfAbsent(jobId, k -> new CopyOnWriteArrayList<>()).add(emitter);

        Runnable cleanup = () -> {
            CopyOnWriteArrayList<SseEmitter> list = emitters.get(jobId);
            if (list != null) list.remove(emitter);
        };
        emitter.onCompletion(cleanup::run);
        emitter.onTimeout(cleanup::run);
        emitter.onError(e -> cleanup.run());

        // Handle the case where the job already finished before this client
        // subscribed (race between POST /start returning and the SSE connecting).
        ScanJob job = jobs.get(jobId);
        if (job != null) {
            if (job.getStatus() == ScanJob.Status.COMPLETE) {
                sendAndComplete(emitter, "complete", Map.of("status", "COMPLETE"));
            } else if (job.getStatus() == ScanJob.Status.ERROR) {
                sendAndComplete(emitter, "error", Map.of("message", job.getErrorMessage()));
            }
        }

        return emitter;
    }

    public void updateStep(String jobId, ScanJob.Status status, String stepDescription) {
        updateStep(jobId, status, stepDescription, null);
    }

    // toolId is one of "gitleaks"/"semgrep"/"trivy"/"checkov" while a specific
    // scanner is running, or null for steps that aren't tool-specific
    // (cloning, generating AI patches, saving). The frontend uses this to
    // highlight the exact tool in its scan visualization instead of guessing.
    public void updateStep(String jobId, ScanJob.Status status, String stepDescription, String toolId) {
        ScanJob job = jobs.get(jobId);
        if (job == null) return;
        job.setStatus(status);
        job.setCurrentStep(stepDescription);
        Map<String, Object> data = new java.util.HashMap<>();
        data.put("status", status.name());
        data.put("step", stepDescription);
        data.put("tool", toolId == null ? "" : toolId);
        broadcast(jobId, "progress", data);
    }

    public void complete(String jobId, List<SecretFinding> findings) {
        ScanJob job = jobs.get(jobId);
        if (job == null) return;
        job.setStatus(ScanJob.Status.COMPLETE);
        job.setFindings(findings);
        job.setCurrentStep("Done");
        broadcastAndComplete(jobId, "complete", Map.of("status", "COMPLETE", "findingsCount", findings.size()));
    }

    public void fail(String jobId, String message) {
        ScanJob job = jobs.get(jobId);
        if (job == null) return;
        job.setStatus(ScanJob.Status.ERROR);
        job.setErrorMessage(message);
        broadcastAndComplete(jobId, "error", Map.of("message", message));
    }

    private void broadcast(String jobId, String eventName, Object data) {
        CopyOnWriteArrayList<SseEmitter> list = emitters.get(jobId);
        if (list == null) return;
        for (SseEmitter emitter : list) {
            try {
                emitter.send(SseEmitter.event().name(eventName).data(data));
            } catch (IOException | IllegalStateException ignored) {
                // client disconnected, cleanup handlers will remove it
            }
        }
    }

    private void broadcastAndComplete(String jobId, String eventName, Object data) {
        CopyOnWriteArrayList<SseEmitter> list = emitters.get(jobId);
        if (list == null) return;
        for (SseEmitter emitter : list) {
            sendAndComplete(emitter, eventName, data);
        }
    }

    private void sendAndComplete(SseEmitter emitter, String eventName, Object data) {
        try {
            emitter.send(SseEmitter.event().name(eventName).data(data));
            emitter.complete();
        } catch (IOException | IllegalStateException ignored) {
            // already gone
        }
    }
}