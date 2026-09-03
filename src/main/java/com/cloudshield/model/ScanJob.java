package com.cloudshield.model;

import java.util.List;

public class ScanJob {

    public enum Status { PENDING, CLONING, SCANNING, ENRICHING, SAVING, COMPLETE, ERROR }

    private final String id;
    private volatile Status status = Status.PENDING;
    private volatile String currentStep = "Queued";
    private volatile List<SecretFinding> findings;
    private volatile Integer findingsCount;
    private volatile String errorMessage;

    public ScanJob(String id) {
        this.id = id;
    }

    public String getId() { return id; }
    public Status getStatus() { return status; }
    public void setStatus(Status status) { this.status = status; }
    public String getCurrentStep() { return currentStep; }
    public void setCurrentStep(String currentStep) { this.currentStep = currentStep; }
    public List<SecretFinding> getFindings() { return findings; }
    public void setFindings(List<SecretFinding> findings) {
        this.findings = findings;
        this.findingsCount = findings != null ? findings.size() : null;
    }
    public Integer getFindingsCount() { return findingsCount; }
    public String getErrorMessage() { return errorMessage; }
    public void setErrorMessage(String errorMessage) { this.errorMessage = errorMessage; }
}