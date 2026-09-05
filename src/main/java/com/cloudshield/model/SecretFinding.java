package com.cloudshield.model;

import jakarta.persistence.*;

@Entity // Tells Spring to make a database table out of this
public class SecretFinding {

    @Id
    @GeneratedValue(strategy = GenerationType.IDENTITY)
    private Long id; // Auto-incrementing primary key

    private String ruleName;
    private String filePath;
    private int lineNumber;

    @Column(length = 1000)
    private String matchSnippet;

    private String severity;

    // Which scanner produced this finding: "gitleaks", "semgrep", "trivy", or
    // "checkov". Set directly by SecretScannerService at scan time - the
    // frontend reads this instead of guessing from the rule name.
    private String tool;

    @Column(length = 5000) // AI patches can be long, give the DB column room
    private String aiSuggestedPatch;

    // No-argument constructor (Required by JPA/Hibernate)
    public SecretFinding() {
    }

    // Constructor
    public SecretFinding(
            String ruleName,
            String filePath,
            int lineNumber,
            String matchSnippet,
            String severity
    ) {
        this.ruleName = ruleName;
        this.filePath = filePath;
        this.lineNumber = lineNumber;
        this.matchSnippet = matchSnippet;
        this.severity = severity;
    }

    // --- Getters ---
    public Long getId() { return id; }
    public String getRuleName() { return ruleName; }
    public String getFilePath() { return filePath; }
    public int getLineNumber() { return lineNumber; }
    public String getMatchSnippet() { return matchSnippet; }
    public String getSeverity() { return severity; }
    public String getTool() { return tool; }
    public String getAiSuggestedPatch() { return aiSuggestedPatch; }

    // --- Setters ---
    public void setId(Long id) { this.id = id; }
    public void setRuleName(String ruleName) { this.ruleName = ruleName; }
    public void setFilePath(String filePath) { this.filePath = filePath; }
    public void setLineNumber(int lineNumber) { this.lineNumber = lineNumber; }
    public void setMatchSnippet(String matchSnippet) { this.matchSnippet = matchSnippet; }
    public void setSeverity(String severity) { this.severity = severity; }
    public void setTool(String tool) { this.tool = tool; }
    public void setAiSuggestedPatch(String aiSuggestedPatch) { this.aiSuggestedPatch = aiSuggestedPatch; }
}