package com.cloudshield.service;

import com.cloudshield.model.SecretFinding;
import org.springframework.boot.json.JsonParser;
import org.springframework.boot.json.JsonParserFactory;
import org.springframework.stereotype.Service;

import java.io.File;
import java.nio.file.Files;
import java.util.ArrayList;
import java.util.Base64;
import java.util.HashMap;
import java.util.List;
import java.util.Map;
import java.util.regex.Pattern;

@Service
public class SecretScannerService {

    // Use Spring's native parser to avoid any Jackson import errors
    private final JsonParser parser = JsonParserFactory.getJsonParser();

    // Below this Shannon entropy (bits/char), a decoded value reads more like
    // English/placeholder text than a random generated secret.
    private static final double ENTROPY_THRESHOLD = 4.2;

    // File paths matching this are overwhelmingly test fixtures/mocks, the
    // single biggest source of secret-scanner false positives.
    private static final Pattern TEST_PATH_PATTERN = Pattern.compile(
            "(?i)(_test\\.|/test/|/tests/|/fixtures?/|/mocks?/|/spec/|/samples?/|/examples?/)"
    );

    // Common placeholder words that show up in dummy credentials.
    private static final Pattern PLACEHOLDER_WORD_PATTERN = Pattern.compile(
            "(?i)\\b(test|dummy|sample|example|placeholder|fake|xxx+|changeme|change_me|your[_-]?api[_-]?key|some)\\b"
    );

    public List<SecretFinding> runGitleaks(String directoryPath) {
        List<SecretFinding> findings = new ArrayList<>();
        try {
            File outputFile = File.createTempFile("gitleaks-report-", ".json");
            ProcessBuilder pb = new ProcessBuilder(
                    "gitleaks", "detect", "--source", directoryPath,
                    "--report-path", outputFile.getAbsolutePath(), "--report-format", "json"
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            process.waitFor();

            if (outputFile.exists() && outputFile.length() > 0) {
                String jsonContent = new String(Files.readAllBytes(outputFile.toPath()));
                if (!jsonContent.trim().isEmpty() && !jsonContent.trim().equals("[]")) {
                    try {
                        List<Object> list = parser.parseList(jsonContent);
                        for (Object item : list) {
                            if (item instanceof Map) {
                                Map<?, ?> map = (Map<?, ?>) item;
                                SecretFinding finding = new SecretFinding();
                                finding.setRuleName("Secret: " + map.get("RuleID"));
                                finding.setFilePath(String.valueOf(map.get("File")));

                                Object startLine = map.get("StartLine");
                                finding.setLineNumber(startLine instanceof Number ? ((Number) startLine).intValue() : 1);

                                String match = String.valueOf(map.get("Match"));
                                finding.setMatchSnippet(match.length() > 200 ? match.substring(0, 200) + "..." : match);

                                applyConfidenceAdjustedSeverity(finding, match, finding.getFilePath());
                                findings.add(finding);
                            }
                        }
                    } catch(Exception ignored) {}
                }
            }
            outputFile.delete();
        } catch (Exception e) {
            System.err.println("Gitleaks failed: " + e.getMessage());
        }
        return findings;
    }

    /**
     * Sets severity to CRITICAL by default, but downgrades to LOW and tags the
     * rule name when the matched value looks like test/placeholder data rather
     * than a real secret. This does not hide the finding, just stops it from
     * crying wolf at CRITICAL severity.
     */
    private void applyConfidenceAdjustedSeverity(SecretFinding finding, String rawMatch, String filePath) {
        boolean testPath = filePath != null && TEST_PATH_PATTERN.matcher(filePath).find();
        boolean placeholderWord = PLACEHOLDER_WORD_PATTERN.matcher(rawMatch).find();
        boolean lowEntropyDecoded = isLowEntropyWhenDecoded(rawMatch);

        if (testPath || placeholderWord || lowEntropyDecoded) {
            finding.setSeverity("LOW");
            finding.setRuleName("[Likely test data] " + finding.getRuleName());
        } else {
            finding.setSeverity("CRITICAL");
        }
    }

    /**
     * Tries to base64-decode the matched value (secrets are frequently stored
     * base64-encoded, e.g. "key":"c29tZSBhdXRoIGtleQ=="). If it decodes to
     * plausible text, entropy is measured on the decoded string. If it doesn't
     * decode, entropy is measured on the raw match instead. Short, low-entropy
     * strings read like English words or placeholders rather than a randomly
     * generated key.
     */
    private boolean isLowEntropyWhenDecoded(String rawMatch) {
        String candidate = extractLikelyValue(rawMatch);
        if (candidate.isEmpty()) return false;

        String toScore = candidate;
        try {
            byte[] decoded = Base64.getDecoder().decode(candidate);
            String decodedText = new String(decoded);
            if (isPrintableAscii(decodedText)) {
                toScore = decodedText;
            }
        } catch (IllegalArgumentException notBase64) {
            // not base64, score the raw value as-is
        }

        double entropy = shannonEntropy(toScore);
        return entropy < ENTROPY_THRESHOLD;
    }

    // Pulls the value out of a "key":"value" style match if present, else
    // returns the trimmed raw match.
    private String extractLikelyValue(String rawMatch) {
        int colon = rawMatch.indexOf(':');
        String value = colon >= 0 ? rawMatch.substring(colon + 1) : rawMatch;
        return value.replaceAll("[\"'{}\\s]", "").trim();
    }

    private boolean isPrintableAscii(String s) {
        if (s.isEmpty()) return false;
        for (char c : s.toCharArray()) {
            if (c < 32 || c > 126) return false;
        }
        return true;
    }

    private double shannonEntropy(String s) {
        if (s == null || s.isEmpty()) return 0.0;
        Map<Character, Integer> freq = new HashMap<>();
        for (char c : s.toCharArray()) {
            freq.merge(c, 1, Integer::sum);
        }
        double entropy = 0.0;
        int length = s.length();
        for (int count : freq.values()) {
            double p = (double) count / length;
            entropy -= p * (Math.log(p) / Math.log(2));
        }
        return entropy;
    }

    public List<SecretFinding> runSemgrep(String directoryPath) {
        List<SecretFinding> findings = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("semgrep", "scan", "--config=auto", "--json", directoryPath);
            pb.redirectErrorStream(true);
            Process process = pb.start();
            String jsonContent = new String(process.getInputStream().readAllBytes());
            process.waitFor();

            if (!jsonContent.trim().isEmpty() && jsonContent.contains("{")) {
                try {
                    Map<String, Object> root = parser.parseMap(jsonContent);
                    Object resultsObj = root.get("results");
                    if (resultsObj instanceof List) {
                        for (Object item : (List<?>) resultsObj) {
                            if (item instanceof Map) {
                                Map<?, ?> map = (Map<?, ?>) item;
                                SecretFinding finding = new SecretFinding();
                                finding.setRuleName("SAST: " + map.get("check_id"));
                                finding.setFilePath(String.valueOf(map.get("path")));

                                Object start = map.get("start");
                                if (start instanceof Map) {
                                    Object line = ((Map<?, ?>) start).get("line");
                                    finding.setLineNumber(line instanceof Number ? ((Number) line).intValue() : 1);
                                }

                                Object extra = map.get("extra");
                                if (extra instanceof Map) {
                                    Map<?, ?> extraMap = (Map<?, ?>) extra;
                                    finding.setSeverity(String.valueOf(extraMap.get("severity")).toUpperCase());
                                    String lines = String.valueOf(extraMap.get("lines")).trim();
                                    finding.setMatchSnippet(lines.length() > 200 ? lines.substring(0, 200) + "..." : lines);
                                }
                                findings.add(finding);
                            }
                        }
                    }
                } catch(Exception ignored) {}
            }
        } catch (Exception e) {
            System.err.println("Semgrep failed: " + e.getMessage());
        }
        return findings;
    }

    public List<SecretFinding> runTrivy(String directoryPath) {
        List<SecretFinding> findings = new ArrayList<>();
        try {
            File outputFile = File.createTempFile("trivy-report-", ".json");
            ProcessBuilder pb = new ProcessBuilder(
                    "trivy", "fs", "--format", "json", "--output", outputFile.getAbsolutePath(), directoryPath
            );
            pb.redirectErrorStream(true);
            Process process = pb.start();
            process.waitFor();

            if (outputFile.exists() && outputFile.length() > 0) {
                String jsonContent = new String(Files.readAllBytes(outputFile.toPath()));
                if (!jsonContent.trim().isEmpty() && jsonContent.contains("{")) {
                    try {
                        Map<String, Object> root = parser.parseMap(jsonContent);
                        Object resultsObj = root.get("Results");
                        if (resultsObj instanceof List) {
                            for (Object resultItem : (List<?>) resultsObj) {
                                if (resultItem instanceof Map) {
                                    Map<?, ?> resultMap = (Map<?, ?>) resultItem;
                                    Object target = resultMap.get("Target");
                                    Object vulnsObj = resultMap.get("Vulnerabilities");
                                    if (vulnsObj instanceof List) {
                                        for (Object vulnItem : (List<?>) vulnsObj) {
                                            if (vulnItem instanceof Map) {
                                                Map<?, ?> vuln = (Map<?, ?>) vulnItem;
                                                SecretFinding finding = new SecretFinding();
                                                finding.setRuleName("SCA: " + vuln.get("VulnerabilityID"));
                                                finding.setFilePath(String.valueOf(target));
                                                finding.setLineNumber(1);
                                                finding.setSeverity(String.valueOf(vuln.get("Severity")).toUpperCase());

                                                String pkg = String.valueOf(vuln.get("PkgName"));
                                                String title = String.valueOf(vuln.get("Title"));
                                                finding.setMatchSnippet("Package: " + pkg + " | " + title);
                                                findings.add(finding);
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    } catch(Exception ignored) {}
                }
            }
            outputFile.delete();
        } catch (Exception e) {
            System.err.println("Trivy failed: " + e.getMessage());
        }
        return findings;
    }

    public List<SecretFinding> runCheckov(String directoryPath) {
        List<SecretFinding> findings = new ArrayList<>();
        try {
            ProcessBuilder pb = new ProcessBuilder("checkov", "-d", directoryPath, "-o", "json");
            pb.redirectErrorStream(true);
            Process process = pb.start();
            String jsonContent = new String(process.getInputStream().readAllBytes());
            process.waitFor();

            if (!jsonContent.trim().isEmpty() && jsonContent.contains("{")) {
                try {
                    // Checkov can sometimes return a list of reports or a single report, we'll try to parse it safely
                    if (jsonContent.trim().startsWith("[")) {
                        // If it's a list, we just grab the first element for simplicity in this implementation
                        List<Object> rootList = parser.parseList(jsonContent);
                        if (!rootList.isEmpty() && rootList.get(0) instanceof Map) {
                            parseCheckovMap((Map<String, Object>) rootList.get(0), findings);
                        }
                    } else {
                        Map<String, Object> root = parser.parseMap(jsonContent);
                        parseCheckovMap(root, findings);
                    }
                } catch(Exception ignored) {}
            }
        } catch (Exception e) {
            System.err.println("Checkov failed: " + e.getMessage());
        }
        return findings;
    }

    // Real per-check severity, based on actual security impact rather than a
    // blanket rating. Checkov's own "severity" field is only populated when
    // scanning with a Bridgecrew/Prisma Cloud API key (--bc-api-key), which
    // this setup doesn't use, so open-source runs return null and we fall
    // back to this. Ratings reflect what each check actually protects against:
    // HIGH = real exploitable risk (root user, disabled signature/cert checks),
    // MEDIUM = weakens security posture or patch hygiene but isn't directly
    // exploitable, LOW = build correctness / best-practice / cosmetic.
    private static final Map<String, String> CHECKOV_SEVERITY_MAP = new HashMap<>();
    static {
        // Dockerfile checks (CKV_DOCKER_*)
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_1", "MEDIUM");  // port 22 exposed
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_2", "LOW");     // missing HEALTHCHECK
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_3", "HIGH");    // no non-root user created
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_4", "MEDIUM");  // ADD used instead of COPY
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_5", "MEDIUM");  // update not paired with install (stale patches)
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_6", "LOW");     // deprecated MAINTAINER instruction
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_7", "MEDIUM");  // base image uses mutable "latest" tag
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_8", "HIGH");    // final USER is root
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_9", "LOW");     // apt vs apt-get usage
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_10", "LOW");    // WORKDIR not absolute
        CHECKOV_SEVERITY_MAP.put("CKV_DOCKER_11", "LOW");    // duplicate FROM alias in multistage build

        // Graph checks (CKV2_DOCKER_*) - mostly disabled cert/signature validation,
        // which is a real supply-chain / MITM risk in a build pipeline.
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_1", "MEDIUM");  // sudo used in RUN
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_2", "HIGH");    // curl cert validation disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_3", "HIGH");    // wget cert validation disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_4", "HIGH");    // pip --trusted-host
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_5", "HIGH");    // PYTHONHTTPSVERIFY disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_6", "HIGH");    // NODE_TLS_REJECT_UNAUTHORIZED disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_7", "HIGH");    // apk --allow-untrusted
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_8", "HIGH");    // apt-get --allow-unauthenticated
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_9", "HIGH");    // yum/dnf --nogpgcheck
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_10", "HIGH");   // rpm signature checks disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_11", "MEDIUM"); // apt-get --force-yes
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_12", "HIGH");   // npm strict-ssl disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_13", "HIGH");   // npm/yarn strict-ssl disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_14", "HIGH");   // GIT_SSL_NO_VERIFY
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_15", "HIGH");   // yum/dnf sslverify disabled
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_16", "HIGH");   // PIP_TRUSTED_HOST
        CHECKOV_SEVERITY_MAP.put("CKV2_DOCKER_17", "MEDIUM"); // chpasswd used
    }

    private void parseCheckovMap(Map<String, Object> root, List<SecretFinding> findings) {
        Object resultsObj = root.get("results");
        if (resultsObj instanceof Map) {
            Object failedChecksObj = ((Map<?, ?>) resultsObj).get("failed_checks");
            if (failedChecksObj instanceof List) {
                for (Object checkItem : (List<?>) failedChecksObj) {
                    if (checkItem instanceof Map) {
                        Map<?, ?> check = (Map<?, ?>) checkItem;
                        String checkId = String.valueOf(check.get("check_id"));

                        SecretFinding finding = new SecretFinding();
                        finding.setRuleName("IaC: " + checkId);
                        finding.setFilePath(String.valueOf(check.get("file_path")));

                        Object fileLineRange = check.get("file_line_range");
                        if (fileLineRange instanceof List && !((List<?>) fileLineRange).isEmpty()) {
                            Object firstLine = ((List<?>) fileLineRange).get(0);
                            finding.setLineNumber(firstLine instanceof Number ? ((Number) firstLine).intValue() : 1);
                        } else {
                            finding.setLineNumber(1);
                        }

                        finding.setSeverity(resolveCheckovSeverity(check, checkId));
                        finding.setMatchSnippet(extractCheckovSnippet(check));
                        findings.add(finding);
                    }
                }
            }
        }
    }

    // Checkov's "code_block" holds the actual matched Dockerfile/IaC lines as
    // [[lineNumber, "line text"], ...]. Using this instead of just the abstract
    // check_name gives the AI real code to reason about, rather than nothing
    // to go on (which previously caused it to invent unfounded explanations,
    // e.g. guessing a finding was "test/placeholder data" with no evidence).
    private String extractCheckovSnippet(Map<?, ?> check) {
        Object codeBlockObj = check.get("code_block");
        if (codeBlockObj instanceof List && !((List<?>) codeBlockObj).isEmpty()) {
            StringBuilder sb = new StringBuilder();
            for (Object lineEntry : (List<?>) codeBlockObj) {
                if (lineEntry instanceof List && ((List<?>) lineEntry).size() >= 2) {
                    Object lineText = ((List<?>) lineEntry).get(1);
                    if (sb.length() > 0) sb.append("\n");
                    sb.append(String.valueOf(lineText).stripTrailing());
                }
            }
            if (sb.length() > 0) {
                String snippet = sb.toString();
                return snippet.length() > 400 ? snippet.substring(0, 400) + "..." : snippet;
            }
        }
        // Fall back to the rule description only if no real code was available.
        return String.valueOf(check.get("check_name"));
    }

    // Prefers Checkov's own severity (only present with a Bridgecrew/Prisma
    // API key), then the curated map above, then a neutral MEDIUM default
    // rather than assuming every unmapped check is HIGH.
    private String resolveCheckovSeverity(Map<?, ?> check, String checkId) {
        Object rawSeverity = check.get("severity");
        if (rawSeverity != null && !"null".equalsIgnoreCase(String.valueOf(rawSeverity))) {
            return String.valueOf(rawSeverity).toUpperCase();
        }
        return CHECKOV_SEVERITY_MAP.getOrDefault(checkId, "MEDIUM");
    }
}