package com.cloudshield.service;

import org.springframework.beans.factory.annotation.Value;
import org.springframework.stereotype.Service;
import org.springframework.web.client.HttpClientErrorException;
import org.springframework.web.client.HttpServerErrorException;
import org.springframework.web.client.RestTemplate;
import org.springframework.http.*;

import java.util.List;
import java.util.Map;

@Service
public class AIPatchService {

    // Loaded from application.properties -> gemini.api.key
    // which itself reads from the GEMINI_API_KEY environment variable.
    // Never hardcode the key here.
    @Value("${gemini.api.key}")
    private String apiKey;

    private static final String URL =
            "https://generativelanguage.googleapis.com/v1beta/models/gemini-3.1-flash-lite:generateContent";

    public String generateFix(String ruleName, String vulnerableCode, String severity) {

        // Severity alone isn't the right signal here: LOW can mean "flagged as
        // likely test/placeholder data" (secrets) OR "genuinely low-risk but
        // real" (e.g. missing HEALTHCHECK). Only the explicit tag set by
        // SecretScannerService means "possible false positive."
        boolean likelyTestData = ruleName != null && ruleName.contains("[Likely test data]");

        String prompt;
        if (likelyTestData) {
            prompt =
                    "You are a cybersecurity expert reviewing a finding that an automated scanner has " +
                            "already flagged as LOW confidence / likely test or placeholder data (based on file path " +
                            "and low entropy of the value), not a confirmed real secret.\n\n" +
                            "Vulnerability: " + ruleName + "\n\n" +
                            "Matched code:\n" + vulnerableCode + "\n\n" +
                            "In 3-5 sentences: briefly confirm whether this looks like placeholder/test data, " +
                            "and give lightweight best-practice advice (e.g. still worth moving to env vars or a " +
                            "test fixtures helper for cleanliness). Do NOT tell the user to revoke or rotate a key, " +
                            "and do NOT recommend scrubbing git history \u2014 treat this as a minor hygiene note, not " +
                            "an incident.";
        } else {
            prompt =
                    "You are a cybersecurity expert.\n" +
                            "Vulnerability: " + ruleName + "\n\n" +
                            "Vulnerable code:\n" + vulnerableCode + "\n\n" +
                            "Severity: " + severity + " (this rating is already final and correct \u2014 it was " +
                            "assigned by the scanning tool based on the real-world risk of this specific check, " +
                            "not by you).\n\n" +
                            "Give a secure fix. Match the tone and depth of your advice to the severity \u2014 a LOW " +
                            "severity finding deserves a brief, practical fix, not an incident-response playbook. " +
                            "Only escalate language (e.g. \"revoke this credential\", \"treat as compromised\") for " +
                            "findings that are actually CRITICAL or HIGH severity secrets.\n\n" +
                            "Do not speculate about why the severity is what it is, and do not guess at context " +
                            "that isn't in the code shown above \u2014 e.g. do not claim this is \"test data\", " +
                            "\"placeholder\", \"development-stage\", or \"not production code\" unless the code " +
                            "snippet itself literally contains words like test/dummy/example/placeholder. If you " +
                            "don't have enough information to explain the severity, just don't mention it and " +
                            "focus on the fix.";
        }

        try {
            RestTemplate restTemplate = new RestTemplate();

            HttpHeaders headers = new HttpHeaders();
            headers.setContentType(MediaType.APPLICATION_JSON);
            headers.set("x-goog-api-key", apiKey);

            Map<String, Object> body = Map.of(
                    "contents", List.of(
                            Map.of(
                                    "parts", List.of(
                                            Map.of("text", prompt)
                                    )
                            )
                    )
            );

            HttpEntity<Map<String, Object>> request =
                    new HttpEntity<>(body, headers);

            Map<?, ?> response =
                    restTemplate.postForObject(URL, request, Map.class);

            System.out.println("GEMINI RESPONSE = " + response);

            List<?> candidates =
                    (List<?>) response.get("candidates");

            Map<?, ?> candidate =
                    (Map<?, ?>) candidates.get(0);

            Map<?, ?> content =
                    (Map<?, ?>) candidate.get("content");

            List<?> parts =
                    (List<?>) content.get("parts");

            Map<?, ?> part =
                    (Map<?, ?>) parts.get(0);

            return ((String) part.get("text")).trim();

        } catch (HttpClientErrorException | HttpServerErrorException e) {
            // This is the important part: e.getMessage() alone hides Google's
            // actual reason (invalid key, API not enabled, quota, etc).
            // getResponseBodyAsString() has the real error JSON.
            System.err.println("===== GEMINI HTTP ERROR =====");
            System.err.println("Status: " + e.getStatusCode());
            System.err.println("Body: " + e.getResponseBodyAsString());
            return "// AI unavailable (" + e.getStatusCode() + "): " + e.getResponseBodyAsString();

        } catch (Exception e) {
            System.err.println("===== GEMINI ERROR =====");
            System.err.println(e.getMessage());
            e.printStackTrace();
            return "// AI unavailable";
        }
    }
}