package com.richeeta.burp.ZeroXGUIDScanner;

import java.awt.Dimension;
import java.awt.FlowLayout;
import java.awt.GridLayout;
import java.awt.event.ItemEvent;
import java.io.IOException;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.security.MessageDigest;
import java.time.Instant;
import java.time.LocalDateTime;
import java.time.ZoneId;
import java.util.ArrayList;
import java.util.Arrays;
import java.util.Base64;
import java.util.Collections;
import java.util.Date;
import java.util.HashMap;
import java.util.HashSet;
import java.util.List;
import java.util.Map;
import java.util.Set;
import java.util.concurrent.ConcurrentHashMap;
import java.util.regex.Matcher;
import java.util.regex.Pattern;

import javax.swing.BorderFactory;
import javax.swing.BoxLayout;
import javax.swing.JButton;
import javax.swing.JCheckBox;
import javax.swing.JComboBox;
import javax.swing.JLabel;
import javax.swing.JOptionPane;
import javax.swing.JPanel;
import javax.swing.JScrollPane;
import javax.swing.JTextArea;
import javax.swing.JTextField;
import javax.swing.border.TitledBorder;

import burp.api.montoya.BurpExtension;
import burp.api.montoya.MontoyaApi;
import burp.api.montoya.core.ByteArray;
import burp.api.montoya.core.Marker;
import burp.api.montoya.core.Registration;
import burp.api.montoya.http.message.HttpRequestResponse;
import burp.api.montoya.scanner.AuditResult;
import burp.api.montoya.scanner.ConsolidationAction;
import burp.api.montoya.scanner.ScanCheck;
import burp.api.montoya.scanner.audit.insertionpoint.AuditInsertionPoint;
import burp.api.montoya.scanner.audit.issues.AuditIssue;
import burp.api.montoya.scanner.audit.issues.AuditIssueConfidence;
import burp.api.montoya.scanner.audit.issues.AuditIssueSeverity;
import burp.api.montoya.ui.UserInterface;

public class ZeroXGUIDScanner implements BurpExtension, ScanCheck
{
    private MontoyaApi api;
    private Registration scanCheckRegistration;
    private JPanel settingsPanel;

    // In-memory config
    private ExtensionConfig config;

    // Global set of discovered tokens (lowercased) to avoid duplicate issues
    private final Set<String> discoveredTokens = ConcurrentHashMap.newKeySet();

    // Track v1 tokens for sequential/time-based checks
    private final List<DiscoveredToken> v1History = Collections.synchronizedList(new ArrayList<>());
    // Track v4 tokens for repeat detection
    private final List<DiscoveredToken> v4History = Collections.synchronizedList(new ArrayList<>());

    // Minimal MAC prefix vendor map (expand as desired)
    private static final Map<String, String> VENDOR_MAP = new HashMap<>();
    static {
        VENDOR_MAP.put("001a2b", "Cisco Systems");
        VENDOR_MAP.put("d4ee07", "Apple Inc");
        VENDOR_MAP.put("00163e", "Hewlett Packard");
        VENDOR_MAP.put("080027", "Oracle (VirtualBox)");
        VENDOR_MAP.put("f4b7e2", "Microsoft");
        VENDOR_MAP.put("001a70", "Dell Inc");
    }

    // For advanced name+namespace reversal in v3/v5
    private static final List<String> EXTENDED_NAMESPACES = Arrays.asList(
        "6ba7b810-9dad-11d1-80b4-00c04fd430c8", // DNS
        "6ba7b811-9dad-11d1-80b4-00c04fd430c8", // URL
        "6ba7b812-9dad-11d1-80b4-00c04fd430c8", // ISO OIDs
        "6ba7b814-9dad-11d1-80b4-00c04fd430c8"  // X.500
    );
    private static final Pattern WORD_PATTERN = Pattern.compile("\\b([\\w.-]{3,})\\b");
    private static final int MAX_NAME_CANDIDATES = 5;

    // Patterns for direct detection
    private static final Pattern GUID_PATTERN = Pattern.compile(
        "\\b([a-fA-F0-9]{8}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{4}-[a-fA-F0-9]{12})\\b|\\b([a-fA-F0-9]{32})\\b");
    private static final Pattern BASE64_PATTERN = Pattern.compile("\\b[A-Za-z0-9+/]{22,}={0,2}\\b");

    // UUID v1 epoch offset (1582..1970) in 100ns intervals
    private static final long EPOCH_1582_TO_1970_100NS = 0x01B21DD213814000L;

    @Override
    public void initialize(MontoyaApi api)
    {
        this.api = api;
        this.config = loadSettingsFromDisk();

        api.extension().setName("0xGUID Scanner");
        scanCheckRegistration = api.scanner().registerScanCheck(this);

        buildSettingsTab(api.userInterface());
        api.logging().logToOutput("0xGUID Scanner loaded successfully (with advanced checks).");
    }

    @Override
    public AuditResult passiveAudit(HttpRequestResponse baseRequestResponse)
    {
        try {
            if (!config.enabled) {
                api.logging().logToOutput("Scanning disabled in settings.");
                return AuditResult.auditResult(Collections.emptyList());
            }

            String host = baseRequestResponse.request().httpService().host();
            api.logging().logToOutput("Scanning host: " + host);

            if (isIgnoredHost(host)) {
                api.logging().logToOutput("Host ignored: " + host);
                return AuditResult.auditResult(Collections.emptyList());
            }

            String requestUrl = baseRequestResponse.request().url();
            api.logging().logToOutput("Request URL: " + requestUrl);

            if (config.ignoreStaticJS && isLikelyStaticJS(requestUrl)) {
                api.logging().logToOutput("Static JS file ignored: " + requestUrl);
                return AuditResult.auditResult(Collections.emptyList());
            }

            // Combine request+response for detection
            String combined = combineText(baseRequestResponse);
            api.logging().logToOutput("Combined Request/Response length: " + combined.length());

            // 1) direct detection
            Set<String> foundTokens = detectGuidsInText(combined);

            // 2) decode base64
            if (config.decodeBase64) {
                Set<String> b64Tokens = decodeBase64AndScan(combined);
                foundTokens.addAll(b64Tokens);
            }

            // 3) decode URL-encoded
            if (config.decodeURLEncoded) {
                Set<String> urlTokens = decodeUrlEncodedAndScan(combined);
                foundTokens.addAll(urlTokens);
            }

            List<AuditIssue> issues = new ArrayList<>();
            for (String token : foundTokens) {
                String norm = token.toLowerCase();
                if (discoveredTokens.contains(norm)) {
                    // Skip duplicates
                    continue;
                }

                discoveredTokens.add(norm);
                Classification classification = classifyGuid(token, combined);

                // Could be null if invalid or if we decided it's not relevant
                if (classification == null) {
                    continue;
                }

                // If it's "fake" but user disabled fake detection, skip
                if ("fake".equals(classification.version) && !config.detectFake) {
                    continue;
                }

                // If user didn't enable that version (1..5)
                if (!classification.version.equals("fake")
                    && !config.enabledVersions.contains(classification.version)) {
                    continue;
                }

                // Compare severity/confidence to user thresholds
                if (severityRank(classification.severity) < severityRank(config.minSeverityToReport)) {
                    continue;
                }
                if (confidenceRank(classification.confidence) < confidenceRank(config.minConfidenceToReport)) {
                    continue;
                }

                // Build the final HTML detail for the issue
                String detailHtml = buildIssueDetail(token, classification, combined, baseRequestResponse);

                // Markers for highlighting
                List<Marker> reqMarkers = new ArrayList<>();
                List<Marker> respMarkers = new ArrayList<>();
                highlightTokenOccurrences(token, baseRequestResponse, reqMarkers, respMarkers);

                HttpRequestResponse marked = baseRequestResponse
                    .withRequestMarkers(reqMarkers)
                    .withResponseMarkers(respMarkers);

                boolean isInsecure = classification.securityImpact != null && classification.securityImpact.contains("CRITICAL");
                String issueName = isInsecure
                    ? String.format("Insecure GUID/UUID v%s Found: %s", classification.version, token)
                    : String.format("GUID/UUID v%s Found: %s", classification.version, token);

                AuditIssue issue = AuditIssue.auditIssue(
                    issueName,
                    detailHtml,
                    classification.remediation,
                    baseRequestResponse.request().url(),
                    classification.severity,
                    classification.confidence,
                    "GUID/UUID Security Issue",
                    "Upgrade to secure approach if guessable or MAC-based.",
                    classification.severity,
                    Collections.singletonList(marked)
                );
                issues.add(issue);
            }

            api.logging().logToOutput("Created " + issues.size() + " issue(s).");
            return AuditResult.auditResult(issues);

        } catch (Exception e) {
            api.logging().logToError("Error in passiveAudit: " + e.getMessage());
            e.printStackTrace();
            return AuditResult.auditResult(Collections.emptyList());
        }
    }

    @Override
    public AuditResult activeAudit(HttpRequestResponse baseRequestResponse, AuditInsertionPoint insertionPoint)
    {
        // We are only doing passive checks
        return AuditResult.auditResult(Collections.emptyList());
    }

    @Override
    public ConsolidationAction consolidateIssues(AuditIssue newIssue, AuditIssue existingIssue)
    {
        if (newIssue.name().equals(existingIssue.name())
            && newIssue.detail().equals(existingIssue.detail())
            && newIssue.severity().equals(existingIssue.severity())) {
            return ConsolidationAction.KEEP_EXISTING;
        }
        return ConsolidationAction.KEEP_BOTH;
    }

    // ---------------------------
    // The classification logic (merged from older advanced version)
    // ---------------------------
    private Classification classifyGuid(String token, String context)
    {
        String rawHex = token.replace("-", "").toLowerCase();
        if (rawHex.length() != 32) {
            return null;
        }

        Classification c = new Classification();
        c.token = token;
        c.rawHex = rawHex;
        c.confidence = AuditIssueConfidence.FIRM;
        c.severity = AuditIssueSeverity.INFORMATION;
        c.discoveryTime = new Date();

        // Check variant nibble
        int variantNibble = hexToInt(rawHex.substring(16, 17));
        boolean isRfcVariant = ((variantNibble & 0x8) == 0x8);

        // Version nibble
        int verNibble = hexToInt(rawHex.substring(12, 13));
        if (!isRfcVariant) {
            c.version = "fake";
            c.severity = AuditIssueSeverity.HIGH;
            c.notesValidationFail = "Variant bits are not RFC4122-compliant.";
            return c;
        }

        switch (verNibble) {
            case 1:
                parseV1(c);
                break;
            case 2:
                parseV2(c);
                break;
            case 3:
                parseV3(c, context);
                break;
            case 4:
                parseV4(c);
                break;
            case 5:
                parseV5(c, context);
                break;
            default:
                c.version = "fake";
                c.severity = AuditIssueSeverity.HIGH;
                c.notesValidationFail = "Unknown version nibble => not standard.";
                return c;
        }
        return c;
    }

    private void parseV1(Classification c)
    {
        c.version = "1";
        c.sectionMac = new StringBuilder();
        c.sectionTimestamp = new StringBuilder();
        c.sectionClockSeq = new StringBuilder();
        c.sectionSecurityImpact = new StringBuilder();

        byte[] raw = parseHex(c.rawHex);
        if (raw == null || raw.length < 16) {
            c.notesValidationFail = "Unable to parse raw bits for v1 analysis.";
            c.version = "fake";
            return;
        }

        long timeLow = getUnsignedInt(raw, 0);
        long timeMid = getUnsignedShort(raw, 4);
        long timeHi = (getUnsignedShort(raw, 6) & 0x0FFF);
        long timestamp100ns = (timeLow) | (timeMid << 32) | (timeHi << 48);

        // Convert to epoch-based
        long nsSince1970 = timestamp100ns - EPOCH_1582_TO_1970_100NS;
        if (nsSince1970 < 0) {
            c.sectionTimestamp.append("Time is before 1970 => suspicious.\n");
            c.severity = escalate(c.severity, AuditIssueSeverity.HIGH);
        }
        long msSince1970 = nsSince1970 / 10000L;
        Instant inst = Instant.ofEpochMilli(msSince1970);
        c.sectionTimestamp.append("Raw timestamp (100ns since 1582): ").append(timestamp100ns).append("\n");
        c.sectionTimestamp.append("Approx. UTC Time: ").append(inst.toString()).append("\n");

        byte[] node = Arrays.copyOfRange(raw, 10, 16);
        String nodeHex = toHex(node);
        c.sectionMac.append("Node ID (hex): ").append(nodeHex).append("\n");
        String macColon = macColonFormat(node);
        c.sectionMac.append("MAC format: ").append(macColon).append("\n");
        boolean multicast = (node[0] & 0x01) != 0;
        boolean localAdmin = (node[0] & 0x02) != 0;
        if (multicast) {
            c.sectionMac.append("MAC is multicast => not globally unique.\n");
        }
        if (localAdmin) {
            c.sectionMac.append("MAC is locally administered => not from vendor.\n");
        }
        String vendorPrefix = nodeHex.substring(0, 6);
        if (VENDOR_MAP.containsKey(vendorPrefix)) {
            c.sectionMac.append("Likely vendor => ").append(VENDOR_MAP.get(vendorPrefix)).append("\n");
        }

        int clockHi = raw[8] & 0x3F;
        int clockLo = raw[9] & 0xFF;
        int clockSeq = (clockHi << 8) | clockLo;
        c.sectionClockSeq.append("Clock sequence => ").append(clockSeq).append("\n");

        // Compare to previous v1 to see how close
        synchronized (v1History) {
            if (!v1History.isEmpty()) {
                DiscoveredToken prev = v1History.get(v1History.size() - 1);
                if ("1".equals(prev.classification.version)) {
                    long oldTs = prev.classification.v1Timestamp100ns;
                    long diff = Math.abs(timestamp100ns - oldTs);
                    c.sectionTimestamp.append("Time delta from previous v1 => " + diff + " (100ns intervals)\n");
                    if (diff < 10000) {
                        c.sectionSecurityImpact.append("Sequential v1 timestamps => potential predictability.\n");
                        c.severity = escalate(c.severity, AuditIssueSeverity.HIGH);
                    }
                }
            }
        }

        c.v1Timestamp100ns = timestamp100ns;
        v1History.add(new DiscoveredToken(c.token, c, System.currentTimeMillis()));

        if (localAdmin || multicast) {
            c.sectionSecurityImpact.append("MAC not globally unique => guessable node bits.\n");
            c.severity = escalate(c.severity, AuditIssueSeverity.HIGH);
        }
        c.remediation = "Use cryptographically secure approach (v4 or ephemeral). Avoid exposing real MAC/time.";
    }

    private void parseV2(Classification c)
    {
        c.version = "2";
        c.sectionDomain = new StringBuilder();
        c.sectionSecurityImpact = new StringBuilder();
        c.sectionClockSeq = new StringBuilder();
        c.sectionNodeId = new StringBuilder();

        c.sectionDomain.append("Local DCE domain (possibly user/group bits).\n");
        c.sectionClockSeq.append("Derived from v1 clock sequence.\n");
        c.sectionNodeId.append("Might overlap domain fields.\n");
        c.sectionSecurityImpact.append("v2 can leak domain/user info => MEDIUM risk.\n");
        c.remediation = "Consider random-based or removing domain bits from v2 usage.";
        c.severity = AuditIssueSeverity.MEDIUM;
    }

    private void parseV3(Classification c, String context)
    {
        c.version = "3";
        c.sectionHashDetails = new StringBuilder();
        c.sectionHashDetails.append("Hash algorithm => MD5.\n");
        c.remediation = "Use v4 or v5 with a cryptographic hash. Avoid guessable names.";

        // Attempt name+namespace reversal
        attemptNamespaceReverseEngineering(c, context, "MD5");

        // If reversal was successful => severity might escalate
        if (c.securityImpact != null && c.securityImpact.contains("CRITICAL")) {
            c.severity = escalate(c.severity, AuditIssueSeverity.HIGH);
            c.confidence = AuditIssueConfidence.CERTAIN;
        } else {
            c.severity = AuditIssueSeverity.LOW;
        }
    }

    private void parseV4(Classification c)
    {
        c.version = "4";
        c.sectionRandomAnalysis = new StringBuilder();
        c.sectionRandomAnalysis.append("Random-based => Checking for repeated patterns.\n");

        synchronized (v4History) {
            for (DiscoveredToken dt : v4History) {
                if (dt.token.equalsIgnoreCase(c.token)) {
                    c.sectionRandomAnalysis.append("**Repeated exact same v4** => suspicious RNG!\n");
                    c.severity = escalate(c.severity, AuditIssueSeverity.HIGH);
                    break;
                }
            }
            v4History.add(new DiscoveredToken(c.token, c, System.currentTimeMillis()));
        }

        c.remediation = "Ensure cryptographic RNG for v4. Avoid repeated patterns.";
        // Default to INFORMATION, but if repeated => escalated above
    }

    private void parseV5(Classification c, String context)
    {
        c.version = "5";
        c.sectionHashDetails = new StringBuilder();
        c.sectionHashDetails.append("Hash algorithm => SHA1.\n");
        c.remediation = "Use random-based approach or carefully protect name+namespace.";

        // Attempt name+namespace reversal
        attemptNamespaceReverseEngineering(c, context, "SHA-1");

        // If reversal worked => escalate
        if (c.securityImpact != null && c.securityImpact.contains("CRITICAL")) {
            c.severity = escalate(c.severity, AuditIssueSeverity.HIGH);
            c.confidence = AuditIssueConfidence.CERTAIN;
        } else {
            c.severity = AuditIssueSeverity.LOW;
        }
    }

    private void attemptNamespaceReverseEngineering(Classification c, String context, String algo)
    {
        // Find word-like candidates in context
        Set<String> candidates = new HashSet<>();
        Matcher mm = WORD_PATTERN.matcher(context);
        while (mm.find() && candidates.size() < MAX_NAME_CANDIDATES) {
            candidates.add(mm.group(1));
        }

        c.sectionHashDetails.append("Attempting name+namespace collisions. Collected up to " + candidates.size() + " candidate word(s).\n");

        // For each known namespace
        for (String ns : EXTENDED_NAMESPACES) {
            String nsHex = ns.replace("-", "");
            byte[] nsRaw = parseHex(nsHex);
            if (nsRaw == null || nsRaw.length != 16) {
                continue;
            }
            // For each candidate name
            for (String candidate : candidates) {
                if (checkNameNamespaceCollision(c, nsRaw, ns,candidate, algo)) {
                    // If we successfully reversed it, break early
                    return;
                }
            }
        }
    }

    private boolean checkNameNamespaceCollision(Classification c, byte[] nsRaw, String ns,String candidate, String algo)
    {
        try {
            byte[] candidateRaw = candidate.getBytes(StandardCharsets.UTF_8);
            byte[] combined = new byte[nsRaw.length + candidateRaw.length];
            System.arraycopy(nsRaw, 0, combined, 0, nsRaw.length);
            System.arraycopy(candidateRaw, 0, combined, nsRaw.length, candidateRaw.length);

            MessageDigest md = MessageDigest.getInstance(algo);
            byte[] digest = md.digest(combined);
            byte[] truncated = Arrays.copyOf(digest, 16);
            String truncatedHex = toHex(truncated);

            // Compare to actual
            if (truncatedHex.equalsIgnoreCase(c.rawHex)) {
                c.sectionHashDetails.append("**Reversed v" + c.version + " => name: " + candidate + ", namespace: " + ns + "**\n");
                c.sectionHashDetails.append("**Full collision => guessable**\n");
                c.securityImpact = "CRITICAL: reversed v" + c.version + " => name+namespace guessable.";
                return true;
            }
        } catch (Exception e) {
            // ignore
        }
        return false;
    }

    // ---------------------------
    // Building the final detail HTML
    // ---------------------------
    private String buildIssueDetail(String token, Classification c, String context, HttpRequestResponse rr)
    {
        // We'll produce a more verbose HTML detail, merging your existing approach
        // with the advanced classification data from above.
        StringBuilder sb = new StringBuilder();

        sb.append("<b>GUID/UUID: </b>").append(token).append("<br/>");
        sb.append("<b>Version: </b>").append(c.version).append("<br/>");
        sb.append("<b>Raw Hex: </b><code>").append(c.rawHex).append("</code><br/>");

        if (c.notesValidationFail != null) {
            sb.append("<b>Validation Failure: </b>").append(c.notesValidationFail).append("<br/>");
        }

        // v1 details
        if ("1".equals(c.version)) {
            if (c.sectionTimestamp != null) {
                sb.append("<hr><b>Timestamp Analysis (v1)</b><br/><pre>")
                  .append(c.sectionTimestamp)
                  .append("</pre>");
            }
            if (c.sectionMac != null) {
                sb.append("<hr><b>MAC / Node Analysis (v1)</b><br/><pre>")
                  .append(c.sectionMac)
                  .append("</pre>");
            }
            if (c.sectionClockSeq != null) {
                sb.append("<hr><b>Clock Sequence (v1)</b><br/><pre>")
                  .append(c.sectionClockSeq)
                  .append("</pre>");
            }
            if (c.sectionSecurityImpact != null && c.sectionSecurityImpact.length() > 0) {
                sb.append("<hr><b>Additional Observations (v1)</b><br/><pre>")
                  .append(c.sectionSecurityImpact)
                  .append("</pre>");
            }
        }
        // v2 details
        else if ("2".equals(c.version)) {
            if (c.sectionDomain != null) {
                sb.append("<hr><b>v2 Domain Bits</b><br/><pre>")
                  .append(c.sectionDomain)
                  .append("</pre>");
            }
            if (c.sectionClockSeq != null) {
                sb.append("<hr><b>Clock Seq (v2)</b><br/><pre>")
                  .append(c.sectionClockSeq)
                  .append("</pre>");
            }
            if (c.sectionNodeId != null) {
                sb.append("<hr><b>Node ID (v2)</b><br/><pre>")
                  .append(c.sectionNodeId)
                  .append("</pre>");
            }
        }
        // v3 / v5 hashing notes
        else if ("3".equals(c.version) || "5".equals(c.version)) {
            if (c.sectionHashDetails != null) {
                sb.append("<hr><b>Hash Details</b><br/><pre>")
                  .append(c.sectionHashDetails)
                  .append("</pre>");
            }
        }
        // v4 details
        else if ("4".equals(c.version)) {
            if (c.sectionRandomAnalysis != null) {
                sb.append("<hr><b>Randomness Analysis (v4)</b><br/><pre>")
                  .append(c.sectionRandomAnalysis)
                  .append("</pre>");
            }
        }
        // "fake" or unknown
        else if ("fake".equals(c.version)) {
            sb.append("<hr><b>Invalid/Non-RFC GUID</b><br/>")
              .append("<pre>")
              .append(c.notesValidationFail != null ? c.notesValidationFail : "Unknown reason.")
              .append("</pre>");
        }

        // Security Impact
        sb.append("<hr><b>Security Impact</b><br/>");
        if (c.securityImpact != null) {
            sb.append("<pre>").append(c.securityImpact).append("</pre>");
        } else {
            sb.append("No critical or proven exploit found.<br/>");
        }

        // Remediation
        if (c.remediation != null) {
            sb.append("<b>Remediation: </b>").append(c.remediation).append("<br/>");
        }

        // Confidence
        sb.append("<b>Confidence: </b>").append(c.confidence).append("<br/>");
        // Severity
        sb.append("<b>Severity: </b>").append(c.severity).append("<br/>");

        // Discovery time
        if (c.discoveryTime != null) {
            sb.append("<b>Discovered at: </b>").append(c.discoveryTime).append("<br/>");
        }
        return sb.toString();
    }

    // ---------------------------
    // Utility routines
    // ---------------------------

    private String combineText(HttpRequestResponse rr) {
        StringBuilder sb = new StringBuilder();
        if (rr.request() != null) {
            ByteArray reqBA = rr.request().toByteArray();
            sb.append(reqBA.toString());
        }
        sb.append("\n--split--\n");
        if (rr.response() != null) {
            ByteArray respBA = rr.response().toByteArray();
            sb.append(respBA.toString());
        }
        return sb.toString();
    }

    private Set<String> detectGuidsInText(String text) {
        Set<String> results = new HashSet<>();
        Matcher m = GUID_PATTERN.matcher(text);
        while (m.find()) {
            String token = m.group();
            if (token != null) {
                results.add(token);
            }
        }
        return results;
    }

    private Set<String> decodeUrlEncodedAndScan(String combined) {
        Set<String> tokens = new HashSet<>();
        try {
            String dec = java.net.URLDecoder.decode(combined, StandardCharsets.UTF_8);
            tokens.addAll(detectGuidsInText(dec));
        } catch (IllegalArgumentException e) {
            api.logging().logToError("Malformed URL-encoded string: " + e.getMessage());
        }
        return tokens;
    }

    private Set<String> decodeBase64AndScan(String combined) {
        Set<String> tokens = new HashSet<>();
        Matcher m = BASE64_PATTERN.matcher(combined);
        while (m.find()) {
            String b64 = m.group();
            try {
                byte[] decoded = Base64.getDecoder().decode(b64);
                String sub = new String(decoded, StandardCharsets.UTF_8);
                tokens.addAll(detectGuidsInText(sub));
            } catch (Exception e) {
                api.logging().logToError("Error decoding Base64: " + e.getMessage());
            }
        }
        return tokens;
    }

    private void highlightTokenOccurrences(String token, HttpRequestResponse rr,
                                           List<Marker> reqMarkers,
                                           List<Marker> respMarkers) {
        if (rr.request() != null) {
            ByteArray reqBA = rr.request().toByteArray();
            String reqStr = reqBA.toString();
            int offset = 0;
            while (true) {
                offset = reqStr.indexOf(token, offset);
                if (offset < 0) break;
                reqMarkers.add(Marker.marker(offset, offset + token.length()));
                offset += token.length();
            }
        }
        if (rr.response() != null) {
            ByteArray respBA = rr.response().toByteArray();
            String respStr = respBA.toString();
            int offset = 0;
            while (true) {
                offset = respStr.indexOf(token, offset);
                if (offset < 0) break;
                respMarkers.add(Marker.marker(offset, offset + token.length()));
                offset += token.length();
            }
        }
    }

    private boolean isIgnoredHost(String host) {
        for (String h : config.ignoredHosts) {
            if (h.equalsIgnoreCase(host)) {
                return true;
            }
        }
        return false;
    }

    private boolean isLikelyStaticJS(String url) {
        return url.toLowerCase().endsWith(".js");
    }

    private int severityRank(AuditIssueSeverity s) {
        switch (s) {
            case HIGH:
                return 4;
            case MEDIUM:
                return 3;
            case LOW:
                return 2;
            case INFORMATION:
                return 1;
            default:
                return 0;
        }
    }

    private int confidenceRank(AuditIssueConfidence c) {
        switch (c) {
            case CERTAIN:
                return 3;
            case FIRM:
                return 2;
            case TENTATIVE:
                return 1;
            default:
                return 0;
        }
    }

    private void buildSettingsTab(UserInterface ui) {
        settingsPanel = new JPanel();
        settingsPanel.setLayout(new BoxLayout(settingsPanel, BoxLayout.Y_AXIS));
        settingsPanel.setBorder(new TitledBorder("0xGUID Scanner Settings"));

        JPanel generalSettingsPanel = new JPanel(new GridLayout(3, 1, 5, 5));
        generalSettingsPanel.setBorder(BorderFactory.createEmptyBorder(10, 10, 10, 10));

        JCheckBox enabledBox = new JCheckBox("Enable GUID/UUID scanning (global)", config.enabled);
        enabledBox.addItemListener(e -> config.enabled = (e.getStateChange() == ItemEvent.SELECTED));
        generalSettingsPanel.add(enabledBox);

        JCheckBox detectFakeBox = new JCheckBox("Detect 'fake' variant/versions", config.detectFake);
        detectFakeBox.addItemListener(e -> config.detectFake = (e.getStateChange() == ItemEvent.SELECTED));
        generalSettingsPanel.add(detectFakeBox);

        JCheckBox ignoreJSBox = new JCheckBox("Ignore static .js files", config.ignoreStaticJS);
        ignoreJSBox.addItemListener(e -> config.ignoreStaticJS = (e.getStateChange() == ItemEvent.SELECTED));
        generalSettingsPanel.add(ignoreJSBox);

        settingsPanel.add(generalSettingsPanel);

        JPanel ignoredHostsPanel = new JPanel();
        ignoredHostsPanel.setLayout(new BoxLayout(ignoredHostsPanel, BoxLayout.Y_AXIS));
        ignoredHostsPanel.setBorder(new TitledBorder("Ignored Hosts"));

        JTextArea ignoredHostsArea = new JTextArea();
        ignoredHostsArea.setEditable(false);
        ignoredHostsArea.setLineWrap(true);
        ignoredHostsArea.setWrapStyleWord(true);
        ignoredHostsArea.setText(String.join("\n", config.ignoredHosts));
        JScrollPane scrollPane = new JScrollPane(ignoredHostsArea);
        scrollPane.setPreferredSize(new Dimension(400, 100));
        ignoredHostsPanel.add(scrollPane);

        JPanel hostControls = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        JTextField hostInput = new JTextField(20);
        JButton addHostBtn = new JButton("Add Host");
        JButton removeHostBtn = new JButton("Remove Host");

        addHostBtn.addActionListener(e -> {
            String host = hostInput.getText().trim();
            if (!host.isEmpty() && !config.ignoredHosts.contains(host)) {
                config.ignoredHosts.add(host);
                ignoredHostsArea.setText(String.join("\n", config.ignoredHosts));
                hostInput.setText("");
            } else {
                JOptionPane.showMessageDialog(settingsPanel, "Host is already ignored or invalid.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        removeHostBtn.addActionListener(e -> {
            String host = hostInput.getText().trim();
            if (config.ignoredHosts.remove(host)) {
                ignoredHostsArea.setText(String.join("\n", config.ignoredHosts));
                hostInput.setText("");
            } else {
                JOptionPane.showMessageDialog(settingsPanel, "Host not found in ignored list.", "Error", JOptionPane.ERROR_MESSAGE);
            }
        });

        hostControls.add(new JLabel("Host:"));
        hostControls.add(hostInput);
        hostControls.add(addHostBtn);
        hostControls.add(removeHostBtn);
        ignoredHostsPanel.add(hostControls);

        settingsPanel.add(ignoredHostsPanel);

        JPanel severityPanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        severityPanel.setBorder(new TitledBorder("Minimum severity to report:"));
        JComboBox<AuditIssueSeverity> minSevCombo = new JComboBox<>(new AuditIssueSeverity[]{
            AuditIssueSeverity.HIGH, AuditIssueSeverity.MEDIUM,
            AuditIssueSeverity.LOW, AuditIssueSeverity.INFORMATION
        });
        minSevCombo.setPreferredSize(new Dimension(150, 25));
        minSevCombo.setSelectedItem(config.minSeverityToReport);
        minSevCombo.addActionListener(e -> config.minSeverityToReport = (AuditIssueSeverity) minSevCombo.getSelectedItem());
        severityPanel.add(minSevCombo);
        settingsPanel.add(severityPanel);

        JPanel confidencePanel = new JPanel(new FlowLayout(FlowLayout.LEFT, 5, 5));
        confidencePanel.setBorder(new TitledBorder("Minimum confidence to report:"));
        JComboBox<AuditIssueConfidence> minConfCombo = new JComboBox<>(new AuditIssueConfidence[]{
            AuditIssueConfidence.CERTAIN, AuditIssueConfidence.FIRM, AuditIssueConfidence.TENTATIVE
        });
        minConfCombo.setPreferredSize(new Dimension(150, 25));
        minConfCombo.setSelectedItem(config.minConfidenceToReport);
        minConfCombo.addActionListener(e -> config.minConfidenceToReport = (AuditIssueConfidence) minConfCombo.getSelectedItem());
        confidencePanel.add(minConfCombo);
        settingsPanel.add(confidencePanel);

        JPanel versionPanel = new JPanel(new GridLayout(1, 5, 5, 5));
        versionPanel.setBorder(new TitledBorder("UUID Versions to Check"));
        List<String> versionList = Arrays.asList("1", "2", "3", "4", "5");
        for (String v : versionList) {
            JCheckBox vb = new JCheckBox("v" + v, config.enabledVersions.contains(v));
            vb.addItemListener(e -> {
                if (e.getStateChange() == ItemEvent.SELECTED) {
                    config.enabledVersions.add(v);
                } else {
                    config.enabledVersions.remove(v);
                }
            });
            versionPanel.add(vb);
        }
        settingsPanel.add(versionPanel);

        JPanel savePanel = new JPanel(new FlowLayout(FlowLayout.RIGHT, 5, 5));
        JButton saveBtn = new JButton("Save Settings");
        saveBtn.addActionListener(e -> {
            saveSettingsToDisk(config);
            JOptionPane.showMessageDialog(settingsPanel, "Settings saved to disk!");
        });
        savePanel.add(saveBtn);

        settingsPanel.add(savePanel);

        ui.registerSuiteTab("0xGUID Scanner", settingsPanel);
    }

    private ExtensionConfig loadSettingsFromDisk() {
        Path path = getSettingsFilePath();
        if (!Files.exists(path)) {
            return new ExtensionConfig();
        }
        try {
            String json = new String(Files.readAllBytes(path), StandardCharsets.UTF_8);
            return ExtensionConfig.fromJson(json);
        } catch (IOException e) {
            api.logging().logToError("Failed loading settings: " + e.getMessage());
            return new ExtensionConfig();
        }
    }

    private void saveSettingsToDisk(ExtensionConfig cfg) {
        try {
            String json = cfg.toJson();
            Files.write(getSettingsFilePath(), json.getBytes(StandardCharsets.UTF_8));
        } catch (IOException e) {
            api.logging().logToError("Failed saving settings: " + e.getMessage());
        }
    }

    private Path getSettingsFilePath() {
        String home = System.getProperty("user.home");
        return Path.of(home, ".guid_scanner_settings.json");
    }

    // Helper methods for parsing
    private byte[] parseHex(String hex)
    {
        if (hex.length() % 2 != 0) return null;
        byte[] out = new byte[hex.length() / 2];
        for (int i = 0; i < hex.length(); i += 2) {
            int hi = Character.digit(hex.charAt(i), 16);
            int lo = Character.digit(hex.charAt(i + 1), 16);
            if (hi < 0 || lo < 0) return null;
            out[i / 2] = (byte) ((hi << 4) + lo);
        }
        return out;
    }

    private String toHex(byte[] data)
    {
        StringBuilder sb = new StringBuilder(data.length * 2);
        for (byte b : data) {
            sb.append(String.format("%02x", b));
        }
        return sb.toString();
    }

    private int hexToInt(String h) {
        return Integer.parseInt(h, 16);
    }

    private long getUnsignedInt(byte[] raw, int offset) {
        return ((raw[offset] & 0xffL) << 24)
            | ((raw[offset + 1] & 0xffL) << 16)
            | ((raw[offset + 2] & 0xffL) << 8)
            | (raw[offset + 3] & 0xffL);
    }

    private long getUnsignedShort(byte[] raw, int offset) {
        return ((raw[offset] & 0xffL) << 8) | (raw[offset + 1] & 0xffL);
    }

    private String macColonFormat(byte[] mac) {
        if (mac.length < 6) return "(invalidMAC)";
        StringBuilder sb = new StringBuilder();
        for (int i = 0; i < 6; i++) {
            sb.append(String.format("%02x", mac[i]));
            if (i < 5) sb.append(":");
        }
        return sb.toString();
    }

    private AuditIssueSeverity escalate(AuditIssueSeverity oldSev, AuditIssueSeverity newSev) {
        int oldRank = severityRank(oldSev);
        int newRank = severityRank(newSev);
        return (newRank > oldRank) ? newSev : oldSev;
    }

    // ---------------------------
    // Data classes
    // ---------------------------
    static class Classification {
        String version = null;
        String token = null;
        String rawHex = null;
        AuditIssueSeverity severity;
        AuditIssueConfidence confidence;
        String notesValidationFail = null;
        String securityImpact = null;
        String remediation = null;
        Date discoveryTime = null;

        // For v1
        StringBuilder sectionMac = null;
        StringBuilder sectionTimestamp = null;
        StringBuilder sectionClockSeq = null;
        StringBuilder sectionSecurityImpact = null;
        long v1Timestamp100ns = 0;

        // For v2
        StringBuilder sectionDomain = null;
        StringBuilder sectionNodeId = null;

        // For v3/v5
        StringBuilder sectionHashDetails = null;

        // For v4
        StringBuilder sectionRandomAnalysis = null;
    }

    static class DiscoveredToken {
        String token;
        Classification classification;
        long discoveredAt;

        DiscoveredToken(String token, Classification c, long discoveredAt) {
            this.token = token;
            this.classification = c;
            this.discoveredAt = discoveredAt;
        }
    }

    static class ExtensionConfig {
        boolean enabled = true;
        boolean detectFake = false;
        boolean ignoreStaticJS = false;
        boolean decodeBase64 = true;
        boolean decodeURLEncoded = true;
        AuditIssueSeverity minSeverityToReport = AuditIssueSeverity.MEDIUM;
        AuditIssueConfidence minConfidenceToReport = AuditIssueConfidence.FIRM;
        Set<String> enabledVersions = new HashSet<>(Arrays.asList("1", "2", "3", "4", "5"));
        List<String> ignoredHosts = new ArrayList<>();

        String toJson() {
            StringBuilder sb = new StringBuilder();
            sb.append("{");
            sb.append("\"enabled\":").append(enabled).append(",");
            sb.append("\"detectFake\":").append(detectFake).append(",");
            sb.append("\"ignoreStaticJS\":").append(ignoreStaticJS).append(",");
            sb.append("\"decodeBase64\":").append(decodeBase64).append(",");
            sb.append("\"decodeURLEncoded\":").append(decodeURLEncoded).append(",");
            sb.append("\"minSeverityToReport\":\"").append(minSeverityToReport).append("\",");
            sb.append("\"minConfidenceToReport\":\"").append(minConfidenceToReport).append("\",");

            sb.append("\"enabledVersions\":[");
            int i = 0;
            for (String v : enabledVersions) {
                if (i > 0) sb.append(",");
                sb.append("\"").append(v).append("\"");
                i++;
            }
            sb.append("],");

            sb.append("\"ignoredHosts\":[");
            for (int idx = 0; idx < ignoredHosts.size(); idx++) {
                if (idx > 0) sb.append(",");
                sb.append("\"").append(ignoredHosts.get(idx)).append("\"");
            }
            sb.append("]}");
            return sb.toString();
        }

        static ExtensionConfig fromJson(String json) {
            ExtensionConfig cfg = new ExtensionConfig();
            try {
                cfg.enabled = json.contains("\"enabled\":true");
                cfg.detectFake = json.contains("\"detectFake\":true");
                cfg.ignoreStaticJS = json.contains("\"ignoreStaticJS\":true");
                cfg.decodeBase64 = json.contains("\"decodeBase64\":true");
                cfg.decodeURLEncoded = json.contains("\"decodeURLEncoded\":true");

                if (json.contains("\"minSeverityToReport\":\"HIGH\"")) {
                    cfg.minSeverityToReport = AuditIssueSeverity.HIGH;
                } else if (json.contains("\"minSeverityToReport\":\"MEDIUM\"")) {
                    cfg.minSeverityToReport = AuditIssueSeverity.MEDIUM;
                } else if (json.contains("\"minSeverityToReport\":\"LOW\"")) {
                    cfg.minSeverityToReport = AuditIssueSeverity.LOW;
                } else {
                    cfg.minSeverityToReport = AuditIssueSeverity.INFORMATION;
                }

                if (json.contains("\"minConfidenceToReport\":\"CERTAIN\"")) {
                    cfg.minConfidenceToReport = AuditIssueConfidence.CERTAIN;
                } else if (json.contains("\"minConfidenceToReport\":\"FIRM\"")) {
                    cfg.minConfidenceToReport = AuditIssueConfidence.FIRM;
                } else {
                    cfg.minConfidenceToReport = AuditIssueConfidence.TENTATIVE;
                }

                cfg.enabledVersions.clear();
                if (json.contains("\"1\"")) cfg.enabledVersions.add("1");
                if (json.contains("\"2\"")) cfg.enabledVersions.add("2");
                if (json.contains("\"3\"")) cfg.enabledVersions.add("3");
                if (json.contains("\"4\"")) cfg.enabledVersions.add("4");
                if (json.contains("\"5\"")) cfg.enabledVersions.add("5");

                int idx = json.indexOf("\"ignoredHosts\":[");
                if (idx >= 0) {
                    int close = json.indexOf("]", idx);
                    if (close > idx) {
                        String sub = json.substring(idx, close);
                        Matcher m = Pattern.compile("\"([^\"]+)\"").matcher(sub);
                        while (m.find()) {
                            String h = m.group(1);
                            if (!"ignoredHosts".equals(h)) {
                                cfg.ignoredHosts.add(h);
                            }
                        }
                    }
                }

            } catch (Exception e) {
                // parse fail fallback
            }
            return cfg;
        }
    }
}
