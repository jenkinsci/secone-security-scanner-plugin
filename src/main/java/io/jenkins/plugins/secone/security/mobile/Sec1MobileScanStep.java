package io.jenkins.plugins.secone.security.mobile;

import java.io.IOException;
import java.io.PrintStream;
import java.net.URI;
import java.net.URISyntaxException;
import java.nio.charset.StandardCharsets;
import java.time.Instant;
import java.time.ZoneId;
import java.time.format.DateTimeFormatter;
import java.util.Collections;
import java.util.HashMap;
import java.util.LinkedHashMap;
import java.util.List;
import java.util.Map;

import org.apache.commons.lang.StringUtils;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.json.JSONArray;
import org.json.JSONObject;
import org.kohsuke.stapler.AncestorInPath;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.kohsuke.stapler.verb.POST;

import com.cloudbees.plugins.credentials.CredentialsProvider;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.PluginWrapper;
import hudson.model.AbstractProject;
import hudson.model.Item;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import hudson.util.ListBoxModel;
import io.jenkins.plugins.secone.security.pojo.Threshold;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;

/**
 * Scans a mobile app binary (.apk, .aab, .ipa, ...) with Sec1 Mobile Security:
 * submits it, polls until the scan finishes, archives the findings and applies
 * a quality gate.
 */
public class Sec1MobileScanStep extends Builder implements SimpleBuildStep {

	static final String DEFAULT_BASE_URL = "https://api.sec1.io/rest/ai-sast-mobile";
	static final String DEFAULT_CONSOLE_URL = "https://unified.sec1.io";
	static final String FINDINGS_FILE = "sec1-mobile-findings.json";
	static final String REPORT_FILE = "sec1-mobile-report.pdf";
	private static final String DEFAULT_CREDENTIALS_ID = "SEC1_API_KEY";
	private static final int FINDINGS_PAGE = 500;
	private static final int MAX_BACKOFF_SECONDS = 60;
	private static final String[] BINARY_EXTENSIONS = { ".apk", ".aab", ".xapk", ".ipa" };

	/** Wait before retrying an Artifactory submission; lowered only by tests. */
	static int submitRetrySeconds = 10;

	/** Wait between requests while the PDF report is being generated; lowered only by tests. */
	static int reportRetrySeconds = 10;

	/** How long to wait for the PDF report to be generated. */
	static int reportTimeoutMinutes = 10;

	/** Serves the PDF when the scanner nodes do not; changed only by tests. */
	static String reportFallbackBase = DEFAULT_BASE_URL;

	/** Lower bound on the poll interval; lowered only by tests. */
	static int minPollSeconds = 10;

	private final String apiCredentialsId;
	private final String binaryPath;
	private String artifactUrl;
	private String artifactSha256;
	private String baseUrl;
	private String appName;
	private String appVersion;
	private String environment;
	private String scanType;
	private String source;
	private String engagementId;
	private Integer pollIntervalSeconds;
	private Integer timeoutMinutes;
	private Boolean applyThreshold;
	private Threshold threshold;
	private String actionOnThresholdBreached;
	private Integer minScore;
	private Boolean archiveFindings;
	private Boolean resubmitPartial;
	private Boolean archiveReport;

	@DataBoundConstructor
	public Sec1MobileScanStep(String apiCredentialsId, String binaryPath) {
		this.apiCredentialsId = apiCredentialsId;
		this.binaryPath = binaryPath;
	}

	public String getApiCredentialsId() {
		return apiCredentialsId;
	}

	public String getBinaryPath() {
		return binaryPath;
	}

	public String getArtifactUrl() {
		return artifactUrl;
	}

	/** Artifactory download URL; the scanner node fetches the binary itself instead of an upload. */
	@DataBoundSetter
	public void setArtifactUrl(String artifactUrl) {
		this.artifactUrl = StringUtils.trimToNull(artifactUrl);
	}

	public String getArtifactSha256() {
		return artifactSha256;
	}

	@DataBoundSetter
	public void setArtifactSha256(String artifactSha256) {
		this.artifactSha256 = StringUtils.trimToNull(artifactSha256);
	}

	public String getBaseUrl() {
		return baseUrl;
	}

	@DataBoundSetter
	public void setBaseUrl(String baseUrl) {
		this.baseUrl = StringUtils.trimToNull(baseUrl);
	}

	public String getAppName() {
		return appName;
	}

	@DataBoundSetter
	public void setAppName(String appName) {
		this.appName = StringUtils.trimToNull(appName);
	}

	public String getAppVersion() {
		return appVersion;
	}

	@DataBoundSetter
	public void setAppVersion(String appVersion) {
		this.appVersion = StringUtils.trimToNull(appVersion);
	}

	public String getEnvironment() {
		return environment;
	}

	@DataBoundSetter
	public void setEnvironment(String environment) {
		this.environment = StringUtils.trimToNull(environment);
	}

	public String getScanType() {
		return StringUtils.defaultIfBlank(scanType, "owasp");
	}

	@DataBoundSetter
	public void setScanType(String scanType) {
		this.scanType = StringUtils.trimToNull(scanType);
	}

	public String getSource() {
		return source;
	}

	@DataBoundSetter
	public void setSource(String source) {
		this.source = StringUtils.trimToNull(source);
	}

	public String getEngagementId() {
		return engagementId;
	}

	@DataBoundSetter
	public void setEngagementId(String engagementId) {
		this.engagementId = StringUtils.trimToNull(engagementId);
	}

	public int getPollIntervalSeconds() {
		return pollIntervalSeconds == null || pollIntervalSeconds <= 0 ? 20 : pollIntervalSeconds;
	}

	@DataBoundSetter
	public void setPollIntervalSeconds(int pollIntervalSeconds) {
		this.pollIntervalSeconds = pollIntervalSeconds;
	}

	public int getTimeoutMinutes() {
		return timeoutMinutes == null || timeoutMinutes <= 0 ? 45 : timeoutMinutes;
	}

	@DataBoundSetter
	public void setTimeoutMinutes(int timeoutMinutes) {
		this.timeoutMinutes = timeoutMinutes;
	}

	/** Null unless set explicitly; a configured threshold applies unless this is false. */
	public Boolean getApplyThreshold() {
		return applyThreshold;
	}

	@DataBoundSetter
	public void setApplyThreshold(Boolean applyThreshold) {
		this.applyThreshold = applyThreshold;
	}

	public Threshold getThreshold() {
		return threshold;
	}

	@DataBoundSetter
	public void setThreshold(Threshold threshold) {
		this.threshold = threshold;
	}

	public String getActionOnThresholdBreached() {
		return actionOnThresholdBreached;
	}

	@DataBoundSetter
	public void setActionOnThresholdBreached(String actionOnThresholdBreached) {
		this.actionOnThresholdBreached = StringUtils.trimToNull(actionOnThresholdBreached);
	}

	public Integer getMinScore() {
		return minScore;
	}

	@DataBoundSetter
	public void setMinScore(Integer minScore) {
		this.minScore = minScore;
	}

	/* Same rules as sec1Security: no threshold means no gate. */
	boolean isThresholdActive() {
		return (threshold != null && !Boolean.FALSE.equals(applyThreshold)) || minScore != null;
	}

	/* actionOnThresholdBreached wins over the action picked in the threshold block; default fail. */
	String resolveBreachAction() {
		for (String candidate : new String[] { actionOnThresholdBreached,
				threshold == null ? null : threshold.getStatusAction() }) {
			String action = StringUtils.lowerCase(StringUtils.trimToNull(candidate));
			if ("fail".equals(action) || "unstable".equals(action) || "continue".equals(action)) {
				return action;
			}
		}
		return "fail";
	}

	/** Download the executive PDF report and archive it with the build. Default false. */
	public boolean isArchiveReport() {
		return archiveReport != null && archiveReport;
	}

	@DataBoundSetter
	public void setArchiveReport(boolean archiveReport) {
		this.archiveReport = archiveReport;
	}

	/** Resubmit once when a scan is interrupted ('partial'); never for a timeout. Default true. */
	public boolean isResubmitPartial() {
		return resubmitPartial == null || resubmitPartial;
	}

	@DataBoundSetter
	public void setResubmitPartial(boolean resubmitPartial) {
		this.resubmitPartial = resubmitPartial;
	}

	/* A scan stopped by a time limit would hit the same limit again; only interruptions are worth a retry. */
	static boolean isTimeoutReason(String error) {
		return StringUtils.containsIgnoreCase(error, "timeout") || StringUtils.containsIgnoreCase(error, "timed_out")
				|| StringUtils.containsIgnoreCase(error, "over_1h");
	}

	public boolean isArchiveFindings() {
		return archiveFindings == null || archiveFindings;
	}

	@DataBoundSetter
	public void setArchiveFindings(boolean archiveFindings) {
		this.archiveFindings = archiveFindings;
	}

	@Override
	public void perform(@NonNull Run<?, ?> run, @NonNull FilePath workspace, @NonNull EnvVars env,
			@NonNull Launcher launcher, @NonNull TaskListener listener) throws InterruptedException, IOException {
		PrintStream log = listener.getLogger();
		log.println("=============== Sec1 Mobile Security Scan ===============");

		String apiKey = resolveApiKey(run, log);
		// Never derived from SEC1_INSTANCE_URL: hybrid deployments send binaries to the customer's
		// scanner nodes (load balancer), while SCA/SAST keep using the control plane.
		String base = StringUtils.trimToNull(env.expand(StringUtils.defaultString(baseUrl)));
		String baseSource = "baseUrl";
		if (base == null) {
			base = StringUtils.trimToNull(env.get("SEC1_MOBILE_BASE_URL"));
			baseSource = "SEC1_MOBILE_BASE_URL";
		}
		if (base == null) {
			base = DEFAULT_BASE_URL;
			baseSource = "default, Sec1 SaaS";
		}
		base = StringUtils.removeEnd(base, "/");
		String consoleUrl = StringUtils.removeEnd(
				StringUtils.defaultIfBlank(env.get("SEC1_DASHBOARD_URL"), DEFAULT_CONSOLE_URL), "/");
		String artifact = StringUtils.trimToNull(env.expand(StringUtils.defaultString(artifactUrl)));
		String pattern = StringUtils.trimToNull(env.expand(StringUtils.defaultString(binaryPath)));
		FilePath binary = null;
		String sha256 = StringUtils.lowerCase(StringUtils.trimToNull(env.expand(StringUtils.defaultString(artifactSha256))));
		boolean shaFromWorkspace = false;
		if (artifact != null) {
			validateArtifactUrl(artifact);
			// With an artifact URL the workspace binary is only used for its checksum, never uploaded.
			if (pattern != null) {
				binary = resolveBinary(workspace, pattern);
				if (sha256 == null) {
					sha256 = binary.act(new MobileApi.Sha256());
					shaFromWorkspace = true;
				}
			}
			if (sha256 != null && !sha256.matches("[0-9a-f]{64}")) {
				throw new AbortException("artifactSha256 must be the 64-character hex SHA-256 of the binary.");
			}
		} else {
			binary = resolveBinary(workspace, pattern);
		}
		String fileName = artifact != null ? artifactFileName(artifact) : binary.getName();
		String userAgent = "Sec1Jenkins/" + pluginVersion();
		VirtualChannel channel = workspace.getChannel();

		Map<String, String> fields = new LinkedHashMap<>();
		fields.put("app_name", StringUtils.defaultIfBlank(env.expand(StringUtils.defaultString(appName)),
				StringUtils.substringBeforeLast(fileName, ".")));
		fields.put("version", StringUtils.defaultIfBlank(env.expand(StringUtils.defaultString(appVersion)),
				env.get("BUILD_NUMBER")));
		fields.put("environment", env.expand(StringUtils.defaultString(environment)));
		fields.put("scan_type", getScanType());
		fields.put("engagement_id", env.expand(StringUtils.defaultString(engagementId)));
		fields.put("source", StringUtils.left(StringUtils.defaultIfBlank(env.expand(StringUtils.defaultString(source)),
				"jenkins:" + env.get("JOB_NAME", "job") + "#" + env.get("BUILD_NUMBER", "0")), 200));

		log.println("Base URL               " + base + " (" + baseSource + ")");
		if (artifact != null) {
			log.println("Artifact URL           " + artifact);
			log.println("Artifact SHA-256       " + (sha256 == null ? "not set (verified against Artifactory's checksum)"
					: sha256 + (shaFromWorkspace ? " (from " + binary.getRemote() + ")" : "")));
		} else {
			log.println("Binary                 " + binary.getRemote() + " (" + binary.length() + " bytes)");
		}
		log.println("App                    " + fields.get("app_name") + " " + fields.get("version")
				+ (StringUtils.isNotBlank(fields.get("environment")) ? " [" + fields.get("environment") + "]" : ""));
		log.println("Scan Type              " + getScanType());

		// One budget for the whole step, a resubmission included, so it fits inside a stage timeout().
		long deadline = System.currentTimeMillis() + getTimeoutMinutes() * 60_000L;
		JSONObject record = null;
		for (int attempt = 1; attempt <= 2; attempt++) {
			JSONObject created = artifact != null
					? submitArtifact(channel, base, apiKey, userAgent, fields, artifact, sha256, log)
					: submit(binary, base, apiKey, userAgent, fields, log);
			String id = created.getString("id");
			log.println("Scan Id                " + id);
			String node = created.optString("scanner_id", "");
			JSONObject submission = created.optJSONObject("submission");
			if (StringUtils.isBlank(node) && submission != null) {
				node = submission.optString("received_by", "");
			}
			if (StringUtils.isNotBlank(node)) {
				log.println("Received By            " + node);
			}
			if (StringUtils.isNotBlank(created.optString("engine_version", ""))) {
				log.println("Engine Version         " + created.optString("engine_version"));
			}
			log.println("Console                " + consoleLink(created, consoleUrl, id));

			record = poll(channel, base, id, apiKey, userAgent, deadline, log);
			String status = record.optString("status");
			if ("partial".equals(status) && attempt == 1) {
				String reason = StringUtils.defaultIfBlank(record.optString("error", ""), "no reason given");
				if (!isResubmitPartial()) {
					log.println("Scan ended 'partial' (" + reason + "); not resubmitting (resubmitPartial is false).");
				} else if (isTimeoutReason(reason)) {
					log.println("Scan ended 'partial' (" + reason + "): the scanner node stopped it at its time limit."
							+ " Not resubmitting, since a new scan would hit the same limit.");
				} else if (System.currentTimeMillis() >= deadline) {
					log.println("Scan ended 'partial' (" + reason + "); no time left within timeoutMinutes to resubmit.");
				} else {
					log.println("Scan ended 'partial' (" + reason + "); resubmitting once.");
					continue;
				}
			}
			break;
		}

		String status = record.optString("status");
		String id = record.getString("id");
		log.println("-------------------- Sec1 Mobile Scan Result --------------------");
		log.println("Status                 " + status);
		log.println("Console                " + consoleLink(record, consoleUrl, id));
		switch (status) {
		case "completed":
			break;
		case "cancelled":
			throw new InterruptedException("Sec1 mobile scan " + id + " was cancelled.");
		default:
			String reason = StringUtils.defaultIfBlank(record.optString("error", ""), "no reason given");
			throw new AbortException("Sec1 mobile scan " + id + " ended '" + status + "': " + reason
					+ ("partial".equals(status) && isTimeoutReason(reason)
							? " (the scanner node's time limit for one scan was reached; raise it with the node operator)"
							: ""));
		}

		JSONObject summary = record.optJSONObject("summary");
		Map<String, Integer> bySeverity = new HashMap<>();
		Integer score = null;
		if (summary != null) {
			JSONObject sev = summary.optJSONObject("by_severity");
			if (sev != null) {
				for (String tier : sev.keySet()) {
					bySeverity.put(tier, sev.optInt(tier, 0));
				}
			}
			if (summary.has("aggregate_score") && !summary.isNull("aggregate_score")) {
				score = summary.optInt("aggregate_score");
			}
			log.println("Findings               " + summary.optInt("total_findings", 0) + " (Critical: "
					+ MobileScanGate.count(bySeverity, "Critical") + ", High: " + MobileScanGate.count(bySeverity, "High")
					+ ", Medium: " + MobileScanGate.count(bySeverity, "Medium") + ", Low: "
					+ MobileScanGate.count(bySeverity, "Low") + ")");
			if (score != null) {
				log.println("Score                  " + score
						+ (StringUtils.isNotBlank(summary.optString("score_band", "")) ? " ("
								+ summary.optString("score_band") + ")" : ""));
			}
		}

		if (isArchiveFindings()) {
			archiveFindings(run, workspace, launcher, listener, channel, base, id, apiKey, userAgent, log);
		}
		if (isArchiveReport()) {
			archiveReport(run, workspace, launcher, listener, base, id, apiKey, userAgent, log);
		}

		if (!isThresholdActive()) {
			log.println("Threshold              Disabled (findings do not affect the build result)");
			return;
		}
		Threshold effective = Boolean.FALSE.equals(applyThreshold) ? null : threshold;
		List<String> breaches = MobileScanGate.evaluate(bySeverity, score, effective, minScore);
		if (breaches.isEmpty()) {
			log.println("Threshold              PASSED");
			return;
		}
		String action = resolveBreachAction();
		for (String breach : breaches) {
			log.println(breach);
		}
		switch (action) {
		case "continue":
			log.println("Threshold              BREACHED (action: continue)");
			break;
		case "unstable":
			log.println("Threshold              BREACHED (action: unstable)");
			run.setResult(Result.UNSTABLE);
			break;
		default:
			log.println("Threshold              BREACHED (action: fail)");
			throw new AbortException("Sec1 mobile scan vulnerability threshold breached. Failing the build.");
		}
	}

	private JSONObject submit(FilePath binary, String base, String apiKey, String userAgent,
			Map<String, String> fields, PrintStream log) throws IOException, InterruptedException {
		log.println("Uploading binary...");
		MobileApi.Response r;
		try {
			r = binary.act(new MobileApi.Submit(base + "/api/v1/scans", apiKey, userAgent, fields));
		} catch (IOException e) {
			throw unreachable(base, e);
		}
		if (!r.isSuccess()) {
			// Not retried: a retry after a partially processed upload would start a second scan.
			throw new AbortException(describeError("Scan submission", r));
		}
		return new JSONObject(r.body);
	}

	/*
	 * Submit by Artifactory URL (no upload). A failed submit never creates a
	 * scan, so transient failures, such as the node not reaching Artifactory
	 * (502 artifactory_unreachable), are safe to retry.
	 */
	private JSONObject submitArtifact(VirtualChannel channel, String base, String apiKey, String userAgent,
			Map<String, String> fields, String artifact, String sha256, PrintStream log)
			throws IOException, InterruptedException {
		JSONObject body = new JSONObject();
		body.put("artifact_url", artifact);
		if (sha256 != null) {
			body.put("artifact_sha256", sha256);
		}
		for (Map.Entry<String, String> field : fields.entrySet()) {
			if (StringUtils.isNotEmpty(field.getValue())) {
				body.put(field.getKey(), field.getValue());
			}
		}
		log.println("Submitting Artifactory URL...");
		for (int attempt = 1;; attempt++) {
			MobileApi.Response r;
			try {
				r = channel.call(new MobileApi.PostJson(base + "/api/v1/scans", apiKey, userAgent, body.toString()));
			} catch (IOException e) {
				if (attempt >= 3) {
					throw unreachable(base, e);
				}
				log.println("Scan submission failed (" + describeException(e) + "); retrying.");
				Thread.sleep(submitRetrySeconds * attempt * 1000L);
				continue;
			}
			if (r.isSuccess()) {
				return new JSONObject(r.body);
			}
			boolean transientError = r.status == 429 || r.status == 502 || r.status == 503 || r.status == 504;
			if (!transientError || attempt >= 3) {
				throw new AbortException(describeError("Scan submission", r));
			}
			log.println(describeError("Scan submission", r) + "; retrying.");
			Thread.sleep(submitRetrySeconds * attempt * 1000L);
		}
	}

	private JSONObject poll(VirtualChannel channel, String base, String id, String apiKey, String userAgent,
			long deadline, PrintStream log) throws IOException, InterruptedException {
		int interval = Math.max(minPollSeconds, getPollIntervalSeconds());
		DateTimeFormatter clock = DateTimeFormatter.ofPattern("HH:mm:ss").withZone(ZoneId.systemDefault());
		String lastLine = "";
		int wait = interval;
		try {
			while (true) {
				MobileApi.Response r;
				try {
					r = channel.call(new MobileApi.Call("GET", base + "/api/v1/scans/" + id, apiKey, userAgent));
				} catch (IOException e) {
					r = null;
					log.println("Status check failed (" + describeException(e) + "); retrying.");
				}
				if (r != null && (r.status == 401 || r.status == 403 || r.status == 404)) {
					throw new AbortException(describeError("Status check", r));
				}
				if (r != null && r.isSuccess()) {
					wait = interval;
					JSONObject rec = new JSONObject(r.body);
					String status = rec.optString("status");
					String line = String.format("%-10s %3d%%  %s", status, rec.optInt("progress", 0),
							rec.optString("phase", ""));
					if (!line.equals(lastLine)) {
						log.println(clock.format(Instant.now()) + "  " + line.trim());
						lastLine = line;
					}
					if (isTerminal(status)) {
						return rec;
					}
				} else if (r != null) {
					// 5xx and 429 are transient: back off and keep polling.
					wait = Math.min(Math.max(wait * 2, interval), MAX_BACKOFF_SECONDS);
					log.println("Status check returned HTTP " + r.status + "; retrying in " + wait + "s.");
				} else {
					wait = Math.min(Math.max(wait * 2, interval), MAX_BACKOFF_SECONDS);
				}
				if (System.currentTimeMillis() > deadline) {
					throw new AbortException("Sec1 mobile scan " + id + " did not finish within "
							+ getTimeoutMinutes() + " minutes. It keeps running and stays visible in the console.");
				}
				Thread.sleep(wait * 1000L);
			}
		} catch (InterruptedException e) {
			cancelScan(channel, base, id, apiKey, userAgent, log);
			throw e;
		}
	}

	/*
	 * Build aborted: cancel the scan so it does not keep consuming a worker.
	 * Pipelines close the step's log and may interrupt this thread again while
	 * the request is in flight, so the request runs on its own thread and the
	 * message is printed before it.
	 */
	private static void cancelScan(VirtualChannel channel, String base, String id, String apiKey, String userAgent,
			PrintStream log) {
		log.println("Build aborted; cancelling Sec1 mobile scan " + id + ".");
		java.util.concurrent.Future<?> request = jenkins.util.Timer.get().submit(() -> {
			if (!sendCancel(channel, base, id, apiKey, userAgent)) {
				LOGGER.warning("Could not cancel Sec1 mobile scan " + id + " after the build was aborted.");
				return;
			}
			// A scan cancelled while still queued can be picked up by a worker and
			// switched back to running; re-check and cancel again if it revived.
			for (long delay : new long[] { 5_000, 10_000 }) {
				try {
					Thread.sleep(delay);
					MobileApi.Response r = channel
							.call(new MobileApi.Call("GET", base + "/api/v1/scans/" + id, apiKey, userAgent));
					String status = r.isSuccess() ? new JSONObject(r.body).optString("status") : "";
					if (isTerminal(status) || r.status == 404) {
						return;
					}
					sendCancel(channel, base, id, apiKey, userAgent);
				} catch (IOException | InterruptedException | RuntimeException ex) {
					LOGGER.log(java.util.logging.Level.FINE, "Cancel re-check failed for scan " + id, ex);
					return;
				}
			}
		});
		long deadline = System.currentTimeMillis() + 15_000;
		while (System.currentTimeMillis() < deadline) {
			try {
				request.get(Math.max(1, deadline - System.currentTimeMillis()), java.util.concurrent.TimeUnit.MILLISECONDS);
				return;
			} catch (InterruptedException again) {
				// Keep waiting: the cancellation must not be cut short by repeated interrupts.
			} catch (java.util.concurrent.ExecutionException | java.util.concurrent.TimeoutException ex) {
				return;
			}
		}
	}

	private static boolean sendCancel(VirtualChannel channel, String base, String id, String apiKey, String userAgent) {
		for (int attempt = 1; attempt <= 3; attempt++) {
			try {
				MobileApi.Response r = channel
						.call(new MobileApi.Call("DELETE", base + "/api/v1/scans/" + id, apiKey, userAgent));
				if (r.isSuccess() || r.status == 404) {
					return true;
				}
			} catch (IOException | InterruptedException | RuntimeException ex) {
				LOGGER.log(java.util.logging.Level.FINE, "Cancel attempt " + attempt + " failed for scan " + id, ex);
			}
		}
		return false;
	}

	private static final java.util.logging.Logger LOGGER = java.util.logging.Logger
			.getLogger(Sec1MobileScanStep.class.getName());

	private void archiveFindings(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener,
			VirtualChannel channel, String base, String id, String apiKey, String userAgent, PrintStream log)
			throws IOException, InterruptedException {
		JSONArray all = new JSONArray();
		for (int offset = 0;; offset += FINDINGS_PAGE) {
			MobileApi.Response r = channel.call(new MobileApi.Call("GET",
					base + "/api/v1/scans/" + id + "/findings?limit=" + FINDINGS_PAGE + "&offset=" + offset, apiKey,
					userAgent));
			if (!r.isSuccess()) {
				log.println("Could not fetch findings: " + describeError("Findings", r));
				return;
			}
			JSONObject page = new JSONObject(r.body);
			JSONArray findings = page.optJSONArray("findings");
			int n = findings == null ? 0 : findings.length();
			for (int i = 0; i < n; i++) {
				all.put(findings.get(i));
			}
			if (n < FINDINGS_PAGE) {
				break;
			}
		}
		JSONObject doc = new JSONObject();
		doc.put("scan_id", id);
		doc.put("count", all.length());
		doc.put("findings", all);
		workspace.child(FINDINGS_FILE).write(doc.toString(2), StandardCharsets.UTF_8.name());
		run.pickArtifactManager().archive(workspace, launcher, jenkins.util.BuildListenerAdapter.wrap(listener),
				Collections.singletonMap(FINDINGS_FILE, FINDINGS_FILE));
		log.println("Findings Archived      " + FINDINGS_FILE + " (" + all.length() + " findings)");
	}

	/*
	 * The executive PDF is generated on request, so the server may answer "not
	 * ready" first. Hybrid scanner nodes may not serve it at all, in which case
	 * it comes from the control plane. A missing report never changes the
	 * build result.
	 */
	private void archiveReport(Run<?, ?> run, FilePath workspace, Launcher launcher, TaskListener listener,
			String base, String id, String apiKey, String userAgent, PrintStream log) throws InterruptedException {
		List<String> bases = new java.util.ArrayList<>();
		bases.add(base);
		if (reportFallbackBase != null && !StringUtils.removeEnd(reportFallbackBase, "/").equals(base)) {
			bases.add(StringUtils.removeEnd(reportFallbackBase, "/"));
		}
		FilePath target = workspace.child(REPORT_FILE);
		long deadline = System.currentTimeMillis() + reportTimeoutMinutes * 60_000L;
		log.println("Downloading PDF report...");
		try {
			for (int i = 0; i < bases.size(); i++) {
				String url = bases.get(i) + "/api/v1/scans/" + id + "/reports/executive";
				while (true) {
					MobileApi.Response r = target.act(new MobileApi.Download(url, apiKey, userAgent));
					if (r.status == 200) { // 202 means still generating, not done
						run.pickArtifactManager().archive(workspace, launcher,
								jenkins.util.BuildListenerAdapter.wrap(listener),
								Collections.singletonMap(REPORT_FILE, REPORT_FILE));
						log.println("Report Archived        " + REPORT_FILE + " (" + (target.length() / 1024) + " KB)");
						return;
					}
					boolean notReady = r.status == 202 || r.status == 409 || r.status == 425 || r.status == 429
							|| r.status == 503;
					if (notReady && System.currentTimeMillis() < deadline) {
						int wait = reportRetrySeconds;
						if (r.body != null && r.body.matches("retry-after:\\d+")) {
							wait = Math.max(1, Math.min(60, Integer.parseInt(r.body.substring(12))));
						}
						Thread.sleep(wait * 1000L);
						continue;
					}
					boolean notServedHere = r.status == 404 || r.status == 405 || r.status == 501;
					if (notServedHere && i + 1 < bases.size()) {
						break; // try the next base, e.g. the control plane for hybrid scanner nodes
					}
					log.println("WARNING: PDF report not archived: " + (r.status == 0 ? r.body
							: describeError("Report download", r)) + ". The build result is not affected.");
					return;
				}
			}
		} catch (IOException e) {
			log.println("WARNING: PDF report not archived (" + describeException(e)
					+ "). The build result is not affected.");
		}
	}

	static boolean isTerminal(String status) {
		return "completed".equals(status) || "failed".equals(status) || "cancelled".equals(status)
				|| "partial".equals(status);
	}

	static String consoleLink(JSONObject record, String consoleUrl, String id) {
		String reportUrl = record.optString("report_url", "");
		if (StringUtils.isNotBlank(reportUrl)) {
			return reportUrl;
		}
		JSONObject input = record.optJSONObject("input");
		String sha = input == null ? "" : input.optString("sha256", "");
		return consoleUrl + "/mobile-security/applications/" + StringUtils.left(sha, 12) + "?scan=" + id;
	}

	/*
	 * Network errors from the JDK HTTP client often carry no message (a refused
	 * or timed-out connection is a bare ConnectException), so name the
	 * exception types along the cause chain instead of printing "null".
	 */
	static String describeException(Throwable e) {
		StringBuilder sb = new StringBuilder();
		java.util.Set<Throwable> seen = new java.util.HashSet<>();
		for (Throwable t = e; t != null && seen.add(t); t = t.getCause()) {
			String part = t.getClass().getSimpleName()
					+ (StringUtils.isNotBlank(t.getMessage()) ? ": " + t.getMessage() : "");
			if (sb.indexOf(part) < 0) {
				sb.append(sb.length() == 0 ? "" : " <- ").append(part);
			}
		}
		return sb.toString();
	}

	static AbortException unreachable(String base, IOException e) {
		return new AbortException("Could not reach the Sec1 Mobile Security API at " + base + " ("
				+ describeException(e) + "). Check baseUrl or SEC1_MOBILE_BASE_URL, and that this agent can reach"
				+ " that address (firewall, proxy, DNS).");
	}

	static String describeError(String what, MobileApi.Response r) {
		String code = "";
		String message = "";
		try {
			JSONObject err = new JSONObject(r.body);
			code = StringUtils.defaultIfBlank(err.optString("code", ""), err.optString("error", ""));
			message = StringUtils.defaultIfBlank(err.optString("message", ""), err.optString("detail", ""));
		} catch (RuntimeException ignored) {
			message = StringUtils.left(StringUtils.defaultString(r.body).trim(), 200);
		}
		String hint;
		switch (code) {
		case "artifactory_not_configured":
		case "artifact_url_not_allowed":
		case "artifactory_auth_failed":
			hint = "Artifactory configuration on the scanner node; raise with the node operator";
			break;
		case "artifact_not_found":
			hint = "Artifactory has no file at this URL; check the URL the publish step produced";
			break;
		case "artifact_checksum_mismatch":
			hint = "artifactSha256 does not match Artifactory's checksum; investigate the publish step";
			break;
		case "artifact_too_large":
			hint = "artifact exceeds the scanner node's size limit";
			break;
		case "artifactory_unreachable":
			hint = "the scanner node could not reach Artifactory";
			break;
		default:
			hint = statusHint(r.status);
		}
		StringBuilder sb = new StringBuilder(what).append(" failed: HTTP ").append(r.status);
		if (StringUtils.isNotBlank(code)) {
			sb.append(" ").append(code);
		}
		if (StringUtils.isNotBlank(message)) {
			sb.append(" - ").append(message);
		}
		if (StringUtils.isNotBlank(hint)) {
			sb.append(" (").append(hint).append(")");
		}
		return sb.toString();
	}

	private static String statusHint(int status) {
		String hint;
		switch (status) {
		case 401:
			hint = "check the API key credential";
			break;
		case 403:
			hint = "the API key belongs to a different tenant than this scanner node";
			break;
		case 404:
			hint = "scan not found for this API key";
			break;
		case 413:
			hint = "binary exceeds the server's upload limit";
			break;
		default:
			hint = "";
		}
		return hint;
	}

	/* The node enforces its own Artifactory base and repository; this catches obvious mistakes early. */
	static void validateArtifactUrl(String url) throws AbortException {
		URI uri;
		try {
			uri = new URI(url);
		} catch (URISyntaxException e) {
			throw new AbortException("artifactUrl is not a valid URL: " + e.getMessage());
		}
		String scheme = StringUtils.lowerCase(uri.getScheme());
		if (!("http".equals(scheme) || "https".equals(scheme)) || StringUtils.isBlank(uri.getHost())) {
			throw new AbortException("artifactUrl must be an http(s) Artifactory download URL.");
		}
		if (uri.getRawUserInfo() != null) {
			throw new AbortException("artifactUrl must not contain credentials; the scanner node uses its own"
					+ " Artifactory credential.");
		}
		String path = StringUtils.lowerCase(StringUtils.defaultString(uri.getPath()));
		if (!StringUtils.endsWithAny(path, BINARY_EXTENSIONS)) {
			throw new AbortException("artifactUrl must point to a .apk, .aab, .xapk or .ipa file.");
		}
	}

	static String artifactFileName(String url) {
		return StringUtils.substringAfterLast(URI.create(url).getPath(), "/");
	}

	private String resolveApiKey(Run<?, ?> run, PrintStream log) throws AbortException {
		String id = StringUtils.defaultIfBlank(apiCredentialsId, DEFAULT_CREDENTIALS_ID);
		StringCredentials creds = CredentialsProvider.findCredentialById(id, StringCredentials.class, run,
				Collections.emptyList());
		if (creds == null && !DEFAULT_CREDENTIALS_ID.equals(id)) {
			creds = CredentialsProvider.findCredentialById(DEFAULT_CREDENTIALS_ID, StringCredentials.class, run,
					Collections.emptyList());
		}
		if (creds == null) {
			throw new AbortException("Sec1 API key credential '" + id + "' not found (expected a Secret text credential).");
		}
		return creds.getSecret().getPlainText();
	}

	static FilePath resolveBinary(FilePath workspace, String pattern) throws IOException, InterruptedException {
		if (StringUtils.isBlank(pattern)) {
			throw new AbortException("Set binaryPath (the .apk/.aab/.ipa to scan, relative to the workspace)"
					+ " or artifactUrl (its Artifactory download URL).");
		}
		FilePath direct = workspace.child(pattern);
		if (!pattern.contains("*") && !pattern.contains("?") && direct.exists() && !direct.isDirectory()) {
			return direct;
		}
		FilePath[] matches = workspace.list(pattern);
		if (matches.length == 1) {
			return matches[0];
		}
		if (matches.length == 0) {
			throw new AbortException("No file matches binaryPath '" + pattern + "' in the workspace.");
		}
		StringBuilder sb = new StringBuilder("binaryPath '" + pattern + "' matches " + matches.length
				+ " files; it must match exactly one:");
		for (FilePath m : matches) {
			sb.append("\n  ").append(m.getRemote());
		}
		throw new AbortException(sb.toString());
	}

	private static String pluginVersion() {
		Jenkins j = Jenkins.getInstanceOrNull();
		PluginWrapper p = j == null ? null : j.getPluginManager().getPlugin("secone-sca-sast-security-scanner");
		return p == null ? "dev" : p.getVersion();
	}

	@Extension
	@Symbol("sec1MobileScan")
	public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

		@NonNull
		@Override
		public String getDisplayName() {
			return "Execute Sec1 Mobile Security Scan";
		}

		@SuppressWarnings("rawtypes")
		@Override
		public boolean isApplicable(Class<? extends AbstractProject> jobType) {
			return true;
		}

		@POST
		public ListBoxModel doFillScanTypeItems(@AncestorInPath Item item) {
			ListBoxModel items = new ListBoxModel();
			if (!canConfigure(item)) {
				return items;
			}
			items.add("OWASP (CI default)", "owasp");
			items.add("Quick", "quick");
			items.add("Compliance", "compliance");
			items.add("Deep", "deep");
			return items;
		}

		private static boolean canConfigure(Item item) {
			return item == null ? Jenkins.get().hasPermission(Jenkins.ADMINISTER) : item.hasPermission(Item.CONFIGURE);
		}
	}
}
