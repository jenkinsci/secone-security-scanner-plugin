package io.jenkins.plugins.secone.security.mobile;

import java.io.IOException;
import java.io.PrintStream;
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
	private static final String DEFAULT_CREDENTIALS_ID = "SEC1_API_KEY";
	private static final int FINDINGS_PAGE = 500;
	private static final int MAX_BACKOFF_SECONDS = 60;

	/** Lower bound on the poll interval; lowered only by tests. */
	static int minPollSeconds = 10;

	private final String apiCredentialsId;
	private final String binaryPath;
	private String baseUrl;
	private String appName;
	private String appVersion;
	private String environment;
	private String scanType;
	private String source;
	private String engagementId;
	private Integer pollIntervalSeconds;
	private Integer timeoutMinutes;
	private String failOnSeverity;
	private Integer maxCritical;
	private Integer maxHigh;
	private Integer maxMedium;
	private Integer minScore;
	private boolean unstableInsteadOfFail;
	private Boolean archiveFindings;

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

	public String getFailOnSeverity() {
		return StringUtils.defaultIfBlank(failOnSeverity, "High");
	}

	@DataBoundSetter
	public void setFailOnSeverity(String failOnSeverity) {
		this.failOnSeverity = StringUtils.trimToNull(failOnSeverity);
	}

	public Integer getMaxCritical() {
		return maxCritical;
	}

	@DataBoundSetter
	public void setMaxCritical(Integer maxCritical) {
		this.maxCritical = maxCritical;
	}

	public Integer getMaxHigh() {
		return maxHigh;
	}

	@DataBoundSetter
	public void setMaxHigh(Integer maxHigh) {
		this.maxHigh = maxHigh;
	}

	public Integer getMaxMedium() {
		return maxMedium;
	}

	@DataBoundSetter
	public void setMaxMedium(Integer maxMedium) {
		this.maxMedium = maxMedium;
	}

	public Integer getMinScore() {
		return minScore;
	}

	@DataBoundSetter
	public void setMinScore(Integer minScore) {
		this.minScore = minScore;
	}

	public boolean isUnstableInsteadOfFail() {
		return unstableInsteadOfFail;
	}

	@DataBoundSetter
	public void setUnstableInsteadOfFail(boolean unstableInsteadOfFail) {
		this.unstableInsteadOfFail = unstableInsteadOfFail;
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
		String base = StringUtils.removeEnd(StringUtils.defaultIfBlank(env.expand(StringUtils.defaultString(baseUrl)),
				StringUtils.defaultIfBlank(env.get("SEC1_MOBILE_BASE_URL"), DEFAULT_BASE_URL)), "/");
		String consoleUrl = StringUtils.removeEnd(
				StringUtils.defaultIfBlank(env.get("SEC1_DASHBOARD_URL"), DEFAULT_CONSOLE_URL), "/");
		FilePath binary = resolveBinary(workspace, env.expand(binaryPath));
		String userAgent = "Sec1Jenkins/" + pluginVersion();
		VirtualChannel channel = workspace.getChannel();

		Map<String, String> fields = new LinkedHashMap<>();
		fields.put("app_name", StringUtils.defaultIfBlank(env.expand(StringUtils.defaultString(appName)),
				StringUtils.substringBeforeLast(binary.getName(), ".")));
		fields.put("version", StringUtils.defaultIfBlank(env.expand(StringUtils.defaultString(appVersion)),
				env.get("BUILD_NUMBER")));
		fields.put("environment", env.expand(StringUtils.defaultString(environment)));
		fields.put("scan_type", getScanType());
		fields.put("engagement_id", env.expand(StringUtils.defaultString(engagementId)));
		fields.put("source", StringUtils.left(StringUtils.defaultIfBlank(env.expand(StringUtils.defaultString(source)),
				"jenkins:" + env.get("JOB_NAME", "job") + "#" + env.get("BUILD_NUMBER", "0")), 200));

		log.println("Base URL               " + base);
		log.println("Binary                 " + binary.getRemote() + " (" + binary.length() + " bytes)");
		log.println("App                    " + fields.get("app_name") + " " + fields.get("version")
				+ (StringUtils.isNotBlank(fields.get("environment")) ? " [" + fields.get("environment") + "]" : ""));
		log.println("Scan Type              " + getScanType());

		JSONObject record = null;
		for (int attempt = 1; attempt <= 2; attempt++) {
			JSONObject created = submit(binary, base, apiKey, userAgent, fields, log);
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

			record = poll(channel, base, id, apiKey, userAgent, log);
			String status = record.optString("status");
			if ("partial".equals(status) && attempt == 1) {
				log.println("Scan ended 'partial' (" + record.optString("error", "no reason given")
						+ "); resubmitting once.");
				continue;
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
			throw new AbortException("Sec1 mobile scan " + id + " ended '" + status + "': "
					+ StringUtils.defaultIfBlank(record.optString("error", ""), "no reason given"));
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

		List<String> violations = MobileScanGate.evaluate(bySeverity, score, getFailOnSeverity(), maxCritical,
				maxHigh, maxMedium, minScore);
		if (violations.isEmpty()) {
			log.println("Quality Gate           PASSED");
			return;
		}
		log.println("Quality Gate           FAILED");
		for (String v : violations) {
			log.println("  - " + v);
		}
		if (unstableInsteadOfFail) {
			run.setResult(Result.UNSTABLE);
		} else {
			throw new AbortException("Sec1 mobile scan quality gate failed.");
		}
	}

	private JSONObject submit(FilePath binary, String base, String apiKey, String userAgent,
			Map<String, String> fields, PrintStream log) throws IOException, InterruptedException {
		log.println("Uploading binary...");
		MobileApi.Response r = binary.act(new MobileApi.Submit(base + "/api/v1/scans", apiKey, userAgent, fields));
		if (!r.isSuccess()) {
			// Not retried: a retry after a partially processed upload would start a second scan.
			throw new AbortException(describeError("Scan submission", r));
		}
		return new JSONObject(r.body);
	}

	private JSONObject poll(VirtualChannel channel, String base, String id, String apiKey, String userAgent,
			PrintStream log) throws IOException, InterruptedException {
		int interval = Math.max(minPollSeconds, getPollIntervalSeconds());
		long deadline = System.currentTimeMillis() + getTimeoutMinutes() * 60_000L;
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
					log.println("Status check failed (" + e.getMessage() + "); retrying.");
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

	static String describeError(String what, MobileApi.Response r) {
		String code = "";
		String message = "";
		try {
			JSONObject err = new JSONObject(r.body);
			code = err.optString("error", "");
			message = StringUtils.defaultIfBlank(err.optString("message", ""), err.optString("detail", ""));
		} catch (RuntimeException ignored) {
			message = StringUtils.left(StringUtils.defaultString(r.body).trim(), 200);
		}
		String hint;
		switch (r.status) {
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
			throw new AbortException("binaryPath is required: the .apk/.aab/.ipa to scan, relative to the workspace.");
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

		@POST
		public ListBoxModel doFillFailOnSeverityItems(@AncestorInPath Item item) {
			ListBoxModel items = new ListBoxModel();
			if (!canConfigure(item)) {
				return items;
			}
			items.add("High or above (default)", "High");
			items.add("Critical only", "Critical");
			items.add("Medium or above", "Medium");
			items.add("Any finding (Low or above)", "Low");
			items.add("Never (use limits / score only)", "None");
			return items;
		}

		private static boolean canConfigure(Item item) {
			return item == null ? Jenkins.get().hasPermission(Jenkins.ADMINISTER) : item.hasPermission(Item.CONFIGURE);
		}
	}
}
