package io.jenkins.plugins.secone.security.mobile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
import java.security.MessageDigest;
import java.util.ArrayDeque;
import java.util.ArrayList;
import java.util.Deque;
import java.util.List;
import java.util.concurrent.atomic.AtomicInteger;

import org.json.JSONArray;
import org.json.JSONObject;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.jvnet.hudson.test.JenkinsRule;
import org.jvnet.hudson.test.TestBuilder;
import org.jvnet.hudson.test.junit.jupiter.WithJenkins;

import com.cloudbees.plugins.credentials.CredentialsScope;
import com.cloudbees.plugins.credentials.SystemCredentialsProvider;
import com.sun.net.httpserver.HttpExchange;
import com.sun.net.httpserver.HttpServer;

import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.FreeStyleBuild;
import hudson.model.FreeStyleProject;
import hudson.model.Result;
import hudson.util.Secret;
import org.jenkinsci.plugins.plaincredentials.impl.StringCredentialsImpl;
import io.jenkins.plugins.secone.security.pojo.Threshold;

@WithJenkins
class Sec1MobileScanStepTest {

	private static final String SCAN_ID = "a564cd4f-8fe8-407e-8277-08c408f93ea7";
	private static final String SHA = "cf76327f24a9b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b";

	private HttpServer server;
	private String baseUrl;
	/** Scan records returned by successive status polls; the last one repeats. */
	private final Deque<JSONObject> polls = new ArrayDeque<>();
	private final List<String> submitBodies = new ArrayList<>();
	private final List<String> submitTypes = new ArrayList<>();
	private final AtomicInteger deletes = new AtomicInteger();
	private int submitStatus = 201;
	private String submitError = "file_too_large";
	/** How many submissions fail with submitStatus before the server accepts one. */
	private int submitFailures = Integer.MAX_VALUE;
	/** Mimics the server race: the first cancel is acknowledged but the scan keeps running. */
	private boolean ignoreFirstCancel = false;
	private volatile boolean cancelled = false;
	private int totalFindings = 0;
	/** Replies to successive PDF report requests on the base URL; the last one repeats. */
	private final Deque<Integer> reportReplies = new ArrayDeque<>();
	private final List<String> reportPaths = new ArrayList<>();
	private static final byte[] PDF = "%PDF-1.7 sec1 report".getBytes(StandardCharsets.ISO_8859_1);

	@BeforeEach
	void startServer() throws IOException {
		Sec1MobileScanStep.minPollSeconds = 0;
		Sec1MobileScanStep.submitRetrySeconds = 0;
		Sec1MobileScanStep.reportRetrySeconds = 0;
		Sec1MobileScanStep.reportFallbackBase = null;
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/api/v1/scans", this::handle);
		server.createContext("/control-plane/api/v1/scans", this::handle);
		server.start();
		baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
	}

	@AfterEach
	void stopServer() {
		server.stop(0);
		Sec1MobileScanStep.minPollSeconds = 10;
		Sec1MobileScanStep.submitRetrySeconds = 10;
		Sec1MobileScanStep.reportRetrySeconds = 10;
		Sec1MobileScanStep.reportFallbackBase = Sec1MobileScanStep.DEFAULT_BASE_URL;
	}

	private void handle(HttpExchange ex) throws IOException {
		if (!"test-key".equals(ex.getRequestHeaders().getFirst("sec1-api-key"))) {
			reply(ex, 401, new JSONObject().put("error", "unauthenticated"));
			return;
		}
		String path = ex.getRequestURI().getPath();
		String method = ex.getRequestMethod();
		if ("POST".equals(method) && path.equals("/api/v1/scans")) {
			submitBodies.add(new String(ex.getRequestBody().readAllBytes(), StandardCharsets.ISO_8859_1));
			submitTypes.add(ex.getRequestHeaders().getFirst("Content-Type"));
			if (submitStatus != 201 && submitBodies.size() <= submitFailures) {
				reply(ex, submitStatus, new JSONObject().put("code", submitError).put("message", "over limit"));
				return;
			}
			reply(ex, 201, record("pending", null));
		} else if ("DELETE".equals(method)) {
			int n = deletes.incrementAndGet();
			cancelled = !(ignoreFirstCancel && n == 1);
			reply(ex, 200, record("cancelled", null));
		} else if (path.endsWith("/reports/executive")) {
			reportPaths.add(path);
			int status = path.startsWith("/control-plane") ? 200
					: (reportReplies.size() > 1 ? reportReplies.poll() : reportReplies.peek());
			if (status == 200) {
				ex.getResponseHeaders().add("Content-Type", "application/pdf");
				ex.sendResponseHeaders(200, PDF.length);
				try (OutputStream os = ex.getResponseBody()) {
					os.write(PDF);
				}
			} else if (status == 299) {
				reply(ex, 200, new JSONObject().put("detail", "not a pdf"));
			} else {
				reply(ex, status, new JSONObject().put("code", "report_error"));
			}
		} else if (path.endsWith("/findings")) {
			String q = ex.getRequestURI().getQuery();
			int offset = Integer.parseInt(q.replaceAll(".*offset=(\\d+).*", "$1"));
			int n = Math.max(0, Math.min(500, totalFindings - offset));
			JSONArray findings = new JSONArray();
			for (int i = 0; i < n; i++) {
				findings.put(new JSONObject().put("title", "finding " + (offset + i)).put("severity", "High"));
			}
			reply(ex, 200, new JSONObject().put("scan_id", SCAN_ID).put("limit", 500).put("offset", offset)
					.put("count", n).put("findings", findings));
		} else if (cancelled) {
			reply(ex, 200, record("cancelled", null));
		} else {
			JSONObject next = polls.size() > 1 ? polls.poll() : polls.peek();
			if (next.has("_http")) {
				reply(ex, next.getInt("_http"), new JSONObject().put("error", "unavailable"));
			} else {
				reply(ex, 200, next);
			}
		}
	}

	private static void reply(HttpExchange ex, int status, JSONObject body) throws IOException {
		byte[] bytes = body.toString().getBytes(StandardCharsets.UTF_8);
		ex.getResponseHeaders().add("Content-Type", "application/json");
		ex.sendResponseHeaders(status, bytes.length);
		try (OutputStream os = ex.getResponseBody()) {
			os.write(bytes);
		}
	}

	private static JSONObject record(String status, JSONObject bySeverity) {
		JSONObject summary = new JSONObject().put("total_findings", 0).put("aggregate_score", 55).put("score_band", "fair")
				.put("by_severity", bySeverity == null ? JSONObject.NULL : bySeverity);
		return new JSONObject().put("id", SCAN_ID).put("status", status).put("progress", 50)
				.put("phase", "android.static_analysis").put("engine_version", "0.4.0")
				.put("input", new JSONObject().put("sha256", SHA)).put("summary", summary)
				.put("error", "failed".equals(status) || "partial".equals(status) ? "scanner_lost" : "");
	}

	private static JSONObject sev(int critical, int high, int medium, int low) {
		return new JSONObject().put("Critical", critical).put("High", high).put("Medium", medium).put("Low", low);
	}

	private FreeStyleProject project(JenkinsRule j, Sec1MobileScanStep step, String... files) throws IOException {
		SystemCredentialsProvider.getInstance().getCredentials().add(new StringCredentialsImpl(CredentialsScope.GLOBAL,
				"SEC1_API_KEY", "", Secret.fromString("test-key")));
		FreeStyleProject p = j.createFreeStyleProject("mobile-app");
		p.getBuildersList().add(new TestBuilder() {
			@Override
			public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener)
					throws InterruptedException, IOException {
				for (String f : files) {
					build.getWorkspace().child(f).write("APK-BYTES-" + f, "UTF-8");
				}
				return true;
			}
		});
		step.setBaseUrl(baseUrl);
		step.setPollIntervalSeconds(1);
		p.getBuildersList().add(step);
		return p;
	}

	private static Sec1MobileScanStep step() {
		return new Sec1MobileScanStep("SEC1_API_KEY", "app/build/*.apk");
	}

	@Test
	void completedScanPassesGateSubmitsMetadataAndArchivesAllFindings(JenkinsRule j) throws Exception {
		polls.add(record("running", null));
		polls.add(record("completed", sev(0, 0, 4, 9)));
		totalFindings = 650;
		Sec1MobileScanStep s = step();
		s.setEnvironment("uat");
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, s, "app/build/app-release.apk"));

		String body = submitBodies.get(0);
		assertTrue(body.contains("name=\"app_name\"\r\n\r\napp-release\r\n"));
		assertTrue(body.contains("name=\"version\"\r\n\r\n1\r\n"));
		assertTrue(body.contains("name=\"environment\"\r\n\r\nuat\r\n"));
		assertTrue(body.contains("name=\"scan_type\"\r\n\r\nowasp\r\n"));
		assertTrue(body.contains("name=\"source\"\r\n\r\njenkins:mobile-app#1\r\n"));
		assertTrue(body.contains("filename=\"app-release.apk\"\r\nContent-Type: application/octet-stream\r\n\r\nAPK-BYTES-app/build/app-release.apk"));

		j.assertLogContains("Threshold              Disabled", b);
		j.assertLogContains("/mobile-security/applications/cf76327f24a9?scan=" + SCAN_ID, b);
		j.assertLogContains("Findings Archived      sec1-mobile-findings.json (650 findings)", b);
		assertNotNull(b.getArtifactManager().root().child("sec1-mobile-findings.json"));
		JSONObject archived = new JSONObject(new String(
				b.getArtifactManager().root().child("sec1-mobile-findings.json").open().readAllBytes(),
				StandardCharsets.UTF_8));
		assertEquals(650, archived.getInt("count"));
	}

	@Test
	void findingsDoNotAffectTheBuildWithoutAThreshold(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(9, 9, 9, 9)));
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, step(), "app/build/a.apk"));
		j.assertLogContains("Threshold              Disabled", b);
	}

	@Test
	void thresholdBreachFailsTheBuildByDefault(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 3, 0, 0)));
		Sec1MobileScanStep s = step();
		s.setThreshold(new Threshold("0", "2", "", "", null));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, s, "app/build/a.apk"));
		j.assertLogContains("High Vulnerability Threshold breached. Found: 3, Allowed: 2", b);
		j.assertLogContains("Threshold              BREACHED (action: fail)", b);
	}

	@Test
	void actionOnThresholdBreachedUnstableOverridesBlockAction(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(1, 0, 0, 0)));
		Sec1MobileScanStep s = step();
		s.setThreshold(new Threshold("0", "", "", "", "fail"));
		s.setActionOnThresholdBreached("unstable");
		j.buildAndAssertStatus(Result.UNSTABLE, project(j, s, "app/build/a.apk"));
	}

	@Test
	void continueActionKeepsTheBuildGreen(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(4, 0, 0, 0)));
		Sec1MobileScanStep s = step();
		s.setThreshold(new Threshold("0", "", "", "", "continue"));
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, s, "app/build/a.apk"));
		j.assertLogContains("Critical Vulnerability Threshold breached. Found: 4, Allowed: 0", b);
		j.assertLogContains("BREACHED (action: continue)", b);
	}

	@Test
	void applyThresholdFalseDisablesAConfiguredThreshold(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(4, 4, 0, 0)));
		Sec1MobileScanStep s = step();
		s.setThreshold(new Threshold("0", "0", "", "", "fail"));
		s.setApplyThreshold(false);
		j.buildAndAssertSuccess(project(j, s, "app/build/a.apk"));
	}

	@Test
	void minScoreAloneAppliesTheAction(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		Sec1MobileScanStep s = step();
		s.setMinScore(70);
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, s, "app/build/a.apk"));
		j.assertLogContains("Score threshold breached. Found: 55, Minimum: 70", b);
	}

	@Test
	void partialScanIsResubmittedOnce(JenkinsRule j) throws Exception {
		polls.add(record("partial", null));
		polls.add(record("completed", sev(0, 0, 0, 0)));
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, step(), "app/build/a.apk"));
		assertEquals(2, submitBodies.size());
		j.assertLogContains("resubmitting once", b);
	}

	@Test
	void partialAfterAStaleScanTimeoutIsNotResubmitted(JenkinsRule j) throws Exception {
		polls.add(record("partial", null).put("error", "stale_scan_timeout"));
		polls.add(record("completed", sev(0, 0, 0, 0)));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, step(), "app/build/a.apk"));
		assertEquals(1, submitBodies.size());
		j.assertLogContains("stopped it at its time limit", b);
		j.assertLogContains("ended 'partial': stale_scan_timeout", b);
		j.assertLogContains("raise it with the node operator", b);
	}

	@Test
	void resubmitPartialFalseNeverResubmits(JenkinsRule j) throws Exception {
		polls.add(record("partial", null));
		polls.add(record("completed", sev(0, 0, 0, 0)));
		Sec1MobileScanStep s = step();
		s.setResubmitPartial(false);
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, s, "app/build/a.apk"));
		assertEquals(1, submitBodies.size());
		j.assertLogContains("not resubmitting (resubmitPartial is false)", b);
	}

	@Test
	void timeoutReasonsAreRecognised() {
		assertTrue(Sec1MobileScanStep.isTimeoutReason("stale_scan_timeout"));
		assertTrue(Sec1MobileScanStep.isTimeoutReason("completed:partial(timed_out)"));
		assertFalse(Sec1MobileScanStep.isTimeoutReason("scanner_lost"));
		assertFalse(Sec1MobileScanStep.isTimeoutReason(""));
	}

	@Test
	void failedScanFailsTheBuildWithTheServerReason(JenkinsRule j) throws Exception {
		polls.add(record("failed", null));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, step(), "app/build/a.apk"));
		j.assertLogContains("ended 'failed': scanner_lost", b);
	}

	@Test
	void transientServerErrorsDuringPollingAreRetried(JenkinsRule j) throws Exception {
		polls.add(new JSONObject().put("_http", 503));
		polls.add(record("completed", sev(0, 0, 0, 0)));
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, step(), "app/build/a.apk"));
		j.assertLogContains("Status check returned HTTP 503", b);
	}

	@Test
	void submissionErrorsAreReportedAndNotRetried(JenkinsRule j) throws Exception {
		submitStatus = 413;
		polls.add(record("completed", null));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, step(), "app/build/a.apk"));
		j.assertLogContains("Scan submission failed: HTTP 413 file_too_large - over limit", b);
		assertEquals(1, submitBodies.size());
	}

	@Test
	void wrongApiKeyFailsFast(JenkinsRule j) throws Exception {
		polls.add(record("completed", null));
		FreeStyleProject p = project(j, step(), "app/build/a.apk");
		SystemCredentialsProvider.getInstance().getCredentials().clear();
		SystemCredentialsProvider.getInstance().getCredentials().add(new StringCredentialsImpl(
				CredentialsScope.GLOBAL, "SEC1_API_KEY", "", Secret.fromString("wrong")));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, p);
		j.assertLogContains("HTTP 401", b);
		j.assertLogContains("check the API key credential", b);
	}

	@Test
	void binaryPathMustMatchExactlyOneFile(JenkinsRule j) throws Exception {
		polls.add(record("completed", null));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE,
				project(j, step(), "app/build/a.apk", "app/build/b.apk"));
		j.assertLogContains("matches 2 files; it must match exactly one", b);
		assertTrue(submitBodies.isEmpty());
	}

	@Test
	void abortingTheBuildCancelsTheScan(JenkinsRule j) throws Exception {
		polls.add(record("running", null));
		FreeStyleProject p = project(j, step(), "app/build/a.apk");
		FreeStyleBuild b = p.scheduleBuild2(0).waitForStart();
		long until = System.currentTimeMillis() + 30_000;
		while (submitBodies.isEmpty() && System.currentTimeMillis() < until) {
			Thread.sleep(200);
		}
		Thread.sleep(1500);
		b.getExecutor().interrupt();
		j.waitForCompletion(b);
		j.assertBuildStatus(Result.ABORTED, b);
		j.assertLogContains("Build aborted; cancelling Sec1 mobile scan " + SCAN_ID, b);
		Thread.sleep(7000);
		assertEquals(1, deletes.get());
	}

	@Test
	void cancelIsRepeatedWhenTheServerRevivesTheScan(JenkinsRule j) throws Exception {
		ignoreFirstCancel = true;
		polls.add(record("running", null));
		FreeStyleProject p = project(j, step(), "app/build/a.apk");
		FreeStyleBuild b = p.scheduleBuild2(0).waitForStart();
		long until = System.currentTimeMillis() + 30_000;
		while (submitBodies.isEmpty() && System.currentTimeMillis() < until) {
			Thread.sleep(200);
		}
		Thread.sleep(1500);
		b.getExecutor().interrupt();
		j.waitForCompletion(b);
		j.assertBuildStatus(Result.ABORTED, b);
		long wait = System.currentTimeMillis() + 15_000;
		while (deletes.get() < 2 && System.currentTimeMillis() < wait) {
			Thread.sleep(250);
		}
		assertEquals(2, deletes.get());
		assertTrue(cancelled);
	}

	private static final String ARTIFACT_URL =
			"https://artifactory.example.com/artifactory/mobile-releases/my-app/42/app-release.apk";

	private static Sec1MobileScanStep artifactStep(String binaryPath) {
		Sec1MobileScanStep s = new Sec1MobileScanStep("SEC1_API_KEY", binaryPath);
		s.setArtifactUrl(ARTIFACT_URL);
		return s;
	}

	private static String sha256(String text) throws Exception {
		StringBuilder hex = new StringBuilder();
		for (byte b : MessageDigest.getInstance("SHA-256").digest(text.getBytes(StandardCharsets.UTF_8))) {
			hex.append(String.format("%02x", b));
		}
		return hex.toString();
	}

	@Test
	void artifactUrlIsSubmittedAsJsonWithoutAnUpload(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		Sec1MobileScanStep s = artifactStep(null);
		s.setArtifactSha256(SHA.toUpperCase());
		s.setEnvironment("uat");
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, s));

		assertTrue(submitTypes.get(0).startsWith("application/json"));
		JSONObject body = new JSONObject(submitBodies.get(0));
		assertEquals(ARTIFACT_URL, body.getString("artifact_url"));
		assertEquals(SHA, body.getString("artifact_sha256"));
		assertEquals("app-release", body.getString("app_name"));
		assertEquals("1", body.getString("version"));
		assertEquals("uat", body.getString("environment"));
		assertEquals("owasp", body.getString("scan_type"));
		assertEquals("jenkins:mobile-app#1", body.getString("source"));
		assertFalse(body.has("file"));
		assertFalse(body.has("engagement_id"));
		j.assertLogContains("Artifact URL           " + ARTIFACT_URL, b);
	}

	@Test
	void artifactUrlWithBinaryPathSendsTheWorkspaceChecksumOnly(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, artifactStep("app/build/*.apk"), "app/build/a.apk"));
		JSONObject body = new JSONObject(submitBodies.get(0));
		assertEquals(sha256("APK-BYTES-app/build/a.apk"), body.getString("artifact_sha256"));
		assertFalse(submitBodies.get(0).contains("APK-BYTES"));
		assertEquals("app-release", body.getString("app_name"));
		j.assertLogContains("(from ", b);
	}

	@Test
	void artifactUrlWithoutChecksumOmitsIt(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, artifactStep(null)));
		assertFalse(new JSONObject(submitBodies.get(0)).has("artifact_sha256"));
		j.assertLogContains("not set (verified against Artifactory's checksum)", b);
	}

	@Test
	void invalidArtifactUrlsAreRefusedBeforeSubmitting(JenkinsRule j) throws Exception {
		polls.add(record("completed", null));
		Sec1MobileScanStep s = artifactStep(null);
		s.setArtifactUrl("https://artifactory.example.com/artifactory/mobile-releases/app.zip");
		FreeStyleProject p = project(j, s);
		j.assertLogContains("must point to a .apk, .aab, .xapk or .ipa file", j.buildAndAssertStatus(Result.FAILURE, p));

		s.setArtifactUrl("https://ci:secret@artifactory.example.com/artifactory/mobile-releases/app.apk");
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, p);
		j.assertLogContains("must not contain credentials", b);
		j.assertLogNotContains("secret@", b);

		s.setArtifactUrl(ARTIFACT_URL);
		s.setArtifactSha256("abc");
		j.assertLogContains("64-character hex SHA-256", j.buildAndAssertStatus(Result.FAILURE, p));
		assertTrue(submitBodies.isEmpty());
	}

	@Test
	void artifactoryUnreachableIsRetried(JenkinsRule j) throws Exception {
		submitStatus = 502;
		submitError = "artifactory_unreachable";
		submitFailures = 1;
		polls.add(record("completed", sev(0, 0, 0, 0)));
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, artifactStep(null)));
		assertEquals(2, submitBodies.size());
		j.assertLogContains("HTTP 502 artifactory_unreachable", b);
		j.assertLogContains("the scanner node could not reach Artifactory", b);
	}

	@Test
	void checksumMismatchFailsWithoutRetry(JenkinsRule j) throws Exception {
		submitStatus = 422;
		submitError = "artifact_checksum_mismatch";
		polls.add(record("completed", null));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, artifactStep(null)));
		assertEquals(1, submitBodies.size());
		j.assertLogContains("HTTP 422 artifact_checksum_mismatch", b);
		j.assertLogContains("investigate the publish step", b);
	}

	@Test
	void neitherBinaryPathNorArtifactUrlFails(JenkinsRule j) throws Exception {
		polls.add(record("completed", null));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE,
				project(j, new Sec1MobileScanStep("SEC1_API_KEY", null)));
		j.assertLogContains("Set binaryPath", b);
		assertTrue(submitBodies.isEmpty());
	}

	@Test
	void mobileBaseUrlComesFromItsOwnVariableNotTheInstanceUrl(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		hudson.slaves.EnvironmentVariablesNodeProperty global = new hudson.slaves.EnvironmentVariablesNodeProperty();
		global.getEnvVars().put("SEC1_MOBILE_BASE_URL", baseUrl + "/");
		global.getEnvVars().put("SEC1_INSTANCE_URL", "http://127.0.0.1:1/control-plane");
		j.jenkins.getGlobalNodeProperties().add(global);
		FreeStyleProject p = project(j, step(), "app/build/a.apk");
		p.getBuildersList().get(Sec1MobileScanStep.class).setBaseUrl(null);
		FreeStyleBuild b = j.buildAndAssertSuccess(p);
		j.assertLogContains("Base URL               " + baseUrl + " (SEC1_MOBILE_BASE_URL)", b);
		assertEquals(1, submitBodies.size());
	}

	@Test
	void unreachableApiNamesTheErrorAndTheUrl(JenkinsRule j) throws Exception {
		polls.add(record("completed", null));
		FreeStyleProject p = project(j, artifactStep(null));
		String dead = "http://127.0.0.1:1/ai-sast-mobile";
		p.getBuildersList().get(Sec1MobileScanStep.class).setBaseUrl(dead);
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, p);
		j.assertLogContains("Scan submission failed (ConnectException", b);
		j.assertLogNotContains("(null)", b);
		j.assertLogContains("Could not reach the Sec1 Mobile Security API at " + dead, b);
		j.assertLogContains("SEC1_MOBILE_BASE_URL", b);
	}

	@Test
	void describeExceptionNamesTypesWhenMessagesAreMissing() {
		IOException e = new IOException(new java.net.ConnectException());
		assertEquals("IOException: java.net.ConnectException",
				Sec1MobileScanStep.describeException(e));
		assertEquals("ConnectException: Connection refused",
				Sec1MobileScanStep.describeException(new java.net.ConnectException("Connection refused")));
	}

	@Test
	void pdfReportIsNotRequestedByDefault(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		j.buildAndAssertSuccess(project(j, step(), "app/build/a.apk"));
		assertTrue(reportPaths.isEmpty());
	}

	@Test
	void scanRunsOnAnAgentWithTheKeySentAsASecret(JenkinsRule j) throws Exception {
		// The HTTP calls run on the agent, so the callables (holding the key
		// as a Secret) are serialized over the remoting channel here.
		polls.add(record("completed", sev(0, 0, 0, 0)));
		reportReplies.add(200);
		Sec1MobileScanStep s = step();
		s.setArchiveReport(true);
		FreeStyleProject p = project(j, s, "app/build/a.apk");
		p.setAssignedNode(j.createOnlineSlave());
		FreeStyleBuild b = j.buildAndAssertSuccess(p);
		j.assertLogContains("Scan Id", b);
		j.assertLogContains("Report Archived        sec1-mobile-report.pdf", b);
		assertEquals(1, reportPaths.size());
	}

	@Test
	void pdfReportIsArchivedOnceGenerated(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(1, 0, 0, 0)));
		reportReplies.add(202);
		reportReplies.add(200);
		Sec1MobileScanStep s = step();
		s.setArchiveReport(true);
		s.setThreshold(new Threshold("0", "", "", "", "fail"));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, s, "app/build/a.apk"));
		assertEquals(2, reportPaths.size());
		assertEquals("/api/v1/scans/" + SCAN_ID + "/reports/executive", reportPaths.get(0));
		j.assertLogContains("Report Archived        sec1-mobile-report.pdf", b);
		byte[] archived = b.getArtifactManager().root().child("sec1-mobile-report.pdf").open().readAllBytes();
		assertEquals(new String(PDF, StandardCharsets.ISO_8859_1), new String(archived, StandardCharsets.ISO_8859_1));
	}

	@Test
	void pdfReportFallsBackToTheControlPlaneWhenNodesDoNotServeIt(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		reportReplies.add(404);
		Sec1MobileScanStep.reportFallbackBase = baseUrl + "/control-plane";
		Sec1MobileScanStep s = step();
		s.setArchiveReport(true);
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, s, "app/build/a.apk"));
		assertEquals(2, reportPaths.size());
		assertTrue(reportPaths.get(1).startsWith("/control-plane/"));
		j.assertLogContains("Report Archived", b);
	}

	@Test
	void pdfReportFailuresOnlyWarn(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		reportReplies.add(500);
		Sec1MobileScanStep s = step();
		s.setArchiveReport(true);
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, s, "app/build/a.apk"));
		j.assertLogContains("WARNING: PDF report not archived: Report download failed: HTTP 500 report_error", b);
		j.assertLogContains("The build result is not affected", b);
		assertNull(b.getArtifactManager().root().child("sec1-mobile-report.pdf").isFile() ? "" : null);
	}

	@Test
	void anAnswerThatIsNotAPdfIsNotArchived(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 0, 0, 0)));
		reportReplies.add(299);
		Sec1MobileScanStep s = step();
		s.setArchiveReport(true);
		FreeStyleBuild b = j.buildAndAssertSuccess(project(j, s, "app/build/a.apk"));
		j.assertLogContains("the server did not return a PDF", b);
		assertFalse(b.getArtifactManager().root().child("sec1-mobile-report.pdf").isFile());
	}

	@Test
	void configRoundTripKeepsThresholdAndUnsetFields(JenkinsRule j) throws Exception {
		Sec1MobileScanStep s = new Sec1MobileScanStep("SEC1_API_KEY", "app/*.apk");
		s.setThreshold(new Threshold("0", "5", "", "", "unstable"));
		s.setEnvironment("prod");
		s.setArtifactUrl(ARTIFACT_URL);
		s.setArtifactSha256(SHA);
		FreeStyleProject p = j.createFreeStyleProject();
		p.getBuildersList().add(s);
		p = j.configRoundtrip(p);
		Sec1MobileScanStep after = p.getBuildersList().get(Sec1MobileScanStep.class);
		assertEquals("app/*.apk", after.getBinaryPath());
		assertEquals(ARTIFACT_URL, after.getArtifactUrl());
		assertTrue(after.isResubmitPartial());
		assertFalse(after.isArchiveReport());
		assertEquals(SHA, after.getArtifactSha256());
		assertNotNull(after.getThreshold());
		assertEquals("0", after.getThreshold().getCriticalThreshold());
		assertEquals("5", after.getThreshold().getHighThreshold());
		assertEquals("unstable", after.getThreshold().getStatusAction());
		assertNull(after.getMinScore());
		assertEquals("prod", after.getEnvironment());
		assertEquals("owasp", after.getScanType());
		assertTrue(after.isArchiveFindings());

		Sec1MobileScanStep none = new Sec1MobileScanStep("SEC1_API_KEY", "app/*.apk");
		FreeStyleProject q = j.createFreeStyleProject();
		q.getBuildersList().add(none);
		q = j.configRoundtrip(q);
		assertNull(q.getBuildersList().get(Sec1MobileScanStep.class).getThreshold());
		assertNull(q.getBuildersList().get(Sec1MobileScanStep.class).getArtifactUrl());
	}
}
