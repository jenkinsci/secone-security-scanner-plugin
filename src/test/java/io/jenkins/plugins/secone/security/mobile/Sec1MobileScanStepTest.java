package io.jenkins.plugins.secone.security.mobile;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertTrue;

import java.io.IOException;
import java.io.OutputStream;
import java.net.InetSocketAddress;
import java.nio.charset.StandardCharsets;
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

@WithJenkins
class Sec1MobileScanStepTest {

	private static final String SCAN_ID = "a564cd4f-8fe8-407e-8277-08c408f93ea7";
	private static final String SHA = "cf76327f24a9b18af2a0e44d7634bbcdf93664d9c78a2695e050393fcfbb5e8b";

	private HttpServer server;
	private String baseUrl;
	/** Scan records returned by successive status polls; the last one repeats. */
	private final Deque<JSONObject> polls = new ArrayDeque<>();
	private final List<String> submitBodies = new ArrayList<>();
	private final AtomicInteger deletes = new AtomicInteger();
	private int submitStatus = 201;
	/** Mimics the server race: the first cancel is acknowledged but the scan keeps running. */
	private boolean ignoreFirstCancel = false;
	private volatile boolean cancelled = false;
	private int totalFindings = 0;

	@BeforeEach
	void startServer() throws IOException {
		Sec1MobileScanStep.minPollSeconds = 0;
		server = HttpServer.create(new InetSocketAddress("127.0.0.1", 0), 0);
		server.createContext("/api/v1/scans", this::handle);
		server.start();
		baseUrl = "http://127.0.0.1:" + server.getAddress().getPort();
	}

	@AfterEach
	void stopServer() {
		server.stop(0);
		Sec1MobileScanStep.minPollSeconds = 10;
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
			if (submitStatus != 201) {
				reply(ex, submitStatus, new JSONObject().put("error", "file_too_large").put("message", "over limit"));
				return;
			}
			reply(ex, 201, record("pending", null));
		} else if ("DELETE".equals(method)) {
			int n = deletes.incrementAndGet();
			cancelled = !(ignoreFirstCancel && n == 1);
			reply(ex, 200, record("cancelled", null));
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

		j.assertLogContains("Quality Gate           PASSED", b);
		j.assertLogContains("/mobile-security/applications/cf76327f24a9?scan=" + SCAN_ID, b);
		j.assertLogContains("Findings Archived      sec1-mobile-findings.json (650 findings)", b);
		assertNotNull(b.getArtifactManager().root().child("sec1-mobile-findings.json"));
		JSONObject archived = new JSONObject(new String(
				b.getArtifactManager().root().child("sec1-mobile-findings.json").open().readAllBytes(),
				StandardCharsets.UTF_8));
		assertEquals(650, archived.getInt("count"));
	}

	@Test
	void highFindingsFailTheBuildByDefault(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(0, 3, 0, 0)));
		FreeStyleBuild b = j.buildAndAssertStatus(Result.FAILURE, project(j, step(), "app/build/a.apk"));
		j.assertLogContains("3 High finding(s) at or above the fail-on severity (High)", b);
	}

	@Test
	void unstableInsteadOfFail(JenkinsRule j) throws Exception {
		polls.add(record("completed", sev(1, 0, 0, 0)));
		Sec1MobileScanStep s = step();
		s.setUnstableInsteadOfFail(true);
		j.buildAndAssertStatus(Result.UNSTABLE, project(j, s, "app/build/a.apk"));
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

	@Test
	void configRoundTripKeepsEmptyLimitsUnset(JenkinsRule j) throws Exception {
		Sec1MobileScanStep s = new Sec1MobileScanStep("SEC1_API_KEY", "app/*.apk");
		s.setMaxHigh(5);
		s.setEnvironment("prod");
		FreeStyleProject p = j.createFreeStyleProject();
		p.getBuildersList().add(s);
		p = j.configRoundtrip(p);
		Sec1MobileScanStep after = p.getBuildersList().get(Sec1MobileScanStep.class);
		assertEquals("app/*.apk", after.getBinaryPath());
		assertEquals(Integer.valueOf(5), after.getMaxHigh());
		assertNull(after.getMaxCritical());
		assertNull(after.getMinScore());
		assertEquals("prod", after.getEnvironment());
		assertEquals("High", after.getFailOnSeverity());
		assertEquals("owasp", after.getScanType());
		assertTrue(after.isArchiveFindings());
	}
}
