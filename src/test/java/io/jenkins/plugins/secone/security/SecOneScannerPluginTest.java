package io.jenkins.plugins.secone.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertNull;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertNotNull;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.util.Map;

import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.junit.jupiter.api.AfterEach;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;
import org.junit.jupiter.api.extension.ExtendWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.jupiter.MockitoExtension;
import org.mockito.junit.jupiter.MockitoSettings;
import org.mockito.quality.Strictness;

import com.cloudbees.plugins.credentials.CredentialsProvider;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.FilePath;
import hudson.Launcher;
import hudson.model.AbstractBuild;
import hudson.model.BuildListener;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.util.Secret;
import io.jenkins.plugins.secone.security.object.factory.ObjectFactory;
import io.jenkins.plugins.secone.security.pojo.Threshold;
import jenkins.model.Jenkins;

@ExtendWith(MockitoExtension.class)
@MockitoSettings(strictness = Strictness.LENIENT)
public class SecOneScannerPluginTest {

	@Mock
	private AbstractBuild<?, ?> abstractBuild;

	@Mock
	private Run<?, ?> run;

	@Mock
	private FilePath filePath;

	@Mock
	private Launcher launcher;

	@Mock
	private BuildListener buildListener;

	private final TaskListener taskListener = Mockito.mock(TaskListener.class);

	@Mock
	private EnvVars envVars;

	private SecOneScannerPlugin plugin;

	@Mock
	private Jenkins jenkins;

	@Mock
	private org.apache.http.HttpEntity scaHttpEntity;

	@Mock
	private org.apache.http.HttpEntity scaStatusHttpEntity;

	@Mock
	private org.apache.http.HttpEntity sastHttpEntity;

	@Mock
	private org.apache.http.HttpEntity sastStatusHttpEntity;

	@Mock
	private ObjectFactory objectFactory;

	private MockedStatic<Jenkins> mockedJenkins;
	private MockedStatic<CredentialsProvider> mockedCredentialsProvider;

	private static String WORKSPACE_DIRECTORY_LOCATION;

	private static InputStream sampleScaReportStream;

	private static InputStream sampleSastReportStream;

	private static InputStream sampleInitiateSastScanResponseStream;

	private static InputStream sampleInitiateScaScanResponseStream;

	@BeforeEach
	public void setUp() throws Exception {

		WORKSPACE_DIRECTORY_LOCATION = new File("src/test/resources/test-data").getAbsolutePath();

		sampleScaReportStream = new FileInputStream(WORKSPACE_DIRECTORY_LOCATION + "/sampleapp-sca-report.txt");
		sampleSastReportStream = new FileInputStream(WORKSPACE_DIRECTORY_LOCATION + "/sampleapp-sast-report.txt");

		sampleInitiateScaScanResponseStream = new FileInputStream(
				WORKSPACE_DIRECTORY_LOCATION + "/sample-initiate-sca-scan-response.txt");
		sampleInitiateSastScanResponseStream = new FileInputStream(
				WORKSPACE_DIRECTORY_LOCATION + "/sample-initiate-sast-scan-response.txt");
		plugin = new SecOneScannerPlugin("customCredentialsId");
		// Inject mock objectFactory via reflection since it's no longer a constructor param
		java.lang.reflect.Field factoryField = SecOneScannerPlugin.class.getDeclaredField("objectFactory");
		factoryField.setAccessible(true);
		factoryField.set(plugin, objectFactory);
		when(taskListener.getLogger()).thenReturn(mock(PrintStream.class));
		mockJenkins();
	}

	@AfterEach
	public void close() {
		mockedJenkins.close();
		mockedCredentialsProvider.close();
	}

	@Test
	public void testScanFromUI() throws Exception {
		plugin.setRunSast(false);
		prepareScaScanSetup();
		assertEquals(true, plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test
	public void testScaScanWithThresholdMediumThreshold() throws Exception {
		plugin.setRunSast(false);
		plugin.setApplyThreshold(true);
		prepareScaScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("100", "100", "0", "", "fail");

		plugin.setThreshold(threshold);

		assertThrows(AbortException.class, () -> plugin.perform(abstractBuild, launcher, buildListener));

	}

	@Test
	public void testScaScanWithThresholdWhereStatusActionIsFail() throws Exception {
		plugin.setRunSast(false);
		plugin.setApplyThreshold(true);
		prepareScaScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("0", "10", "", "", "fail");

		plugin.setThreshold(threshold);

		assertThrows(AbortException.class, () -> plugin.perform(abstractBuild, launcher, buildListener));

	}

	@Test
	public void testScaScanWithThresholdWhereStatusActionIsUnstable() throws Exception {
		plugin.setRunSast(false);
		plugin.setApplyThreshold(true);
		prepareScaScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("0", "10", "", "", "unstable");

		plugin.setThreshold(threshold);

		assertEquals(true, plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test
	public void testScaScanWithThresholdWhereStatusActionIsContinue() throws Exception {
		plugin.setRunSast(false);
		plugin.setApplyThreshold(true);
		prepareScaScanSetup();
		Threshold threshold = new Threshold("0", "10", "", "", "continue");

		plugin.setThreshold(threshold);

		assertEquals(true, plugin.perform(abstractBuild, launcher, buildListener));

	}

	private void prepareScaScanSetup() throws Exception {

		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(envVars.get("SEC1_INSTANCE_URL")).thenReturn("https://api.sec1.io");

		when(envVars.get("WORKSPACE")).thenReturn(WORKSPACE_DIRECTORY_LOCATION);

		StringCredentials apiKeyCred = mock(StringCredentials.class);

		when(CredentialsProvider.findCredentialById(eq("customCredentialsId"), eq(StringCredentials.class),
				eq(abstractBuild), anyList())).thenReturn(apiKeyCred);

		Secret mysecret = mock(Secret.class);

		when(apiKeyCred.getSecret()).thenReturn(mysecret);

		when(apiKeyCred.getSecret().getPlainText()).thenReturn("testApiKey");

		HttpPost httpPost = mock(HttpPost.class);

		when(objectFactory.createHttpPost(anyString())).thenReturn(httpPost);

		CloseableHttpResponse httpResponse = mock(CloseableHttpResponse.class);
		CloseableHttpResponse scaStatusHttpResponse = mock(CloseableHttpResponse.class);

		CloseableHttpClient client = mock(CloseableHttpClient.class);
		when(objectFactory.createHttpClient(any(URI.class))).thenReturn(client);

		when(client.execute(httpPost)).thenReturn(httpResponse).thenReturn(scaStatusHttpResponse);

		StatusLine statusLine = mock(StatusLine.class);
		when(httpResponse.getStatusLine()).thenReturn(statusLine);
		when(statusLine.getStatusCode()).thenReturn(200);
		when(httpResponse.getEntity()).thenReturn(scaHttpEntity);
		when(scaStatusHttpResponse.getEntity()).thenReturn(scaStatusHttpEntity);
		when(scaHttpEntity.getContent()).thenReturn(sampleInitiateScaScanResponseStream);
		when(scaStatusHttpEntity.getContent()).thenReturn(sampleScaReportStream);

		when(objectFactory.getGitFolderConfigPath()).thenReturn("config");

	}

	@Test
	public void testScaSastScanWithThresholdMediumThreshold() throws Exception {
		plugin.setRunSast(true);
		plugin.setApplyThreshold(true);
		prepareScaSastScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("100", "100", "0", "", "fail");

		plugin.setThreshold(threshold);

		assertThrows(AbortException.class, () -> plugin.perform(abstractBuild, launcher, buildListener));

	}

	@Test
	public void testScaSastScanWithThresholdWhereStatusActionIsFail() throws Exception {
		plugin.setRunSast(true);
		plugin.setApplyThreshold(true);
		prepareScaSastScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("0", "10", "", "", "fail");

		plugin.setThreshold(threshold);

		assertThrows(AbortException.class, () -> plugin.perform(abstractBuild, launcher, buildListener));

	}

	@Test
	public void testScaSastScanWithThresholdWhereStatusActionIsUnstable() throws Exception {
		plugin.setRunSast(true);
		plugin.setApplyThreshold(true);
		prepareScaSastScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("0", "10", "", "", "unstable");

		plugin.setThreshold(threshold);

		assertEquals(true, plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test
	public void testScaSastScanWithThresholdWhereStatusActionIsContinue() throws Exception {
		plugin.setRunSast(true);
		plugin.setApplyThreshold(true);
		prepareScaSastScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("0", "10", "", "", "continue");

		plugin.setThreshold(threshold);

		assertEquals(true, plugin.perform(abstractBuild, launcher, buildListener));

	}

	private void prepareScaSastScanSetup() throws Exception {

		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(envVars.get("SEC1_INSTANCE_URL")).thenReturn("https://api.sec1.io");

		when(envVars.get("WORKSPACE")).thenReturn(WORKSPACE_DIRECTORY_LOCATION);

		StringCredentials apiKeyCred = mock(StringCredentials.class);

		when(CredentialsProvider.findCredentialById(eq("customCredentialsId"), eq(StringCredentials.class),
				eq(abstractBuild), anyList())).thenReturn(apiKeyCred);

		Secret mysecret = mock(Secret.class);

		when(apiKeyCred.getSecret()).thenReturn(mysecret);

		when(apiKeyCred.getSecret().getPlainText()).thenReturn("testApiKey");

		HttpPost httpPost = mock(HttpPost.class);

		when(objectFactory.createHttpPost(anyString())).thenReturn(httpPost);

		CloseableHttpResponse scaHttpResponse = mock(CloseableHttpResponse.class);
		CloseableHttpResponse scaStatusHttpResponse = mock(CloseableHttpResponse.class);
		CloseableHttpResponse sastHttpResponse = mock(CloseableHttpResponse.class);
		CloseableHttpResponse sastStatusHttpResponse = mock(CloseableHttpResponse.class);

		CloseableHttpClient client = mock(CloseableHttpClient.class);
		when(objectFactory.createHttpClient(any(URI.class))).thenReturn(client);

		when(client.execute(any(HttpPost.class))).thenReturn(scaHttpResponse).thenReturn(scaStatusHttpResponse)
				.thenReturn(sastHttpResponse).thenReturn(sastStatusHttpResponse);

		StatusLine statusLine = mock(StatusLine.class);
		when(scaHttpResponse.getStatusLine()).thenReturn(statusLine);
		when(sastHttpResponse.getStatusLine()).thenReturn(statusLine);
		when(statusLine.getStatusCode()).thenReturn(200);

		when(scaHttpResponse.getEntity()).thenReturn(scaHttpEntity);
		when(scaStatusHttpResponse.getEntity()).thenReturn(scaStatusHttpEntity);
		when(sastHttpResponse.getEntity()).thenReturn(sastHttpEntity);
		when(sastStatusHttpResponse.getEntity()).thenReturn(sastStatusHttpEntity);
		when(scaHttpEntity.getContent()).thenReturn(sampleInitiateScaScanResponseStream);
		when(scaStatusHttpEntity.getContent()).thenReturn(sampleScaReportStream);
		when(sastHttpEntity.getContent()).thenReturn(sampleInitiateSastScanResponseStream);
		when(sastStatusHttpEntity.getContent()).thenReturn(sampleSastReportStream);
		when(objectFactory.getGitFolderConfigPath()).thenReturn("config");

	}

	private static final byte[] PDF = "%PDF-1.4 sec1 sast report".getBytes(StandardCharsets.ISO_8859_1);

	/**
	 * SAST-only build: trigger, one status poll, then (when archiveReport is
	 * set) the report download, which answers with the given status and body.
	 */
	private jenkins.model.ArtifactManager prepareSastReportSetup(File workspace, int reportStatus, byte[] reportBody)
			throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(abstractBuild.getWorkspace()).thenReturn(new FilePath(workspace));
		when(envVars.get("SEC1_INSTANCE_URL")).thenReturn("https://api.sec1.io");
		when(envVars.get("WORKSPACE")).thenReturn(WORKSPACE_DIRECTORY_LOCATION);
		StringCredentials apiKeyCred = mock(StringCredentials.class);
		when(CredentialsProvider.findCredentialById(eq("customCredentialsId"), eq(StringCredentials.class),
				eq(abstractBuild), anyList())).thenReturn(apiKeyCred);
		Secret mysecret = mock(Secret.class);
		when(apiKeyCred.getSecret()).thenReturn(mysecret);
		when(mysecret.getPlainText()).thenReturn("testApiKey");

		when(objectFactory.createHttpPost(anyString())).thenAnswer(inv -> mock(HttpPost.class));
		CloseableHttpClient client = mock(CloseableHttpClient.class);
		when(objectFactory.createHttpClient(any(URI.class))).thenReturn(client);
		CloseableHttpResponse sastHttpResponse = mock(CloseableHttpResponse.class);
		CloseableHttpResponse sastStatusHttpResponse = mock(CloseableHttpResponse.class);
		CloseableHttpResponse reportHttpResponse = mock(CloseableHttpResponse.class);
		when(client.execute(any(HttpPost.class))).thenReturn(sastHttpResponse).thenReturn(sastStatusHttpResponse)
				.thenReturn(reportHttpResponse);
		StatusLine ok = mock(StatusLine.class);
		when(ok.getStatusCode()).thenReturn(200);
		when(sastHttpResponse.getStatusLine()).thenReturn(ok);
		when(sastHttpResponse.getEntity()).thenReturn(sastHttpEntity);
		when(sastStatusHttpResponse.getEntity()).thenReturn(sastStatusHttpEntity);
		when(sastHttpEntity.getContent()).thenReturn(sampleInitiateSastScanResponseStream);
		when(sastStatusHttpEntity.getContent()).thenReturn(sampleSastReportStream);
		StatusLine reportLine = mock(StatusLine.class);
		when(reportLine.getStatusCode()).thenReturn(reportStatus);
		when(reportHttpResponse.getStatusLine()).thenReturn(reportLine);
		when(reportHttpResponse.getEntity()).thenReturn(new org.apache.http.entity.ByteArrayEntity(reportBody));
		when(objectFactory.getGitFolderConfigPath()).thenReturn("config");

		jenkins.model.ArtifactManager artifactManager = mock(jenkins.model.ArtifactManager.class);
		when(abstractBuild.pickArtifactManager()).thenReturn(artifactManager);
		return artifactManager;
	}

	@Test
	public void testSastPdfReportIsArchivedWhenRequested() throws Exception {
		File workspace = Files.createTempDirectory("sec1-ws").toFile();
		jenkins.model.ArtifactManager artifactManager = prepareSastReportSetup(workspace, 200, PDF);
		plugin.setRunSca(false);
		plugin.setArchiveReport(true);

		assertTrue(plugin.perform(abstractBuild, launcher, buildListener));

		verify(objectFactory).createHttpPost("https://api.sec1.io/rest/sast/asset/report/status");
		verify(objectFactory).createHttpPost("https://api.sec1.io/rest/sast/report/generate");
		assertEquals(new String(PDF, StandardCharsets.ISO_8859_1), new String(
				Files.readAllBytes(new File(workspace, "sec1-sast-report.pdf").toPath()), StandardCharsets.ISO_8859_1));
		verify(artifactManager).archive(any(FilePath.class), eq(launcher), any(),
				eq(Map.of("sec1-sast-report.pdf", "sec1-sast-report.pdf")));
	}

	@Test
	public void testSastPdfReportIsNotRequestedByDefault() throws Exception {
		File workspace = Files.createTempDirectory("sec1-ws").toFile();
		jenkins.model.ArtifactManager artifactManager = prepareSastReportSetup(workspace, 200, PDF);
		plugin.setRunSca(false);

		assertTrue(plugin.perform(abstractBuild, launcher, buildListener));

		verify(objectFactory, never()).createHttpPost("https://api.sec1.io/rest/sast/report/generate");
		verify(artifactManager, never()).archive(any(), any(), any(), any());
		assertFalse(new File(workspace, "sec1-sast-report.pdf").exists());
	}

	@Test
	public void testSastPdfReportFailureOnlyWarns() throws Exception {
		File workspace = Files.createTempDirectory("sec1-ws").toFile();
		jenkins.model.ArtifactManager artifactManager = prepareSastReportSetup(workspace, 403,
				"{\"error\":\"forbidden\"}".getBytes(StandardCharsets.UTF_8));
		plugin.setRunSca(false);
		plugin.setArchiveReport(true);

		assertTrue(plugin.perform(abstractBuild, launcher, buildListener));

		verify(artifactManager, never()).archive(any(), any(), any(), any());
		assertFalse(new File(workspace, "sec1-sast-report.pdf").exists());
		verify(abstractBuild, never()).setResult(any());
	}

	@Test
	public void testScaPdfReportIsArchivedWhenRequested() throws Exception {
		File workspace = Files.createTempDirectory("sec1-ws").toFile();
		jenkins.model.ArtifactManager artifactManager = prepareSastReportSetup(workspace, 200, PDF);
		// Same three replies, but for SCA: trigger, status, report.
		when(sastHttpEntity.getContent()).thenReturn(sampleInitiateScaScanResponseStream);
		when(sastStatusHttpEntity.getContent()).thenReturn(sampleScaReportStream);
		plugin.setRunSast(false);
		plugin.setArchiveReport(true);

		assertTrue(plugin.perform(abstractBuild, launcher, buildListener));

		verify(objectFactory).createHttpPost(
				"https://api.sec1.io/rest/foss/report/166c316c9df7-efc4-4de4-87d4-5qr454sd/pdf?type=sca-security-assessment");
		assertTrue(new File(workspace, "sec1-sca-report.pdf").exists());
		verify(artifactManager).archive(any(FilePath.class), eq(launcher), any(),
				eq(Map.of("sec1-sca-report.pdf", "sec1-sca-report.pdf")));
	}

	@Test
	public void testTriggerFailureNamesStatusAndReason() {
		String url = "https://api.sec1.io/rest/foss/ascan";
		assertEquals("could not reach the Sec1 API at " + url + ". Check SEC1_INSTANCE_URL and the network.",
				SecOneScannerPlugin.triggerFailure(null, url));
		assertEquals("HTTP 403, the Sec1 API key was rejected. Check that the credential holds a current API key."
				+ " Response: 401 Unauthorized",
				SecOneScannerPlugin.triggerFailure(new SecOneScannerPlugin.ScanTriggerResponse(403, "401 Unauthorized\n"), url));
		assertEquals("HTTP 500: {\"error\":\"boom\"}",
				SecOneScannerPlugin.triggerFailure(new SecOneScannerPlugin.ScanTriggerResponse(500, "{\"error\":\"boom\"}"), url));
		assertEquals("HTTP 502.", SecOneScannerPlugin.triggerFailure(new SecOneScannerPlugin.ScanTriggerResponse(502, null), url));
	}

	@Test
	public void testReportIdFromUrl() {
		assertEquals("65568086-f399-4bfd-90da-f75010857713", SecOneScannerPlugin.reportIdFromUrl(
				"https://unified.sec1.io/dashboard-scan-details/65568086-f399-4bfd-90da-f75010857713"));
		assertEquals("65568086-f399-4bfd-90da-f75010857713", SecOneScannerPlugin.reportIdFromUrl(
				"https://unified.sec1.io/dashboard-scan-details/65568086-f399-4bfd-90da-f75010857713/"));
		assertNull(SecOneScannerPlugin.reportIdFromUrl(""));
		assertNull(SecOneScannerPlugin.reportIdFromUrl(null));
		assertNull(SecOneScannerPlugin.reportIdFromUrl("https://unified.sec1.io/dashboard"));
	}

	@Test
	public void testInvalidScmUrl() throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(envVars.get("SEC1_INSTANCE_URL")).thenReturn("https://api.sec1.io");

		StringCredentials apiKeyCred = mock(StringCredentials.class);

		when(CredentialsProvider.findCredentialById(eq("customCredentialsId"), eq(StringCredentials.class),
				eq(abstractBuild), anyList())).thenReturn(apiKeyCred);

		Secret mysecret = mock(Secret.class);

		when(apiKeyCred.getSecret()).thenReturn(mysecret);

		when(apiKeyCred.getSecret().getPlainText()).thenReturn("testApiKey");

		assertThrows(AbortException.class, () -> plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test
	public void testScanFromUIException() throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);

		when(envVars.get("WORKSPACE")).thenReturn(WORKSPACE_DIRECTORY_LOCATION);

		assertThrows(AbortException.class, () -> plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test
	public void testPerformFromScriptException() throws Exception {
		assertThrows(AbortException.class, () -> plugin.perform(run, filePath, envVars, launcher, taskListener));
	}

	@Test
	public void testGetApiKey() throws Exception {

		String apiKey = "testApiKey";

		when(CredentialsProvider.findCredentialById(anyString(), eq(StringCredentials.class), any(Run.class),
				anyList())).thenReturn(null);

		mockApiKeyJourney("SEC1_API_KEY");

		assertEquals(apiKey, plugin.getApiKey(run, taskListener));
	}

	private void mockApiKeyJourney(String keyID) {

		StringCredentials apiKeyCred = mock(StringCredentials.class);

		when(CredentialsProvider.findCredentialById(eq(keyID), eq(StringCredentials.class), any(Run.class), anyList()))
				.thenReturn(apiKeyCred);

		Secret mysecret = mock(Secret.class);

		when(apiKeyCred.getSecret()).thenReturn(mysecret);

		when(apiKeyCred.getSecret().getPlainText()).thenReturn("testApiKey");
	}

	@Test
	public void testGetApiKeyWithCustomCredentialsId() throws Exception {
		String apiKey = "testApiKey";
		plugin.setApiCredentialsId("customCredentialsId");

		mockApiKeyJourney("customCredentialsId");

		assertEquals(apiKey, plugin.getApiKey(run, taskListener));

	}

	@Test
	public void testGetApiKeyWithNoCredentials() throws Exception {
		when(CredentialsProvider.findCredentialById(anyString(), eq(StringCredentials.class), eq(run), anyList()))
				.thenReturn(null);
		assertNull(plugin.getApiKey(run, taskListener));
	}

	private void mockJenkins() {
		mockedJenkins = mockStatic(Jenkins.class);
		when(Jenkins.get()).thenReturn(jenkins);
		mockedCredentialsProvider = mockStatic(CredentialsProvider.class);
	}

	@Test
	public void testParseHeadBranchKeepsSlashesAndIgnoresDetachedHead() {
		assertEquals("feature/scm-url-config", plugin.parseHeadBranch("ref: refs/heads/feature/scm-url-config\n"));
		assertEquals("main", plugin.parseHeadBranch("ref: refs/heads/main"));
		assertNull(plugin.parseHeadBranch("73c8cb6fa1b2c3d4e5f60718293a4b5c6d7e8f90"));
		assertNull(plugin.parseHeadBranch(null));
	}

	@Test
	public void testParseRemoteOriginUrlStripsCredentialsAndStopsAtNextSection() {
		String config = "[core]\n\tbare = false\n"
				+ "[remote \"origin\"]\n\turl = https://user:secret@github.com/org/repo.git\n"
				+ "\tfetch = +refs/heads/*:refs/remotes/origin/*\n"
				+ "[remote \"upstream\"]\n\turl = https://github.com/other/repo.git\n";
		String url = plugin.parseRemoteOriginUrl(config);
		assertNotNull(url);
		assertFalse(url.contains("secret"));
		assertTrue(url.contains("github.com/org/repo"));
		assertNull(plugin.parseRemoteOriginUrl("[core]\n\tbare = false\n"));
	}
}
