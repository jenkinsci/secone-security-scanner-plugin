package io.jenkins.plugins.secone.security;

import static org.junit.Assert.assertEquals;
import static org.junit.Assert.assertNull;
import static org.junit.Assert.assertThrows;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyList;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.ArgumentMatchers.eq;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.mockStatic;
import static org.mockito.Mockito.when;

import java.io.File;
import java.io.FileInputStream;

import java.io.InputStream;
import java.io.PrintStream;
import java.net.URI;


import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;

import org.apache.http.impl.client.CloseableHttpClient;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.junit.After;
import org.junit.Before;
import org.junit.Test;
import org.junit.runner.RunWith;
import org.mockito.Mock;
import org.mockito.MockedStatic;
import org.mockito.Mockito;
import org.mockito.junit.MockitoJUnitRunner;


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

@RunWith(MockitoJUnitRunner.class)
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

	private static MockedStatic<Jenkins> mockedJenkins;
	private static MockedStatic<CredentialsProvider> mockedCredentialsProvider;

	private static String WORKSPACE_DIRECTORY_LOCATION;

	private static InputStream sampleScaReportStream;

	private static InputStream sampleSastReportStream;

	private static InputStream sampleInitiateSastScanResponseStream;

	private static InputStream sampleInitiateScaScanResponseStream;

	@Before
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

	@After
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

	@Test(expected = AbortException.class)
	public void testScaScanWithThresholdWhereStatusActionIsFail() throws Exception {
		plugin.setRunSast(false);
		plugin.setApplyThreshold(true);
		prepareScaScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("0", "10", "", "", "fail");

		plugin.setThreshold(threshold);

		plugin.perform(abstractBuild, launcher, buildListener);

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

	@Test(expected = AbortException.class)
	public void testScaSastScanWithThresholdWhereStatusActionIsFail() throws Exception {
		plugin.setRunSast(true);
		plugin.setApplyThreshold(true);
		prepareScaSastScanSetup();
		// fail build if threshold breached
		Threshold threshold = new Threshold("0", "10", "", "", "fail");

		plugin.setThreshold(threshold);

		plugin.perform(abstractBuild, launcher, buildListener);

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

		// when(client.execute(httpPost)).thenReturn(scaHttpResponse);
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

	@Test(expected = AbortException.class)
	public void testInvalidScmUrl() throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);
		when(envVars.get("SEC1_INSTANCE_URL")).thenReturn("https://api.sec1.io");

		// when(envVars.get("WORKSPACE")).thenReturn("idont/exist");

		StringCredentials apiKeyCred = mock(StringCredentials.class);

		when(CredentialsProvider.findCredentialById(eq("customCredentialsId"), eq(StringCredentials.class),
				eq(abstractBuild), anyList())).thenReturn(apiKeyCred);

		Secret mysecret = mock(Secret.class);

		when(apiKeyCred.getSecret()).thenReturn(mysecret);

		when(apiKeyCred.getSecret().getPlainText()).thenReturn("testApiKey");

		plugin.perform(abstractBuild, launcher, buildListener);
	}

	@Test(expected = AbortException.class)
	public void testScanFromUIException() throws Exception {
		when(buildListener.getLogger()).thenReturn(System.out);
		when(abstractBuild.getEnvironment(buildListener)).thenReturn(envVars);

		when(envVars.get("WORKSPACE")).thenReturn(WORKSPACE_DIRECTORY_LOCATION);
		assertEquals(1, plugin.perform(abstractBuild, launcher, buildListener));
	}

	@Test(expected = AbortException.class)
	public void testPerformFromScriptException() throws Exception {
		plugin.perform(run, filePath, envVars, launcher, taskListener);
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
}
