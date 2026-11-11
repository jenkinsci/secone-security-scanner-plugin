package io.jenkins.plugins.secone.security;

import static org.junit.jupiter.api.Assertions.assertEquals;
import static org.junit.jupiter.api.Assertions.assertThrows;
import static org.junit.jupiter.api.Assertions.assertTrue;
import static org.mockito.ArgumentMatchers.any;
import static org.mockito.ArgumentMatchers.anyString;
import static org.mockito.Mockito.mock;
import static org.mockito.Mockito.never;
import static org.mockito.Mockito.verify;
import static org.mockito.Mockito.when;

import java.io.ByteArrayOutputStream;
import java.io.PrintStream;
import java.net.URI;
import java.nio.charset.StandardCharsets;

import org.apache.http.StatusLine;
import org.apache.http.client.methods.CloseableHttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.junit.jupiter.api.BeforeEach;
import org.junit.jupiter.api.Test;

import hudson.AbortException;
import hudson.model.TaskListener;
import io.jenkins.plugins.secone.security.object.factory.ObjectFactory;

class ScaPolicyEnforcementTest {

	private SecOneScannerPlugin plugin;
	private ObjectFactory objectFactory;
	private TaskListener listener;
	private ByteArrayOutputStream log;

	@BeforeEach
	void setUp() throws Exception {
		plugin = new SecOneScannerPlugin("cred");
		objectFactory = mock(ObjectFactory.class);
		java.lang.reflect.Field f = SecOneScannerPlugin.class.getDeclaredField("objectFactory");
		f.setAccessible(true);
		f.set(plugin, objectFactory);
		log = new ByteArrayOutputStream();
		listener = mock(TaskListener.class);
		when(listener.getLogger()).thenReturn(new PrintStream(log, true, "UTF-8"));
	}

	private void serverReplies(int status, String body) throws Exception {
		CloseableHttpClient client = mock(CloseableHttpClient.class);
		CloseableHttpResponse response = mock(CloseableHttpResponse.class);
		StatusLine statusLine = mock(StatusLine.class);
		when(objectFactory.createHttpClient(any(URI.class))).thenReturn(client);
		when(objectFactory.createHttpPost(anyString())).thenReturn(mock(HttpPost.class));
		when(client.execute(any(HttpPost.class))).thenReturn(response);
		when(response.getStatusLine()).thenReturn(statusLine);
		when(statusLine.getStatusCode()).thenReturn(status);
		when(response.getEntity()).thenReturn(new StringEntity(body, StandardCharsets.UTF_8));
	}

	private String log() {
		return new String(log.toByteArray(), StandardCharsets.UTF_8);
	}

	@Test
	void failActionAbortsAndListsViolations() throws Exception {
		serverReplies(200, "{\"policyApplied\":true,\"breached\":true,\"action\":\"FAIL\",\"policySource\":\"repository\","
				+ "\"severityViolations\":[{\"severity\":\"CRITICAL\",\"count\":3,\"max\":0}],"
				+ "\"licenseViolations\":[{\"purl\":\"pkg:npm/x@1\",\"licenses\":[\"AGPL-3.0\"],"
				+ "\"reason\":\"License category denied: NETWORK_COPYLEFT\"}],\"licenseViolationTotal\":1}");
		AbortException ex = assertThrows(AbortException.class,
				() -> plugin.enforceScaPolicy("https://api.sec1.io", "r1", "key", listener));
		assertTrue(ex.getMessage().contains("SCA policy breached (repository policy)"));
		assertTrue(log().contains("CRITICAL: 3 found, policy allows 0"));
		assertTrue(log().contains("pkg:npm/x@1  AGPL-3.0"));
	}

	@Test
	void unstableActionReturnsTwo() throws Exception {
		serverReplies(200, "{\"policyApplied\":true,\"breached\":true,\"action\":\"UNSTABLE\"}");
		assertEquals(2, plugin.enforceScaPolicy("https://api.sec1.io", "r1", "key", listener));
	}

	@Test
	void noPolicyOrPassedReturnsZero() throws Exception {
		serverReplies(200, "{\"policyApplied\":false,\"breached\":false}");
		assertEquals(0, plugin.enforceScaPolicy("https://api.sec1.io", "r1", "key", listener));
		assertTrue(log().contains("None configured"));
	}

	@Test
	void serverThatCannotEvaluateOnlyWarns() throws Exception {
		serverReplies(404, "{\"error\":\"Not Found\"}");
		assertEquals(0, plugin.enforceScaPolicy("https://api.sec1.io", "r1", "key", listener));
		assertTrue(log().contains("could not be evaluated (HTTP 404)"));
	}

	@Test
	void skipPolicyMakesNoCall() throws Exception {
		plugin.setSkipPolicy(true);
		assertEquals(0, plugin.enforceScaPolicy("https://api.sec1.io", "r1", "key", listener));
		verify(objectFactory, never()).createHttpClient(any(URI.class));
	}
}
