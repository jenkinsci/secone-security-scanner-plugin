package io.jenkins.plugins.secone.security.object.factory;

import java.io.File;
import java.net.URI;
import java.net.URISyntaxException;
import java.util.List;
import java.util.regex.Pattern;

import org.apache.http.HttpHost;
import org.apache.http.client.config.RequestConfig;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.impl.client.CloseableHttpClient;
import org.apache.http.impl.client.HttpClients;

import hudson.ProxyConfiguration;
import jenkins.model.Jenkins;

public class ObjectFactory {

	private static final int CONNECT_TIMEOUT_MS = 30_000;
	private static final int SOCKET_TIMEOUT_MS = 120_000;
	private static final int CONNECTION_REQUEST_TIMEOUT_MS = 30_000;

	public HttpPost createHttpPost(String uri) throws URISyntaxException {
		HttpPost post = new HttpPost(uri);
		post.setConfig(getRequestConfig(new URI(uri)));
		return post;
	}

	public CloseableHttpClient createHttpClient(URI apiUri) {
		Jenkins jenkins = Jenkins.getInstanceOrNull();
		ProxyConfiguration proxyConfig = (jenkins != null) ? jenkins.proxy : null;

		RequestConfig defaultConfig = baseRequestConfigBuilder().build();
		if (proxyConfig != null && shouldUseProxy(proxyConfig, apiUri.getHost())) {
			HttpHost proxyHost = new HttpHost(proxyConfig.name, proxyConfig.port);
			return HttpClients.custom()
					.setProxy(proxyHost)
					.setDefaultRequestConfig(defaultConfig)
					.build();
		}
		return HttpClients.custom()
				.setDefaultRequestConfig(defaultConfig)
				.build();
	}

	public String getGitFolderConfigPath() {
		return ".git" + File.separator + "config";
	}

	private ProxyConfiguration getJenkinsProxyConfiguration() {
		Jenkins jenkins = Jenkins.getInstanceOrNull();
		return jenkins != null ? jenkins.proxy : null;
	}

	private RequestConfig getRequestConfig(URI uri) {
		RequestConfig.Builder builder = baseRequestConfigBuilder();
		ProxyConfiguration proxy = getJenkinsProxyConfiguration();
		if (proxy != null && shouldUseProxy(proxy, uri.getHost())) {
			builder.setProxy(new HttpHost(proxy.name, proxy.port));
		}
		return builder.build();
	}

	private RequestConfig.Builder baseRequestConfigBuilder() {
		return RequestConfig.custom()
				.setConnectTimeout(CONNECT_TIMEOUT_MS)
				.setSocketTimeout(SOCKET_TIMEOUT_MS)
				.setConnectionRequestTimeout(CONNECTION_REQUEST_TIMEOUT_MS);
	}

	private boolean shouldUseProxy(ProxyConfiguration proxy, String host) {
		if (proxy == null || host == null) {
			return false;
		}

		List<Pattern> noProxyHostPatterns = proxy.getNoProxyHostPatterns();
		for (Pattern noProxyHostPattern : noProxyHostPatterns) {
			if (noProxyHostPattern.matcher(host).matches()) {
				return false;
			}
		}
		return true;
	}
}
