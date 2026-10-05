package io.jenkins.plugins.secone.security.mobile;

import java.io.ByteArrayInputStream;
import java.io.File;
import java.io.FileInputStream;
import java.io.IOException;
import java.io.InputStream;
import java.io.SequenceInputStream;
import java.io.Serializable;
import java.net.ProxySelector;
import java.net.URI;
import java.net.http.HttpClient;
import java.net.http.HttpRequest;
import java.net.http.HttpResponse;
import java.nio.charset.StandardCharsets;
import java.time.Duration;
import java.util.Collections;
import java.util.Map;
import java.util.UUID;

import hudson.remoting.VirtualChannel;
import jenkins.MasterToSlaveFileCallable;
import jenkins.security.MasterToSlaveCallable;

/**
 * Calls to the Sec1 Mobile Security scan API. They execute on the agent that
 * holds the workspace: the binary is uploaded from where the build produced
 * it, and hybrid deployments whose scanner nodes are only reachable from the
 * build network work without the controller needing access.
 */
final class MobileApi {

	private MobileApi() {
	}

	static final class Response implements Serializable {
		private static final long serialVersionUID = 1L;
		final int status;
		final String body;

		Response(int status, String body) {
			this.status = status;
			this.body = body;
		}

		boolean isSuccess() {
			return status >= 200 && status < 300;
		}
	}

	static HttpClient client() {
		return HttpClient.newBuilder().connectTimeout(Duration.ofSeconds(30)).proxy(ProxySelector.getDefault())
				.followRedirects(HttpClient.Redirect.NORMAL).build();
	}

	/** Streams the binary as a multipart upload to {@code POST /api/v1/scans}. */
	static final class Submit extends MasterToSlaveFileCallable<Response> {
		private static final long serialVersionUID = 1L;
		private final String url;
		private final String apiKey;
		private final String userAgent;
		private final Map<String, String> fields;

		Submit(String url, String apiKey, String userAgent, Map<String, String> fields) {
			this.url = url;
			this.apiKey = apiKey;
			this.userAgent = userAgent;
			this.fields = fields;
		}

		@Override
		public Response invoke(File binary, VirtualChannel channel) throws IOException, InterruptedException {
			String boundary = "----Sec1Mobile" + UUID.randomUUID().toString().replace("-", "");
			StringBuilder head = new StringBuilder();
			for (Map.Entry<String, String> field : fields.entrySet()) {
				if (field.getValue() == null || field.getValue().isEmpty()) {
					continue;
				}
				head.append("--").append(boundary).append("\r\n")
						.append("Content-Disposition: form-data; name=\"").append(field.getKey()).append("\"\r\n\r\n")
						.append(field.getValue()).append("\r\n");
			}
			head.append("--").append(boundary).append("\r\n")
					.append("Content-Disposition: form-data; name=\"file\"; filename=\"")
					.append(binary.getName().replace("\"", "")).append("\"\r\n")
					.append("Content-Type: application/octet-stream\r\n\r\n");
			byte[] prefix = head.toString().getBytes(StandardCharsets.UTF_8);
			byte[] suffix = ("\r\n--" + boundary + "--\r\n").getBytes(StandardCharsets.UTF_8);
			long length = prefix.length + binary.length() + suffix.length;

			HttpRequest.BodyPublisher body = HttpRequest.BodyPublishers.fromPublisher(
					HttpRequest.BodyPublishers.ofInputStream(() -> {
						try {
							InputStream file = new FileInputStream(binary);
							return new SequenceInputStream(Collections.enumeration(java.util.List.of(
									new ByteArrayInputStream(prefix), file, new ByteArrayInputStream(suffix))));
						} catch (IOException e) {
							throw new java.io.UncheckedIOException(e);
						}
					}), length);

			HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofMinutes(30))
					.header("sec1-api-key", apiKey).header("User-Agent", userAgent)
					.header("Accept", "application/json")
					.header("Content-Type", "multipart/form-data; boundary=" + boundary).POST(body).build();
			HttpResponse<String> response = client().send(request,
					HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
			return new Response(response.statusCode(), response.body());
		}
	}

	/** A small JSON request ({@code GET} or {@code DELETE}). */
	static final class Call extends MasterToSlaveCallable<Response, IOException> {
		private static final long serialVersionUID = 1L;
		private final String method;
		private final String url;
		private final String apiKey;
		private final String userAgent;

		Call(String method, String url, String apiKey, String userAgent) {
			this.method = method;
			this.url = url;
			this.apiKey = apiKey;
			this.userAgent = userAgent;
		}

		@Override
		public Response call() throws IOException {
			HttpRequest request = HttpRequest.newBuilder(URI.create(url)).timeout(Duration.ofSeconds(60))
					.header("sec1-api-key", apiKey).header("User-Agent", userAgent)
					.header("Accept", "application/json").method(method, HttpRequest.BodyPublishers.noBody()).build();
			try {
				HttpResponse<String> response = client().send(request,
						HttpResponse.BodyHandlers.ofString(StandardCharsets.UTF_8));
				return new Response(response.statusCode(), response.body());
			} catch (InterruptedException e) {
				Thread.currentThread().interrupt();
				throw new IOException("Interrupted while calling " + url, e);
			}
		}
	}
}
