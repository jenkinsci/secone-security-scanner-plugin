package io.jenkins.plugins.secone.security.tools;

import java.io.File;
import java.io.IOException;
import java.net.URL;
import java.nio.charset.StandardCharsets;
import java.time.Instant;

import org.apache.commons.io.FileUtils;
import org.kohsuke.stapler.DataBoundConstructor;

import edu.umd.cs.findbugs.annotations.NonNull;
import hudson.Extension;
import hudson.FilePath;
import hudson.Functions;
import hudson.model.Node;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.tools.ToolInstallation;
import hudson.tools.ToolInstaller;
import hudson.tools.ToolInstallerDescriptor;
import jenkins.security.MasterToSlaveCallable;

public class Sec1CliInstaller extends ToolInstaller {

	private static final String DOWNLOAD_BASE_URL =
			"https://storage.googleapis.com/digitalassets-sec1/latest/";
	private static final String INSTALLED_FROM = ".installedFrom";
	private static final String TIMESTAMP_FILE = ".timestamp";
	private static final long REFRESH_INTERVAL_MS = 24L * 60 * 60 * 1000; // 24 hours
	// Published next to the binaries and replaced with every sec1-cli release.
	private static final String CHECKSUMS_NAME = "sec1-cli-SHA256SUMS.txt";
	private static final String CHECKSUMS_FILE = ".checksums";

	@DataBoundConstructor
	public Sec1CliInstaller(String label) {
		super(label);
	}

	@Override
	public FilePath performInstallation(ToolInstallation tool, Node node, TaskListener log)
			throws IOException, InterruptedException {
		FilePath expected = preferredLocation(tool, node);
		VirtualChannel channel = node.getChannel();
		if (channel == null) {
			throw new IOException("Cannot install sec1-cli: node '" + node.getDisplayName() + "' is offline.");
		}

		CliPlatform platform = channel.call(new GetPlatform());
		Platform sastPlatform = channel.call(new GetSastPlatform());
		URL downloadUrl = new URL(DOWNLOAD_BASE_URL + platform.getDownloadFileName());
		URL sastDownloadUrl = new URL(DOWNLOAD_BASE_URL + sastPlatform.getDownloadFileName());

		// The checksums published for the current release, read from the agent
		// (which is where the binaries are downloaded). Null when unreachable.
		String published = channel.call(new FetchText(new URL(DOWNLOAD_BASE_URL + CHECKSUMS_NAME)));
		if (isUpToDate(expected, published)) {
			return expected;
		}

		expected.mkdirs();
		// One installation carries both binaries: sec1-cli (SCA/SBOM) and
		// sec1-sast (SAST engine), so a single Tool entry serves both scans.
		log.getLogger().println("Downloading sec1-cli from " + downloadUrl);
		channel.call(new Downloader(downloadUrl, new File(expected.getRemote(), platform.getInstalledFileName())));
		log.getLogger().println("Downloading sec1-sast from " + sastDownloadUrl);
		channel.call(new Downloader(sastDownloadUrl,
				new File(expected.getRemote(), sastPlatform.getInstalledFileName())));

		expected.child(INSTALLED_FROM).write(downloadUrl + "\n" + sastDownloadUrl, StandardCharsets.UTF_8.name());
		if (published != null) {
			expected.child(CHECKSUMS_FILE).write(published, StandardCharsets.UTF_8.name());
		} else {
			expected.child(CHECKSUMS_FILE).delete();
		}
		expected.child(TIMESTAMP_FILE).write(String.valueOf(Instant.now().toEpochMilli()), StandardCharsets.UTF_8.name());
		return expected;
	}

	/**
	 * The installation is kept for 24 hours, unless a new sec1-cli release has
	 * been published since it was downloaded: the published checksums then
	 * differ from the ones stored with the installation. When the checksums
	 * cannot be read, only the 24 hour rule applies.
	 */
	private boolean isUpToDate(FilePath expected, String published) throws IOException, InterruptedException {
		FilePath timestamp = expected.child(TIMESTAMP_FILE);
		if (!timestamp.exists()) {
			return false;
		}
		if (published != null) {
			FilePath checksums = expected.child(CHECKSUMS_FILE);
			if (!sameRelease(published, checksums.exists() ? checksums.readToString() : null)) {
				return false;
			}
		}
		try {
			long lastInstalled = Long.parseLong(timestamp.readToString().trim());
			return (System.currentTimeMillis() - lastInstalled) < REFRESH_INTERVAL_MS;
		} catch (NumberFormatException e) {
			return false;
		}
	}

	/** Whether the installed checksums are those of the published release. */
	static boolean sameRelease(String published, String installed) {
		return installed != null && published.trim().equals(installed.trim());
	}

	/** Reads a small text file over HTTP on the agent; null when it cannot be read. */
	private static class FetchText extends MasterToSlaveCallable<String, IOException> {
		private static final long serialVersionUID = 1L;
		private final URL url;

		FetchText(URL url) {
			this.url = url;
		}

		@Override
		public String call() {
			try {
				java.net.URLConnection connection = url.openConnection();
				connection.setConnectTimeout(10_000);
				connection.setReadTimeout(10_000);
				try (java.io.InputStream in = connection.getInputStream()) {
					String text = org.apache.commons.io.IOUtils.toString(in, StandardCharsets.UTF_8);
					return text.trim().isEmpty() ? null : text;
				}
			} catch (IOException e) {
				return null;
			}
		}
	}

	private static class GetPlatform extends MasterToSlaveCallable<CliPlatform, IOException> {
		private static final long serialVersionUID = 1L;

		@Override
		public CliPlatform call() throws IOException {
			return CliPlatform.current();
		}
	}

	private static class GetSastPlatform extends MasterToSlaveCallable<Platform, IOException> {
		private static final long serialVersionUID = 1L;

		@Override
		public Platform call() throws IOException {
			return Platform.current();
		}
	}

	private static class Downloader extends MasterToSlaveCallable<Void, IOException> {
		private static final long serialVersionUID = 1L;
		private final URL url;
		private final File destination;

		Downloader(URL url, File destination) {
			this.url = url;
			this.destination = destination;
		}

		@Override
		public Void call() throws IOException {
			FileUtils.copyURLToFile(url, destination, 30_000, 120_000);
			if (!Functions.isWindows()) {
				if (!destination.setExecutable(true, false)) {
					throw new IOException("Failed to mark sec1-cli as executable: " + destination);
				}
			}
			return null;
		}
	}

	@Extension
	public static final class DescriptorImpl extends ToolInstallerDescriptor<Sec1CliInstaller> {

		@NonNull
		@Override
		public String getDisplayName() {
			return "Install from sec1.io (latest)";
		}

		@Override
		public boolean isApplicable(Class<? extends ToolInstallation> toolType) {
			return toolType == Sec1CliInstallation.class;
		}
	}
}
