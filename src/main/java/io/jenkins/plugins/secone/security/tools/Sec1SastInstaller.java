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

public class Sec1SastInstaller extends ToolInstaller {

	private static final String DOWNLOAD_BASE_URL =
			"https://storage.googleapis.com/digitalassets-sec1/latest/";
	private static final String INSTALLED_FROM = ".installedFrom";
	private static final String TIMESTAMP_FILE = ".timestamp";
	private static final long REFRESH_INTERVAL_MS = 24L * 60 * 60 * 1000; // 24 hours

	@DataBoundConstructor
	public Sec1SastInstaller(String label) {
		super(label);
	}

	@Override
	public FilePath performInstallation(ToolInstallation tool, Node node, TaskListener log)
			throws IOException, InterruptedException {
		FilePath expected = preferredLocation(tool, node);
		VirtualChannel channel = node.getChannel();
		if (channel == null) {
			throw new IOException("Cannot install sec1-sast: node '" + node.getDisplayName() + "' is offline.");
		}

		Platform platform = channel.call(new GetPlatform());
		URL downloadUrl = new URL(DOWNLOAD_BASE_URL + platform.getDownloadFileName());

		if (isUpToDate(expected)) {
			return expected;
		}

		expected.mkdirs();
		log.getLogger().println("Downloading sec1-sast from " + downloadUrl);
		channel.call(new Downloader(downloadUrl, new File(expected.getRemote(), platform.getInstalledFileName())));

		expected.child(INSTALLED_FROM).write(downloadUrl.toString(), StandardCharsets.UTF_8.name());
		expected.child(TIMESTAMP_FILE).write(String.valueOf(Instant.now().toEpochMilli()), StandardCharsets.UTF_8.name());
		return expected;
	}

	private boolean isUpToDate(FilePath expected) throws IOException, InterruptedException {
		FilePath timestamp = expected.child(TIMESTAMP_FILE);
		if (!timestamp.exists()) {
			return false;
		}
		try {
			long lastInstalled = Long.parseLong(timestamp.readToString().trim());
			return (System.currentTimeMillis() - lastInstalled) < REFRESH_INTERVAL_MS;
		} catch (NumberFormatException e) {
			return false;
		}
	}

	private static class GetPlatform extends MasterToSlaveCallable<Platform, IOException> {
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
					throw new IOException("Failed to mark sec1-sast as executable: " + destination);
				}
			}
			return null;
		}
	}

	@Extension
	public static final class DescriptorImpl extends ToolInstallerDescriptor<Sec1SastInstaller> {

		@NonNull
		@Override
		public String getDisplayName() {
			return "Install from sec1.io (latest)";
		}

		@Override
		public boolean isApplicable(Class<? extends ToolInstallation> toolType) {
			return toolType == Sec1SastInstallation.class;
		}
	}
}
