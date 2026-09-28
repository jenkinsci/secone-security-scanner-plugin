package io.jenkins.plugins.secone.security.tools;

import java.io.IOException;
import java.util.Locale;

/*
 * Download/installed file names for the unified sec1-cli binary (built with
 * pkg from resilient-foss-cli). macOS ships x64 only; arm64 Macs run it via
 * Rosetta.
 */
public enum CliPlatform {
	LINUX_AMD64("sec1-cli-linux", "sec1-cli"),
	LINUX_ARM64("sec1-cli-linux-arm64", "sec1-cli"),
	MAC("sec1-cli-macos", "sec1-cli"),
	WINDOWS_AMD64("sec1-cli-win.exe", "sec1-cli.exe");

	private final String downloadFileName;
	private final String installedFileName;

	CliPlatform(String downloadFileName, String installedFileName) {
		this.downloadFileName = downloadFileName;
		this.installedFileName = installedFileName;
	}

	public String getDownloadFileName() {
		return downloadFileName;
	}

	public String getInstalledFileName() {
		return installedFileName;
	}

	public static CliPlatform current() throws IOException {
		String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
		boolean arm64 = arch.equals("aarch64") || arch.equals("arm64");

		if (os.contains("linux")) {
			return arm64 ? LINUX_ARM64 : LINUX_AMD64;
		}
		if (os.contains("mac") || os.contains("darwin")) {
			return MAC;
		}
		if (os.contains("windows")) {
			return WINDOWS_AMD64;
		}
		throw new IOException("Unsupported platform: os=" + os + " arch=" + arch);
	}
}
