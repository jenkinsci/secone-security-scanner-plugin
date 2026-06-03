package io.jenkins.plugins.secone.security.tools;

import java.io.IOException;
import java.util.Locale;

public enum Platform {
	LINUX_AMD64("sec1-sast-linux-amd64", "sec1-sast"),
	LINUX_ARM64("sec1-sast-linux-arm64", "sec1-sast"),
	MAC_AMD64("sec1-sast-darwin-amd64", "sec1-sast"),
	MAC_ARM64("sec1-sast-darwin-arm64", "sec1-sast"),
	WINDOWS_AMD64("sec1-sast-windows-amd64.exe", "sec1-sast.exe");

	private final String downloadFileName;
	private final String installedFileName;

	Platform(String downloadFileName, String installedFileName) {
		this.downloadFileName = downloadFileName;
		this.installedFileName = installedFileName;
	}

	public String getDownloadFileName() {
		return downloadFileName;
	}

	public String getInstalledFileName() {
		return installedFileName;
	}

	public static Platform current() throws IOException {
		String os = System.getProperty("os.name", "").toLowerCase(Locale.ROOT);
		String arch = System.getProperty("os.arch", "").toLowerCase(Locale.ROOT);
		boolean arm64 = arch.equals("aarch64") || arch.equals("arm64");

		if (os.contains("linux")) {
			return arm64 ? LINUX_ARM64 : LINUX_AMD64;
		}
		if (os.contains("mac") || os.contains("darwin")) {
			return arm64 ? MAC_ARM64 : MAC_AMD64;
		}
		if (os.contains("windows")) {
			return WINDOWS_AMD64;
		}
		throw new IOException("Unsupported platform: os=" + os + " arch=" + arch);
	}
}
