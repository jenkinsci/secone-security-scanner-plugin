package io.jenkins.plugins.secone.security.tools;

import static org.junit.jupiter.api.Assertions.assertFalse;
import static org.junit.jupiter.api.Assertions.assertTrue;

import org.junit.jupiter.api.Test;

class Sec1CliInstallerTest {

	private static final String RELEASE_A = "aaa  sec1-cli-linux\nbbb  sec1-cli-win.exe\n";
	private static final String RELEASE_B = "ccc  sec1-cli-linux\nbbb  sec1-cli-win.exe\n";

	@Test
	void sameChecksumsMeanTheInstalledReleaseIsCurrent() {
		assertTrue(Sec1CliInstaller.sameRelease(RELEASE_A, RELEASE_A));
		assertTrue(Sec1CliInstaller.sameRelease(RELEASE_A, RELEASE_A.trim() + "\r\n"));
	}

	@Test
	void aNewReleaseIsDownloaded() {
		assertFalse(Sec1CliInstaller.sameRelease(RELEASE_B, RELEASE_A));
	}

	@Test
	void anInstallationFromBeforeChecksumsWereStoredIsDownloadedAgain() {
		assertFalse(Sec1CliInstaller.sameRelease(RELEASE_A, null));
	}
}
