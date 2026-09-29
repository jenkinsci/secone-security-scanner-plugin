package io.jenkins.plugins.secone.security.tools;

import java.io.IOException;
import java.util.Collections;
import java.util.List;

import org.jenkinsci.Symbol;
import org.kohsuke.stapler.DataBoundConstructor;

import edu.umd.cs.findbugs.annotations.NonNull;
import edu.umd.cs.findbugs.annotations.Nullable;
import hudson.EnvVars;
import hudson.Extension;
import hudson.Launcher;
import hudson.Util;
import hudson.model.EnvironmentSpecific;
import hudson.model.Node;
import hudson.model.TaskListener;
import hudson.remoting.VirtualChannel;
import hudson.slaves.NodeSpecific;
import hudson.tools.ToolDescriptor;
import hudson.tools.ToolInstallation;
import hudson.tools.ToolInstaller;
import hudson.tools.ToolProperty;
import io.jenkins.plugins.secone.security.SecOneScannerPlugin;
import jenkins.model.Jenkins;
import jenkins.security.MasterToSlaveCallable;

public class Sec1CliInstallation extends ToolInstallation
		implements EnvironmentSpecific<Sec1CliInstallation>, NodeSpecific<Sec1CliInstallation> {

	private static final long serialVersionUID = 1L;

	@DataBoundConstructor
	public Sec1CliInstallation(@NonNull String name, @Nullable String home,
			@Nullable List<? extends ToolProperty<?>> properties) {
		super(name, home, properties == null ? Collections.emptyList() : properties);
	}

	@Override
	public Sec1CliInstallation forEnvironment(EnvVars env) {
		return new Sec1CliInstallation(getName(), env.expand(getHome()), getProperties().toList());
	}

	@Override
	public Sec1CliInstallation forNode(@NonNull Node node, TaskListener log) throws IOException, InterruptedException {
		return new Sec1CliInstallation(getName(), translateFor(node, log), getProperties().toList());
	}

	public String getExecutable(@NonNull Launcher launcher) throws IOException, InterruptedException {
		return resolve(launcher, false);
	}

	/* The same installation also carries the sec1-sast engine binary. */
	public String getSastExecutable(@NonNull Launcher launcher) throws IOException, InterruptedException {
		return resolve(launcher, true);
	}

	private String resolve(Launcher launcher, boolean sast) throws IOException, InterruptedException {
		VirtualChannel channel = launcher.getChannel();
		if (channel == null) {
			throw new IOException("Unable to resolve Sec1 CLI executable: launcher has no channel.");
		}
		final String home = Util.fixEmptyAndTrim(getHome());
		if (home == null) {
			throw new IOException("Sec1 CLI installation '" + getName() + "' has no home directory set.");
		}
		return channel.call(new ResolveExecutable(home, sast));
	}

	private static class ResolveExecutable extends MasterToSlaveCallable<String, IOException> {
		private static final long serialVersionUID = 1L;
		private final String home;
		private final boolean sast;

		ResolveExecutable(String home, boolean sast) {
			this.home = home;
			this.sast = sast;
		}

		@Override
		public String call() throws IOException {
			String fileName = sast ? Platform.current().getInstalledFileName()
					: CliPlatform.current().getInstalledFileName();
			java.io.File homeDir = new java.io.File(home);
			java.io.File installed = new java.io.File(homeDir, fileName);
			if (installed.isFile()) {
				return installed.getAbsolutePath();
			}
			if (!sast && homeDir.isFile()) {
				return homeDir.getAbsolutePath();
			}
			throw new IOException("Sec1 CLI binary not found under " + home
					+ " (looked for " + fileName + ").");
		}
	}

	@Extension
	@Symbol("sec1Cli")
	public static class DescriptorImpl extends ToolDescriptor<Sec1CliInstallation> {

		@NonNull
		@Override
		public String getDisplayName() {
			return "Sec1 CLI";
		}

		@Override
		public List<? extends ToolInstaller> getDefaultInstallers() {
			return Collections.singletonList(new Sec1CliInstaller(null));
		}

		@Override
		public Sec1CliInstallation[] getInstallations() {
			Jenkins j = Jenkins.getInstanceOrNull();
			if (j == null) {
				return new Sec1CliInstallation[0];
			}
			SecOneScannerPlugin.DescriptorImpl d = j.getDescriptorByType(SecOneScannerPlugin.DescriptorImpl.class);
			return d == null ? new Sec1CliInstallation[0] : d.getCliInstallations();
		}

		@Override
		public void setInstallations(Sec1CliInstallation... installations) {
			Jenkins j = Jenkins.getInstanceOrNull();
			if (j == null) {
				return;
			}
			SecOneScannerPlugin.DescriptorImpl d = j.getDescriptorByType(SecOneScannerPlugin.DescriptorImpl.class);
			if (d != null) {
				d.setCliInstallations(installations);
			}
		}
	}
}
