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

public class Sec1SastInstallation extends ToolInstallation
		implements EnvironmentSpecific<Sec1SastInstallation>, NodeSpecific<Sec1SastInstallation> {

	private static final long serialVersionUID = 1L;

	@DataBoundConstructor
	public Sec1SastInstallation(@NonNull String name, @Nullable String home,
			@Nullable List<? extends ToolProperty<?>> properties) {
		super(name, home, properties == null ? Collections.emptyList() : properties);
	}

	@Override
	public Sec1SastInstallation forEnvironment(EnvVars env) {
		return new Sec1SastInstallation(getName(), env.expand(getHome()), getProperties().toList());
	}

	@Override
	public Sec1SastInstallation forNode(@NonNull Node node, TaskListener log) throws IOException, InterruptedException {
		return new Sec1SastInstallation(getName(), translateFor(node, log), getProperties().toList());
	}

	public String getExecutable(@NonNull Launcher launcher) throws IOException, InterruptedException {
		VirtualChannel channel = launcher.getChannel();
		if (channel == null) {
			throw new IOException("Unable to resolve sec1-sast executable: launcher has no channel.");
		}
		final String home = Util.fixEmptyAndTrim(getHome());
		if (home == null) {
			throw new IOException("sec1-sast installation '" + getName() + "' has no home directory set.");
		}
		return channel.call(new ResolveExecutable(home));
	}

	private static class ResolveExecutable extends MasterToSlaveCallable<String, IOException> {
		private static final long serialVersionUID = 1L;
		private final String home;

		ResolveExecutable(String home) {
			this.home = home;
		}

		@Override
		public String call() throws IOException {
			Platform platform = Platform.current();
			java.io.File homeDir = new java.io.File(home);
			java.io.File installed = new java.io.File(homeDir, platform.getInstalledFileName());
			if (installed.isFile()) {
				return installed.getAbsolutePath();
			}
			if (homeDir.isFile()) {
				return homeDir.getAbsolutePath();
			}
			throw new IOException("sec1-sast binary not found under " + home
					+ " (looked for " + platform.getInstalledFileName() + ").");
		}
	}

	@Extension
	@Symbol("sec1Sast")
	public static class DescriptorImpl extends ToolDescriptor<Sec1SastInstallation> {

		@NonNull
		@Override
		public String getDisplayName() {
			return "Sec1 SAST CLI";
		}

		@Override
		public List<? extends ToolInstaller> getDefaultInstallers() {
			return Collections.singletonList(new Sec1SastInstaller(null));
		}

		@Override
		public Sec1SastInstallation[] getInstallations() {
			Jenkins j = Jenkins.getInstanceOrNull();
			if (j == null) {
				return new Sec1SastInstallation[0];
			}
			SecOneScannerPlugin.DescriptorImpl d = j.getDescriptorByType(SecOneScannerPlugin.DescriptorImpl.class);
			return d == null ? new Sec1SastInstallation[0] : d.getSastInstallations();
		}

		@Override
		public void setInstallations(Sec1SastInstallation... installations) {
			Jenkins j = Jenkins.getInstanceOrNull();
			if (j == null) {
				return;
			}
			SecOneScannerPlugin.DescriptorImpl d = j.getDescriptorByType(SecOneScannerPlugin.DescriptorImpl.class);
			if (d != null) {
				d.setSastInstallations(installations);
			}
		}
	}
}
