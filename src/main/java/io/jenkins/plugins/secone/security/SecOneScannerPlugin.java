package io.jenkins.plugins.secone.security;

import java.io.BufferedReader;
import java.io.File;
import java.io.FileReader;
import java.io.IOException;
import java.io.InputStream;
import java.io.PrintStream;
import java.net.MalformedURLException;
import java.net.URI;
import java.net.URISyntaxException;
import java.net.URL;
import java.nio.charset.Charset;
import java.nio.charset.StandardCharsets;
import java.nio.file.Files;
import java.nio.file.Path;
import java.nio.file.Paths;
import java.util.Collections;

import org.apache.commons.io.IOUtils;
import org.apache.commons.lang.StringUtils;
import org.apache.commons.lang.math.NumberUtils;
import org.apache.http.ConnectionClosedException;
import org.apache.http.HttpResponse;
import org.apache.http.client.methods.HttpPost;
import org.apache.http.entity.StringEntity;
import org.apache.http.impl.client.CloseableHttpClient;
import org.jenkinsci.Symbol;
import org.jenkinsci.plugins.plaincredentials.StringCredentials;
import org.json.JSONArray;
import org.json.JSONObject;
import org.kohsuke.stapler.DataBoundConstructor;
import org.kohsuke.stapler.DataBoundSetter;
import org.slf4j.Logger;
import org.slf4j.LoggerFactory;

import com.cloudbees.plugins.credentials.CredentialsProvider;

import hudson.AbortException;
import hudson.EnvVars;
import hudson.Extension;
import hudson.FilePath;
import hudson.Launcher;
import hudson.Plugin;
import hudson.XmlFile;
import hudson.model.AbstractBuild;
import hudson.model.AbstractProject;
import hudson.model.BuildListener;
import hudson.model.Job;
import hudson.model.Result;
import hudson.model.Run;
import hudson.model.TaskListener;
import hudson.tasks.BuildStepDescriptor;
import hudson.tasks.Builder;
import io.jenkins.plugins.secone.security.object.factory.ObjectFactory;
import io.jenkins.plugins.secone.security.pojo.Threshold;
import jenkins.model.Jenkins;
import jenkins.tasks.SimpleBuildStep;

public class SecOneScannerPlugin extends Builder implements SimpleBuildStep {

	private static final Logger logger = LoggerFactory.getLogger(SecOneScannerPlugin.class);

	private static final String API_CONTEXT = "/rest";

	private static final String SCA_SCAN_API = "/foss/ascan?enableSbom=true";

	private static final String SCA_STATUS_CHECK_URL = "/foss/report/status";

	private static final String INSTANCE_URL = "SEC1_INSTANCE_URL";

	private static final String DASHBOARD_URL = "SEC1_DASHBOARD_URL";

	private static final String SAST_SCAN_API = "/foss/sast/ascan";

	private static final String SAST_STATUS_CHECK_URL = "/sast/asset/report/status";

	private static final String API_KEY = "SEC1_API_KEY";

	private static final String API_KEY_HEADER = "sec1-api-key";

	private String apiCredentialsId;
	private boolean applyThreshold;

	private String actionOnThresholdBreached;

	private Threshold threshold;

	private boolean runSca;

	private boolean runSast;

	private String scanTag;

	private boolean printInAnsiColor;

	private ObjectFactory objectFactory;

	@DataBoundConstructor
	public SecOneScannerPlugin(String apiCredentialsId) {
		this.apiCredentialsId = apiCredentialsId;
		this.objectFactory = new ObjectFactory();
		this.runSca = true;
		this.runSast = true;
	}

	public String getApiCredentialsId() {
		return apiCredentialsId;
	}

	public void setApiCredentialsId(String apiCredentialsId) {
		this.apiCredentialsId = apiCredentialsId;
	}

	public boolean isApplyThreshold() {
		return applyThreshold;
	}

	@DataBoundSetter
	public void setApplyThreshold(boolean applyThreshold) {
		this.applyThreshold = applyThreshold;
	}

	public Threshold getThreshold() {
		return threshold;
	}

	@DataBoundSetter
	public void setThreshold(Threshold threshold) {
		this.threshold = threshold;
	}

	public String getActionOnThresholdBreached() {
		return actionOnThresholdBreached;
	}

	@DataBoundSetter
	public void setActionOnThresholdBreached(String actionOnThresholdBreached) {
		this.actionOnThresholdBreached = actionOnThresholdBreached;
	}

	public boolean isRunSca() {
		return runSca;
	}

	@DataBoundSetter
	public void setRunSca(boolean runSca) {
		this.runSca = runSca;
	}

	public boolean isRunSast() {
		return runSast;
	}

	@DataBoundSetter
	public void setRunSast(boolean runSast) {
		this.runSast = runSast;
	}

	public String getScanTag() {
		return scanTag;
	}

	@DataBoundSetter
	public void setScanTag(String scanTag) {
		this.scanTag = scanTag;
	}

	// Backward compatibility for tag
	public String getTag() {
		return scanTag;
	}

	public void setTag(String tag) {
		this.scanTag = tag;
	}

	// Backward compatibility
	public boolean isRunSec1SastSecurity() {
		return runSast;
	}

	public void setRunSec1SastSecurity(boolean runSec1SastSecurity) {
		this.runSast = runSec1SastSecurity;
	}

	// from UI
	@Override
	public boolean perform(AbstractBuild<?, ?> build, Launcher launcher, BuildListener listener)
			throws IOException, InterruptedException {
		// printStartMessage(listener);
		if (threshold != null) {
			applyThreshold = true;
		}
		if (objectFactory == null) {
			objectFactory = new ObjectFactory();
		}
		printInAnsiColor = isAnsiColorPluginInstalled(build.getParent());
		String workingDirectory = getGitWorkingDirectory(build.getEnvironment(listener), listener);
		int result = performScan(build, listener, applyThreshold, workingDirectory);
		if (result != 0) {
			build.setResult(Result.UNSTABLE);
		}
		return true;
	}

	private void printScaStartMessage(TaskListener listener) {
		printLogs(listener.getLogger(), "=============== Sec1 SCA Scan Start ===============", "g");
	}

	private void printScaEndMessage(TaskListener listener) {
		printLogs(listener.getLogger(), "=============== Sec1 SCA Scan End ===============", "g");
	}

	private void printSastStartMessage(TaskListener listener) {
		printLogs(listener.getLogger(), "=============== Sec1 SAST Scan Start ===============", "g");
	}

	private void printSastEndMessage(TaskListener listener) {
		printLogs(listener.getLogger(), "=============== Sec1 SAST Scan End ===============", "g");
	}

	private String getInstanceUrl(EnvVars envVars, TaskListener listener) {
		String instanceUrl = envVars.get(INSTANCE_URL);
		if (StringUtils.isNotBlank(instanceUrl)) {
			listener.getLogger().println("SEC1_INSTANCE_URL : " + instanceUrl);
			return instanceUrl;
		}
		// listener.getLogger()
		// .println("No environment variable SEC1_INSTANCE_URL set. Using default :
		// https://api.sec1.io");
		return "https://api.sec1.io";
	}

	private String getDashboardUrl(EnvVars envVars, TaskListener listener) {
		String dashboardUrl = envVars.get(DASHBOARD_URL);
		if (StringUtils.isNotBlank(dashboardUrl)) {
			listener.getLogger().println("SEC1_DASHBOARD_URL : " + dashboardUrl);
			return dashboardUrl;
		}
		return "https://unified.sec1.io";
	}

	// From script
	@Override
	public void perform(Run<?, ?> run, FilePath workspace, EnvVars env, Launcher launcher, TaskListener listener)
			throws InterruptedException, IOException {

		if (objectFactory == null) {
			objectFactory = new ObjectFactory();
		}

		printInAnsiColor = isAnsiColorPluginInstalled(run.getParent());

		String workingDirectory = getGitWorkingDirectory(env, listener);

		if (StringUtils.isBlank(actionOnThresholdBreached)) {
			printLogs(listener.getLogger(), "actionOnThresholdBreached is not set. Default action is fail.", "g");
		} else if (StringUtils.equalsIgnoreCase(actionOnThresholdBreached, "fail")
				|| StringUtils.equalsIgnoreCase(actionOnThresholdBreached, "unstable")
				|| StringUtils.equalsIgnoreCase(actionOnThresholdBreached, "continue")) {
			if (threshold != null) {
				getThreshold().setStatusAction(actionOnThresholdBreached);
			}
		}

		int result = performScan(run, listener, applyThreshold, workingDirectory);
		if (result != 0) {
			run.setResult(Result.UNSTABLE);
		}
	}

	public String getApiKey(Run<?, ?> run, TaskListener listener) {
		if (StringUtils.isNotBlank(apiCredentialsId)) {
			printLogs(listener.getLogger(), "Resolving API key from configured credentials.", "g");

			StringCredentials apiKeyCreds = CredentialsProvider.findCredentialById(apiCredentialsId,
					StringCredentials.class, run, Collections.emptyList());

			if (apiKeyCreds == null) {
				printLogs(listener.getLogger(), "Configured credentials not found. Trying default credentials.", "g");
				apiKeyCreds = CredentialsProvider.findCredentialById(API_KEY, StringCredentials.class, run,
						Collections.emptyList());
			}
			if (apiKeyCreds != null) {
				String apiKey = apiKeyCreds.getSecret().getPlainText();
				return apiKey;
			}
		} else {
			printLogs(listener.getLogger(), "No credentials ID configured. Using default credentials.", "g");
			StringCredentials apiKeyCreds = CredentialsProvider.findCredentialById(API_KEY, StringCredentials.class,
					run, Collections.emptyList());
			if (apiKeyCreds != null) {
				String apiKey = apiKeyCreds.getSecret().getPlainText();
				return apiKey;
			}
		}
		return null;
	}

	@Override
	public boolean requiresWorkspace() {
		// return SimpleBuildStep.super.requiresWorkspace();
		return true;
	}

	private int performScan(Run<?, ?> run, TaskListener listener, boolean applyThreshold, String workingDirectory)
			throws AbortException {

		String sec1ApiKey = getApiKey(run, listener);

		if (StringUtils.isBlank(sec1ApiKey)) {
			throw new AbortException(getErrorMessageInAnsi("API Key not configured. Please check your configuration."));
		}

		StringBuilder fossInstanceUrl = new StringBuilder();
		StringBuilder scmUrl = new StringBuilder();

		String dashboardUrl = null;
		try {
			EnvVars envVars = run.getEnvironment(listener);
			fossInstanceUrl.append(getInstanceUrl(envVars, listener));
			dashboardUrl = getDashboardUrl(envVars, listener);
		} catch (IOException | InterruptedException e) {
			throw new AbortException(getErrorMessageInAnsi("Exception while getting environment variables."));
		}
		String gitUrl = null;
		try {
			gitUrl = getGitUrl(workingDirectory);
			if (StringUtils.isBlank(gitUrl)) {
				gitUrl = run.getEnvironment(listener).get("GIT_URL");
			}
		} catch (IOException | InterruptedException e) {
			logger.error("Error - Check your git configuration. ", e);
		}
		if (StringUtils.isBlank(gitUrl)) {
			throw new AbortException(
					getErrorMessageInAnsi("Exception while getting getting git url. Check your git configuration."));
		}
		scmUrl.append(gitUrl);
		StringBuilder appName = new StringBuilder();
		try {
			appName.append(getSubUrl(scmUrl.toString()));
		} catch (Exception ex) {
			logger.error("Error - extracting app name from url", ex);
			logger.info("Issue extracting app name from url, setting it to default");
			appName = new StringBuilder(scmUrl);
		}
		String banchName = null;
		try {
			banchName = getGitBranch(workingDirectory);
			if (StringUtils.isBlank(banchName)) {
				banchName = run.getEnvironment(listener).get("GIT_BRANCH");
			}
		} catch (Exception ex) {
			logger.error("Error - extracting branch name for scm url : {}", scmUrl, ex);
		}
		String resolvedTag = StringUtils.isNotBlank(scanTag) ? scanTag : (StringUtils.isNotBlank(banchName) ? banchName : "default");

		int scaResult = 0;
		int sastResult = 0;
		AbortException scaAbortException = null;

		if (runSca) {
			try {
				scaResult = runScaScan(fossInstanceUrl, listener, sec1ApiKey, workingDirectory, scmUrl, appName,
						banchName, dashboardUrl, resolvedTag);
			} catch (AbortException ex) {
				if (runSast) {
					// Save exception to re-throw after SAST scan completes
					printLogs(listener.getLogger(), "SCA scan failed: " + ex.getMessage(), "r");
					scaResult = -1;
					scaAbortException = ex;
				} else {
					throw ex;
				}
			}
		}

		if (runSast) {
			try {
				sastResult = runSastScan(fossInstanceUrl, listener, sec1ApiKey, workingDirectory, scmUrl, appName,
						banchName, dashboardUrl, resolvedTag);
			} catch (InterruptedException ex) {
				printLogs(listener.getLogger(), "Error while running sast scan. Failed to wait for result.", "r");
				sastResult = -1;
			}
		}

		if (!runSca && !runSast) {
			printLogs(listener.getLogger(), "No scan type selected. Enable at least one of runSca or runSast.", "r");
		}

		// If SCA had a fatal failure, re-throw after SAST has completed
		if (scaAbortException != null) {
			throw scaAbortException;
		}

		// Return the worst result from both scans
		return Math.max(scaResult, sastResult);
	}

	private int runSastScan(StringBuilder fossInstanceUrl, TaskListener listener, String sec1ApiKey,
			String workingDirectory, StringBuilder scmUrl, StringBuilder appName, String branchName,
			String dashboardUrl, String resolvedTag) throws AbortException, InterruptedException {
		printSastStartMessage(listener);
		int result = 0;

		JSONObject inputParamsMap = new JSONObject();
		JSONObject requestJson = new JSONObject();
		requestJson.put("location", scmUrl);
		if (StringUtils.isNotBlank(branchName)) {
			requestJson.put("branchName", getSanitizedBranchName(branchName));
		}

		requestJson.put("appName", appName);
		requestJson.put("source", "jenkins");
		requestJson.put("tag", resolvedTag);

		JSONArray inputParams = new JSONArray();
		inputParams.put(requestJson);

		inputParamsMap.put("scanRequestList", inputParams);

		listener.getLogger().println("-------------------- Sec1 SAST Scan Config --------------------");
		listener.getLogger().println("SCM Url                " + scmUrl);
		listener.getLogger().println("Tag                    " + resolvedTag);
		listener.getLogger().println("Threshold              " + (applyThreshold ? "Enabled" : "Disabled"));
		if (threshold != null && applyThreshold) {
			listener.getLogger().println("Threshold Values       Critical: "
					+ (StringUtils.isNotBlank(threshold.getCriticalThreshold()) ? threshold.getCriticalThreshold()
							: "NA")
					+ ", High: "
					+ (StringUtils.isNotBlank(threshold.getHighThreshold()) ? threshold.getHighThreshold() : "NA")
					+ ", Medium: "
					+ (StringUtils.isNotBlank(threshold.getMediumThreshold()) ? threshold.getMediumThreshold() : "NA")
					+ ", Low: "
					+ (StringUtils.isNotBlank(threshold.getLowThreshold()) ? threshold.getLowThreshold() : "NA"));
		}
		String scanUrl = fossInstanceUrl + API_CONTEXT + SAST_SCAN_API;

		HttpResponse responseEntity = triggerSastScan(scanUrl, inputParamsMap, sec1ApiKey);
		if (responseEntity != null && responseEntity.getStatusLine().getStatusCode() == 200) {
			String sastStatusCheckUrl = fossInstanceUrl + SAST_STATUS_CHECK_URL;
			try (CloseableHttpClient client = objectFactory.createHttpClient(new URI(sastStatusCheckUrl))) {
				if (responseEntity.getEntity() != null) {
					org.apache.http.HttpEntity httpScanResponseEntity = responseEntity.getEntity();
					if (httpScanResponseEntity.getContent() != null) {
						JSONArray responseJsonArray = null;
						try (InputStream rawContent = httpScanResponseEntity.getContent()) {
							byte[] bytes = IOUtils.toByteArray(rawContent);
							String content = new String(bytes, Charset.defaultCharset().name());

							responseJsonArray = new JSONArray(content);
						}
						if (responseJsonArray == null || responseJsonArray.length() == 0) {
							throw new AbortException(
									getErrorMessageInAnsi("Error while processing scan result. Failing the build."));
						}

						String reportId = responseJsonArray.getJSONObject(0).optString("uuid");

						String scanStatus = "INITIATED";
						JSONObject responseJson = new JSONObject();
						long startTime = System.currentTimeMillis();
						long maxDuration = 10 * 60 * 1000; // 10 minutes

						HttpPost statusPost = objectFactory.createHttpPost(sastStatusCheckUrl);
						statusPost.setHeader(API_KEY_HEADER, sec1ApiKey);
						statusPost.setHeader("Content-Type", "application/json");
						statusPost.setHeader("Accept", "application/json");

						while (!StringUtils.equalsIgnoreCase("COMPLETED", scanStatus)) {
							if (System.currentTimeMillis() - startTime > maxDuration) {
								listener.getLogger().println("-------------------- Sec1 SAST Scan Result --------------------");
								listener.getLogger().println("Report Url             " + dashboardUrl + "/sast-advance-dashboard/" + reportId);
								listener.getLogger().println("Status                 TIMED OUT");
								throw new AbortException(
										getErrorMessageInAnsi("Sec1 SAST Scan timed out after 10 minutes."));
							}

							// Sleep for 10 seconds before polling again
							Thread.sleep(10000);

							JSONObject statusPayload = new JSONObject();
							JSONArray reportIdArray = new JSONArray();
							reportIdArray.put(reportId);
							statusPayload.put("reportId", reportIdArray);
							statusPost.setEntity(new StringEntity(statusPayload.toString()));

							HttpResponse statusResponse = client.execute(statusPost);

							org.apache.http.HttpEntity statusEntity = statusResponse.getEntity();

							try (InputStream statusRawContent = statusEntity.getContent()) {
								byte[] statusBytes = IOUtils.toByteArray(statusRawContent);

								String statusContent = new String(statusBytes, Charset.defaultCharset().name());
								JSONArray statusArray = new JSONArray(statusContent);
								responseJson = statusArray.getJSONObject(0);
								scanStatus = responseJson.getString("scanStatus");
							}

							if (StringUtils.equalsIgnoreCase("SCANNING", scanStatus)) {
								listener.getLogger().println("Sec1 SAST Scan in progress...");
							} else if (scanStatus.equals("FAILED")) {
								listener.getLogger()
										.println("-------------------- Sec1 SAST Scan Result --------------------");
								listener.getLogger().println("Report Url             "
										+ dashboardUrl + "/sast-advance-dashboard/" + reportId);
								listener.getLogger().println("Status                 FAILURE");
								throw new AbortException(
										getErrorMessageInAnsi("Sec1 SAST Security Scan Finished with failures"));
							}
						}

						if (responseJson != null) {
							int critical = responseJson.optInt("critical");
							int high = responseJson.optInt("high");
							int medium = responseJson.optInt("medium");
							int low = responseJson.optInt("low");

							listener.getLogger()
									.println("-------------------- Sec1 SAST Scan Result --------------------");
							if (StringUtils.isBlank(responseJson.optString("errorMessage"))) {
								String reportUrl = dashboardUrl + "/sast-advance-dashboard/" + reportId;
								listener.getLogger().println("Vulnerabilities        Critical: " + critical
										+ ", High: " + high + ", Medium: " + medium + ", Low: " + low);
								listener.getLogger().println("Report Url             " + reportUrl);

								if (applyThreshold) {
									if (critical != 0 && threshold.getCriticalThreshold() != null
											&& NumberUtils.isDigits(threshold.getCriticalThreshold())
											&& critical >= Integer.parseInt(threshold.getCriticalThreshold())) {
										String message = "Critical Vulnerability Threshold breached. Found: " + critical + ", Allowed: " + threshold.getCriticalThreshold();
										result = failBuildOnThresholdBreach(message, listener, threshold);
									}
									if (high != 0 && threshold.getHighThreshold() != null
											&& NumberUtils.isDigits(threshold.getHighThreshold())
											&& high >= Integer.parseInt(threshold.getHighThreshold())) {
										String message = "High Vulnerability Threshold breached. Found: " + high + ", Allowed: " + threshold.getHighThreshold();
										result = failBuildOnThresholdBreach(message, listener, threshold);
									}
									if (medium != 0 && threshold.getMediumThreshold() != null
											&& NumberUtils.isDigits(threshold.getMediumThreshold())
											&& medium >= Integer.parseInt(threshold.getMediumThreshold())) {
										String message = "Medium Vulnerability Threshold breached. Found: " + medium + ", Allowed: " + threshold.getMediumThreshold();
										result = failBuildOnThresholdBreach(message, listener, threshold);
									}
									if (low != 0 && threshold.getLowThreshold() != null
											&& NumberUtils.isDigits(threshold.getLowThreshold())
											&& low >= Integer.parseInt(threshold.getLowThreshold())) {
										String message = "Low Vulnerability Threshold breached. Found: " + low + ", Allowed: " + threshold.getLowThreshold();
										result = failBuildOnThresholdBreach(message, listener, threshold);
									}
								}

							} else {
								printLogs(listener.getLogger(),
										"Error Details : " + responseJson.optString("errorMessage"), "r");
								result = 2;
							}
						}
					} else {
						logger.info("Invalid content recevied");
						throw new AbortException(
								getErrorMessageInAnsi("Error while processing sast scan result. Failing the build."));
					}
				}
			} catch (AbortException ex) {
				printSastEndMessage(listener);
				throw ex;
			} catch (IOException ex) {
				logger.error("SAST scan failed with IOException", ex);
				printSastEndMessage(listener);
				throw new AbortException(getErrorMessageInAnsi("Attention: Build Failed. Check configuration. " + ex.getMessage()));
			} catch (URISyntaxException e) {
				throw new AbortException(getErrorMessageInAnsi("Attention: Check configured Sec1 API url."));
			}
		} else {
			logger.error("Issue while getting response from system.");
			throw new AbortException(getErrorMessageInAnsi("Error while processing scan result. Failing the build."));
		}

		printSastEndMessage(listener);
		return result;
	}

	private String getSanitizedBranchName(String branchName) {
		if (branchName != null && branchName.startsWith("origin/")) {
			branchName = branchName.substring("origin/".length());
		}
		return branchName;
	}

	private HttpResponse triggerSastScan(String apiUrl, JSONObject inputParamsMap, String sec1ApiKey) {
		try (CloseableHttpClient client = objectFactory.createHttpClient(new URI(apiUrl))) {
			HttpPost httpPost = objectFactory.createHttpPost(apiUrl);
			httpPost.addHeader(API_KEY_HEADER, sec1ApiKey);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Accept", "application/json");
			StringEntity stringEntity = new StringEntity(inputParamsMap.toString(), StandardCharsets.UTF_8);

			httpPost.setEntity(stringEntity);

			HttpResponse response = client.execute(httpPost);
			return response;
		} catch (IOException e) {
			logger.error("Issue while connecting to api.", e);
		} catch (URISyntaxException e) {
			logger.error("Check configured Sec1 API url => {}", apiUrl, e);
		}
		return null;
	}

	public String getGitBranch(String repositoryPath) throws IOException {
		Path headFilePath = Paths.get(repositoryPath, ".git", "HEAD");
		if (!Files.exists(headFilePath)) {
			return null;
		}

		try (BufferedReader reader = Files.newBufferedReader(headFilePath, StandardCharsets.UTF_8)) {
			String headContent = reader.readLine();
			if (headContent != null && headContent.startsWith("ref:")) {
				String[] parts = headContent.split("/");
				return parts[parts.length - 1]; // Returns the branch name
			}
		}

		return null;
	}

	private int runScaScan(StringBuilder fossInstanceUrl, TaskListener listener, String sec1ApiKey,
			String workingDirectory, StringBuilder scmUrl, StringBuilder appName,
			String branchName, String dashboardUrl, String resolvedTag) throws AbortException {

		printScaStartMessage(listener);

		int result = 0;

		String scanUrl = fossInstanceUrl + API_CONTEXT + SCA_SCAN_API;
		JSONObject rquestJson = new JSONObject();
		JSONArray scanRequestList = new JSONArray();

		JSONObject inputParamsMap = new JSONObject();
		inputParamsMap.put("location", scmUrl);
		inputParamsMap.put("appName", appName);
		inputParamsMap.put("source", "jenkins");
		inputParamsMap.put("tag", resolvedTag);
		if (StringUtils.isNotBlank(branchName)) {
			inputParamsMap.put("branchName", getSanitizedBranchName(branchName));
		}

		scanRequestList.put(inputParamsMap);
		rquestJson.put("scanRequestList", scanRequestList);

		listener.getLogger().println("-------------------- Sec1 SCA Scan Config --------------------");
		listener.getLogger().println("SCM Url                " + scmUrl);
		listener.getLogger().println("Tag                    " + resolvedTag);
		listener.getLogger().println("Threshold              " + (applyThreshold ? "Enabled" : "Disabled"));
		if (threshold != null && applyThreshold) {
			listener.getLogger().println("Threshold Values       Critical: "
					+ (StringUtils.isNotBlank(threshold.getCriticalThreshold()) ? threshold.getCriticalThreshold()
							: "NA")
					+ ", High: "
					+ (StringUtils.isNotBlank(threshold.getHighThreshold()) ? threshold.getHighThreshold() : "NA")
					+ ", Medium: "
					+ (StringUtils.isNotBlank(threshold.getMediumThreshold()) ? threshold.getMediumThreshold() : "NA")
					+ ", Low: "
					+ (StringUtils.isNotBlank(threshold.getLowThreshold()) ? threshold.getLowThreshold() : "NA"));
		}

		HttpResponse responseEntity = triggerScaScan(scanUrl, rquestJson.toString(), sec1ApiKey);
		if (responseEntity != null && responseEntity.getStatusLine().getStatusCode() == 200) {
			String scaStatusCheckUrl = fossInstanceUrl + SCA_STATUS_CHECK_URL;
			try (CloseableHttpClient client = objectFactory.createHttpClient(new URI(scaStatusCheckUrl))) {
				if (responseEntity.getEntity() != null) {
					org.apache.http.HttpEntity httpScanResponseEntity = responseEntity.getEntity();
					if (httpScanResponseEntity.getContent() != null) {
						JSONArray responseJsonArray = null;
						try (InputStream rawContent = httpScanResponseEntity.getContent()) {
							byte[] bytes = IOUtils.toByteArray(rawContent);
							String content = new String(bytes, Charset.defaultCharset().name());
							responseJsonArray = new JSONArray(content);
						}
						if (responseJsonArray == null || responseJsonArray.length() == 0) {
							throw new AbortException(
									getErrorMessageInAnsi("Error while processing scan result. Failing the build."));
						}

						String reportId = responseJsonArray.getJSONObject(0).optString("uuid");

						String scanStatus = "INITIATED";
						long startTime = System.currentTimeMillis();
						long maxDuration = 10 * 60 * 1000; // 10 minutes

						HttpPost statusPost = objectFactory.createHttpPost(scaStatusCheckUrl);
						statusPost.setHeader(API_KEY_HEADER, sec1ApiKey);
						statusPost.setHeader("Content-Type", "application/json");
						statusPost.setHeader("Accept", "application/json");
						JSONObject responseJson = null;
						while (!StringUtils.equalsIgnoreCase("COMPLETED", scanStatus)) {
							if (System.currentTimeMillis() - startTime > maxDuration) {
								listener.getLogger().println("-------------------- Sec1 SCA Scan Result --------------------");
								listener.getLogger().println("Report Url             " + dashboardUrl + "/dashboard-scan-details/" + reportId);
								listener.getLogger().println("Status                 TIMED OUT");
								throw new AbortException(
										getErrorMessageInAnsi("Sec1 SCA Scan timed out after 10 minutes."));
							}

							// Sleep for 10 seconds before polling again
							Thread.sleep(10000);

							JSONArray reportIdArray = new JSONArray();
							reportIdArray.put(reportId);
							statusPost.setEntity(new StringEntity(reportIdArray.toString()));

							HttpResponse statusResponse = client.execute(statusPost);

							org.apache.http.HttpEntity statusEntity = statusResponse.getEntity();

							try (InputStream statusRawContent = statusEntity.getContent()) {
								byte[] statusBytes = IOUtils.toByteArray(statusRawContent);

								String statusContent = new String(statusBytes, Charset.defaultCharset().name());

								responseJson = new JSONObject(statusContent);
							}
							scanStatus = responseJson.getJSONObject(reportId).getString("status");
							if (!StringUtils.equalsIgnoreCase("FAILED", scanStatus)
									&& !StringUtils.equalsIgnoreCase("COMPLETED", scanStatus)) {
								listener.getLogger().println("Sec1 SCA Scan in progress...");
							} else if (scanStatus.equals("FAILED")) {
								JSONObject scanResult = responseJson.getJSONObject(reportId)
										.optJSONObject("scannerResponseEntity");
								listener.getLogger()
										.println("-------------------- Sec1 SCA Scan Result --------------------");
								if (scanResult != null) {
									listener.getLogger()
											.println("Report Url             " + scanResult.optString("reportUrl"));
								}
								listener.getLogger().println("Status                 FAILURE");
								throw new AbortException(
										getErrorMessageInAnsi("Sec1 SCA Security Scan Finished with failures"));
							}
						}
						if (responseJson != null) {
							JSONObject scanResult = responseJson.getJSONObject(reportId)
									.optJSONObject("scannerResponseEntity");
							if (scanResult != null && scanResult.has("cveCountDetails")) {
								int critical = scanResult.optJSONObject("cveCountDetails") != null
										? scanResult.getJSONObject("cveCountDetails").optInt("CRITICAL")
										: 0;
								int high = scanResult.optJSONObject("cveCountDetails") != null
										? scanResult.getJSONObject("cveCountDetails").optInt("HIGH")
										: 0;
								int medium = scanResult.optJSONObject("cveCountDetails") != null
										? scanResult.getJSONObject("cveCountDetails").optInt("MEDIUM")
										: 0;
								int low = scanResult.optJSONObject("cveCountDetails") != null
										? scanResult.getJSONObject("cveCountDetails").optInt("LOW")
										: 0;

								listener.getLogger()
										.println("-------------------- Sec1 SCA Scan Result --------------------");
								if (StringUtils.isBlank(scanResult.optString("errorMessage"))) {
									listener.getLogger().println("Vulnerabilities        Critical: " + critical
											+ ", High: " + high + ", Medium: " + medium + ", Low: " + low);
									listener.getLogger().println("Status                 " + scanResult.optString("overallRagStatus").toUpperCase());
									listener.getLogger()
											.println("Report Url             " + scanResult.optString("reportUrl"));

									if (applyThreshold) {
										try {
											if (critical != 0 && threshold.getCriticalThreshold() != null
													&& NumberUtils.isDigits(threshold.getCriticalThreshold())
													&& critical >= Integer.parseInt(threshold.getCriticalThreshold())) {
												String message = "Critical Vulnerability Threshold breached. Found: " + critical + ", Allowed: " + threshold.getCriticalThreshold();
												result = failBuildOnThresholdBreach(message, listener, threshold);
											}
											if (high != 0 && threshold.getHighThreshold() != null
													&& NumberUtils.isDigits(threshold.getHighThreshold())
													&& high >= Integer.parseInt(threshold.getHighThreshold())) {
												String message = "High Vulnerability Threshold breached. Found: " + high + ", Allowed: " + threshold.getHighThreshold();
												result = failBuildOnThresholdBreach(message, listener, threshold);
											}
											if (medium != 0 && threshold.getMediumThreshold() != null
													&& NumberUtils.isDigits(threshold.getMediumThreshold())
													&& medium >= Integer.parseInt(threshold.getMediumThreshold())) {
												String message = "Medium Vulnerability Threshold breached. Found: " + medium + ", Allowed: " + threshold.getMediumThreshold();
												result = failBuildOnThresholdBreach(message, listener, threshold);
											}
											if (low != 0 && threshold.getLowThreshold() != null
													&& NumberUtils.isDigits(threshold.getLowThreshold())
													&& low >= Integer.parseInt(threshold.getLowThreshold())) {
												String message = "Low Vulnerability Threshold breached. Found: " + low + ", Allowed: " + threshold.getLowThreshold();
												result = failBuildOnThresholdBreach(message, listener, threshold);
											}
										} catch (AbortException ex) {
											throw new AbortException(getErrorMessageInAnsi(
													"Attention: Build Failed because of vulnerability threshold level breached for sca."));
										}
									}
								} else {
									printLogs(listener.getLogger(),
											"Error Details : " + scanResult.optString("errorMessage"), "r");
									result = 2;
								}
							}
						} else {
							logger.info("Invalid content recevied");
							throw new AbortException(getErrorMessageInAnsi(
									"Error while processing scan result. Failing the build."));
						}
					} else {
						logger.info("Invalid content recevied");
						throw new AbortException(
								getErrorMessageInAnsi("Error while processing scan result. Failing the build."));
					}
				}
			} catch (AbortException ex) {
				throw ex;
			} catch (ConnectionClosedException ex) {
				logger.info("Attention: Connectivity issue. Please try again.", ex);
				throw new AbortException(getErrorMessageInAnsi("Attention: Connectivity issue. Please try again."));
			} catch (IOException | InterruptedException e) {
				logger.info("Build Failed. Check configuration.", e);
				throw new AbortException(getErrorMessageInAnsi("Attention: Build Failed. Check configuration."));
			} catch (URISyntaxException e) {
				throw new AbortException(getErrorMessageInAnsi("Attention: Check configured Sec1 API url."));
			}
		} else {
			if (responseEntity != null && responseEntity.getStatusLine().getStatusCode() == 401) {
				throw new AbortException(getErrorMessageInAnsi("401 Unauthorized. Check your api key."));
			}
			logger.error("Issue while getting response from system.");
			throw new AbortException(
					getErrorMessageInAnsi("Error while processing sca scan result. Failing the build."));
		}
		printScaEndMessage(listener);
		return result;
	}

	private void printLogs(PrintStream logger, String message, String color) {
		if (printInAnsiColor) {
			if (StringUtils.isNotBlank(color)) {
				switch (color) {
				case "g":
					logger.println("\u001B[32m" + message + "\u001B[0m");
					break;
				case "r":
					logger.println("\u001B[31m" + message + "\u001B[0m");
					break;
				default:
					logger.println(message);
					break;
				}
			} else {
				logger.println(message);
			}
		} else {
			logger.println(message);
		}
	}

	private String getErrorMessageInAnsi(String message) {
		if (printInAnsiColor) {
			return "\u001B[31m" + message + "\u001B[0m";
		}
		return message;
	}

	private int failBuildOnThresholdBreach(String message, TaskListener listener, Threshold threshold)
			throws AbortException {
		if (StringUtils.isNotBlank(threshold.getStatusAction())) {
			if (StringUtils.equalsIgnoreCase(threshold.getStatusAction(), "fail")) {
				throw new AbortException(message + " Failing the build.");
			} else if (StringUtils.equalsIgnoreCase(threshold.getStatusAction(), "unstable")) {
				printLogs(listener.getLogger(), message, "r");
				return 2;
			} else {
				listener.getLogger().println(message);
			}
		} else {
			throw new AbortException(message + " Failing the build.");
		}
		return 0;
	}

	@Symbol({"sec1Security", "sec1ScaSastSecurity"})
	@Extension
	public static final class DescriptorImpl extends BuildStepDescriptor<Builder> {

		public DescriptorImpl() {
			super(SecOneScannerPlugin.class);
		}

		@Override
		public boolean isApplicable(Class<? extends AbstractProject> aClass) {
			return true;
		}

		@Override
		public String getDisplayName() {
			return "Execute Sec1 Security Scan";
		}
	}

	private String getSubUrl(String scmUrl) throws MalformedURLException {
		URL apiUrl = new URL(scmUrl);

		int subUrlLocation = StringUtils.indexOf(scmUrl, apiUrl.getHost()) + apiUrl.getHost().length() + 1;
		if (apiUrl.getPort() != -1) {
			subUrlLocation = StringUtils.indexOf(scmUrl, apiUrl.getHost()) + apiUrl.getHost().length()
					+ String.valueOf(apiUrl.getPort()).length() + 1;
		}
		return StringUtils.substring(scmUrl, subUrlLocation);
	}

	private String getGitWorkingDirectory(EnvVars env, TaskListener listener) {
		return env.get("WORKSPACE");
	}

	private HttpResponse triggerScaScan(String apiUrl, String inputParamsMap, String sec1ApiKey) {

		try (CloseableHttpClient client = objectFactory.createHttpClient(new URI(apiUrl))) {
			HttpPost httpPost = objectFactory.createHttpPost(apiUrl);
			httpPost.setHeader("Content-Type", "application/json");
			httpPost.setHeader("Accept", "application/json");
			httpPost.setHeader(API_KEY_HEADER, sec1ApiKey);
			StringEntity stringEntity = new StringEntity(inputParamsMap, StandardCharsets.UTF_8);
			httpPost.setEntity(stringEntity);
			HttpResponse response = client.execute(httpPost);
			return response;
		} catch (IOException e) {
			logger.error("Issue while connecting to api.", e);
		} catch (URISyntaxException e) {
			logger.error("Check configured Sec1 API url => {}", apiUrl, e);
		}
		return null;
	}

	public String getGitUrl(String repositoryPath) throws IOException {
		String gitConfigPath = repositoryPath + File.separator + objectFactory.getGitFolderConfigPath();
		if (!Files.exists(Path.of(gitConfigPath))) {
			return null;
		}
		try (BufferedReader reader = new BufferedReader(new FileReader(gitConfigPath, StandardCharsets.UTF_8))) {
			String line;
			boolean inRemoteSection = false;

			while ((line = reader.readLine()) != null) {
				if (line.trim().equals("[remote \"origin\"]")) {
					inRemoteSection = true;
				}
				if (inRemoteSection && line.trim().startsWith("url")) {
					String[] parts = line.split("=");
					if (parts.length == 2) {
						String rawUrl = parts[1].trim();
						return removeCredentialsFromGitUrl(rawUrl);
					}
				}
				if (inRemoteSection && line.trim().startsWith("[") && !line.trim().equals("[remote \"origin\"]")) {
					break;
				}
			}
		}
		return null;
	}

	public String getGitFolderConfigPath() {
		return ".git" + File.separator + "config";
	}

	private String removeCredentialsFromGitUrl(String rawUrl) {
		try {
			URI uri = new URI(rawUrl);
			String userInfo = uri.getUserInfo();

			if (userInfo != null) {
				return rawUrl.replace(userInfo + "@", "");
			}
		} catch (URISyntaxException e) {
			e.printStackTrace();
		}

		return rawUrl;
	}

	private boolean isAnsiColorPluginInstalled(Job<?, ?> job) {
		Plugin plugin = Jenkins.get().getPlugin("ansicolor");
		if (plugin != null && plugin.getWrapper().isEnabled()) {
			XmlFile config = job.getConfigFile();
			try {
				String configString = config.asString();
				if (StringUtils.isNotBlank(configString)
						&& StringUtils.contains(configString, "hudson.plugins.ansicolor.AnsiColorBuildWrapper")) {
					return true;
				}
			} catch (Exception ex) {
				return false;
			}
		}
		return false;
	}
}