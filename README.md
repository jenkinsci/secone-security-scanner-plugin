# Sec1 Security Scanner

[![Sec1](https://digitalassets.sec1.io/sec1-logo.svg)](https://sec1.io)

## Introduction

Integrates Sec1 Security scanning into your CI/CD pipeline, enabling teams to identify vulnerabilities and security issues early in the development lifecycle.

## Usage
To use the plugin up you will need to take the following steps in order:

1. [Install the Sec1 Security Plugin](#1-install-the-sec1-security-plugin)
2. [Configure a Sec1 API Token Credential](#2-configure-a-sec1-api-token-credential)
3. [Add Sec1 Security to your Project](#3-add-sec1-security-to-your-project)

## 1. Install the SEC1 Security Scanner Plugin

- Go to "Manage Jenkins" > "System Configuration" > "Plugins".
- Search for "Sec1 Security Scanner" under "Available plugins".
- Install the plugin.

### Custom Endpoints

By default, Sec1 uses the following endpoints:
- **API endpoint**: `https://api.sec1.io`
- **Dashboard endpoint**: `https://unified.sec1.io`

It is possible to configure custom endpoints by setting environment variables:

- Go to "Manage Jenkins" > "System Configuration" -> "System"
- Under "Global properties" check the "Environment variables" option
- Click "Add"
- Set `SEC1_INSTANCE_URL` to override the API endpoint
- Set `SEC1_DASHBOARD_URL` to override the dashboard endpoint (used for report URLs in build output)


## 2. Configure a Sec1 API Token Credential

- Go to "Manage Jenkins" > "Security" > "Credentials"
- Choose a Store
- Choose a Domain
- Go to "Add Credentials"
- Select "Secret text"
- Add `<YOUR_SEC1_API_KEY_ID>` as ID and Configure the Credentials.
- Remember the "ID" as you'll need it when configuring the build step.

To get `Sec1 Api Key` navigate to [My Account](https://account.sec1.io/) > "Login with GitHub" > Click on profile icon at top right > "Settings"  
- In "API key" section, click on "Generate API key"
- Copy key for use.

<blockquote>
<details>
<summary>📷 Show Preview</summary>

![Sec1 API Token](docs/sec1-configuration-api-key.png)

</details>
</blockquote>

## 3. Add Sec1 Security to your Project

This step will depend on if you're using Freestyle Projects or Pipeline Projects.

### Freestyle Projects

- Select a project
- Go to "Configure"
- Under "Build", select "Add build step" select "Execute Sec1 Security Scanner"
- Configure as needed. Click the "?" icons for more information about each option.

<blockquote>
<details>
<summary>📷 Show Preview</summary>

![Basic configuration](docs/sec1-buildstep.png)

</details>
</blockquote>

### Pipeline Projects

Use the `sec1Security` step as part of your pipeline script. You can use the "Snippet Generator" to generate the code
from a web form and copy it into your pipeline.

<blockquote>
<details>
<summary>📷 Show Example</summary>

```groovy
pipeline {
  agent any

  stages {
    stage('Build') {
      steps {
        echo 'Building...'
      }
    }
    stage('Sec1 Security Scan') {
      steps {
        script {
          sec1Security(
            apiCredentialsId: '<Your Sec1 Api Key ID>',
            scmUrl: 'https://github.com/your-org/your-repo',
            runSca: true,
            runSast: true,
            sastIncrementalScan: false,
            asyncScan: false,
            scanTag: 'my-scan-tag',
            applyThreshold: true,
            actionOnThresholdBreached: 'unstable',
            threshold: [criticalThreshold: '0', highThreshold: '0', mediumThreshold: '0', lowThreshold: '0']
          )
        }
      }
    }
    stage('Deploy') {
      steps {
        echo 'Deploying...'
      }
    }
  }
}
```

</details>
</blockquote>
You can pass the following parameters to your `sec1Security` step.

#### `apiCredentialsId` (required, default: *none*)

Sec1 API Key Credential ID. As configured in "[2. Configure a Sec1 API Token Credential](#2-configure-a-sec1-api-token-credential)".

#### `scmUrl` (optional, default: *auto-detected*)

Git repository URL to scan. If not provided, the plugin attempts to detect it from the workspace `.git/config` or the `GIT_URL` environment variable. Use this parameter when auto-detection fails (e.g., on some pipeline configurations).

#### `runSca` (optional, default: `true`)

Whether SCA (Software Composition Analysis) scan needs to be executed for the configured git repository.

#### `runSast` (optional, default: `true`)

Whether SAST (Static Application Security Testing) scan needs to be executed for the configured git repository.

#### `sastMode` (optional, default: `api`)

Where the SAST scan runs. Two values:

- `api` (default) — the Sec1 server clones the repo and runs the scan. Existing behavior.
- `cli` — the scan runs on the Jenkins agent via the `sec1-sast` binary, which uploads the report to the Sec1 service. Useful when the Sec1 server cannot reach your repository (private SCM, air-gapped network).

In CLI mode `asyncScan` and `sastIncrementalScan` are ignored (the CLI runs synchronously and does not currently support incremental scans).

#### `sastInstallation` (required when `sastMode: 'cli'`)

The name of a Sec1 SAST installation configured under **Manage Jenkins → Tools → Sec1 SAST CLI**. Each installation either points to a pre-installed `sec1-sast` binary on the agent or uses the auto-installer to download it from sec1.io on first use.

#### `sastIncrementalScan` (optional, default: `false`)

Run the SAST scan in incremental mode. Only changed code is analyzed, which is faster for large repositories. Requires a baseline full scan to exist on the Sec1 server.

#### `asyncScan` (optional, default: `false`)

Fire-and-forget mode. The plugin submits the scan and exits without waiting for the result, so the pipeline keeps running while the scan completes on the Sec1 server. The report URL is printed in the build log.

If `applyThreshold` is also `true`, the plugin still polls for the result since threshold checks need the final counts. Use `asyncScan` without `applyThreshold` to get true fire-and-forget behavior.

#### `scanTag` (optional, default: *branch name*)

A tag to identify this scan. If not provided, the branch name is used. If the branch name is also unavailable, defaults to `default`.

#### `applyThreshold` (optional, default: `false`)

Whether vulnerability threshold needs to be applied on the build.

#### `threshold` (optional, default: *none*)

Threshold values for each type of vulnerability. Example configuration:
`[criticalThreshold: '0', highThreshold: '10', mediumThreshold: '0', lowThreshold: '0']`

If the scan reports more vulnerabilities than the configured threshold for the respective severity, an error will be shown in the console and the build status will be modified based on `actionOnThresholdBreached`.

#### `actionOnThresholdBreached` (optional, default: `fail`)

The action to take on the build if a vulnerability threshold is breached. Possible values: `fail`, `unstable`, `continue`

## Scan duration

The plugin polls every 10 seconds for the scan result and times out after 30 minutes. For scans that take longer, set `asyncScan: true` (without `applyThreshold`) so the pipeline does not block.

## Running SAST on the agent (CLI mode)

By default the SAST scan runs on the Sec1 server. To run it on the Jenkins agent instead, set `sastMode: 'cli'` and configure a Sec1 SAST installation:

1. Go to **Manage Jenkins → Tools → Sec1 SAST CLI installations**.
2. Click **Add Sec1 SAST CLI** and give it a name (for example `sec1-sast`).
3. Either:
   - Set **Installation directory** to the directory containing a pre-installed `sec1-sast` binary on the agent, OR
   - Add the **Install from sec1.io (latest)** installer. The plugin downloads the right binary for the agent's platform on first use and caches it under `$JENKINS_HOME/tools/`.
4. In your job, set `sastMode: 'cli'` and `sastInstallation: 'sec1-sast'` (matching the name above).

The plugin runs the CLI on the agent, streams its output to the build log, extracts the report ID, and then polls the Sec1 server for the final status (so threshold enforcement still respects server-side triage like false-positive marks).

## Troubleshooting

To see more information on your steps:

- View the "Console Output" for a specific build.

---

-- Sec1 team
