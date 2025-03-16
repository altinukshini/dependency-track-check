# OWASP Dependency-Track Checker GitHub Action

[![GitHub release](https://img.shields.io/github/release/altinukshini/dependency-track-checker.svg)](https://github.com/altinukshini/dependency-track-checker/releases)
[![License](https://img.shields.io/github/license/altinukshini/dependency-track-checker.svg)](LICENSE)

A GitHub Action to check [OWASP Dependency-Track](https://dependencytrack.org/) scan results for a project and optionally fail the workflow based on policy violations or risk score thresholds.

## Overview

This action connects to a Dependency-Track instance, checks the processing status of an uploaded SBOM (Software Bill of Materials), retrieves project information and policy violations, and provides detailed reports. It can:

- Wait for SBOM processing to complete
- Retrieve project risk scores and policy violations
- Add results to GitHub Actions job summary
- Comment results on pull requests
- Fail the workflow based on configurable thresholds

## Usage

```yaml
      # Check Dependency-Track results
      - name: Check Dependency-Track Results
        uses: altinukshini/dependency-track-checker@v1
        with:
          api_key: ${{ secrets.DEPENDENCY_TRACK_API_KEY }}
          api_url: ${{ secrets.DEPENDENCY_TRACK_URL }}
          project_name: 'my-app'
          project_version: '1.0.0'
          sbom_token: ${{ steps.upload-sbom.outputs.token }}
          fail_on_policy_violation: 'true' # or
          project_risk_score_threshold: '20'
          gh_token: ${{ secrets.GITHUB_TOKEN }}
```

## Inputs

| Input | Description | Required | Default |
|-------|-------------|----------|---------|
| `api_key` | Dependency-Track API Key | Yes | |
| `api_url` | Dependency-Track API URL | Yes | |
| `project_name` | Dependency-Track Project Name | Yes | |
| `project_version` | Dependency-Track Project Version | Yes | |
| `sbom_token` | Token response from Dependency Track of the uploaded SBOM file | Yes | |
| `print_github_summary` | Prints a summary of the Dependency-Track scan results to the GitHub Actions job summary | No | `true` |
| `comment_results_in_pr` | Comment the Dependency-Track scan results in the PR | No | `true` |
| `fail_on_policy_violation` | Fail the job if a policy violation with FAIL state is found | No | `true` |
| `project_risk_score_threshold` | Fail the job if the project risk score is above this threshold | No | `-1` (disabled) |
| `gh_token` | GitHub Token used for PR Comment | No | |
| `owner` | GitHub Owner (defaults to current repo owner) | No | |
| `repo` | GitHub Repo (defaults to current repo) | No | |
| `pr_number` | GitHub PR Number (defaults to current PR) | No | |

## Outputs

| Output | Description |
|--------|-------------|
| `project_uuid` | The UUID of the project in Dependency-Track |
| `project_risk_score` | The risk score of the project in Dependency-Track |
| `security_score_category` | The security score category of the project in Dependency-Track |
| `total_policy_violations` | The total number of policy violations in the project |
| `fail_policy_violations` | The number of policy violations with FAIL state in the project |
| `warn_policy_violations` | The number of policy violations with WARN state in the project |

## Risk Score Categories

The action categorizes project risk scores as follows:

- **Low**: 0-10
- **Medium**: 11-20
- **High**: 21-50
- **Critical**: 51+

## Features

### GitHub Actions Summary

When `print_github_summary` is enabled, the action will add a detailed summary of the scan results to the GitHub Actions job summary page, including:

- Project information
- Policy violation counts
- Risk score and category
- Detailed table of all policy violations
- Link to the Dependency-Track dashboard

### Pull Request Comments

When `comment_results_in_pr` is enabled and a PR number is available, the action will:

- Post a detailed comment with the scan results
- Update the comment if it already exists (to avoid multiple comments)
- Include emojis to visually indicate the severity of findings

### Workflow Failure Conditions

The action can fail the workflow based on two configurable conditions:

1. **Policy Violations**: When `fail_on_policy_violation` is enabled, the workflow will fail if any policy violations with a FAIL state are found.

2. **Risk Score Threshold**: When `project_risk_score_threshold` is set to a value greater than -1, the workflow will fail if the project risk score exceeds this threshold.

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

