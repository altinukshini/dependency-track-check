const core = require('@actions/core');
const github = require('@actions/github');
const fetch = require('node-fetch');

const api_key = core.getInput('api_key');
const api_url = core.getInput('api_url');
const project_name = core.getInput('project_name');
const project_version = core.getInput('project_version');
const sbom_token = core.getInput('sbom_token');

const print_github_summary = core.getInput('print_github_summary').toLowerCase() === 'true';
const comment_results_in_pr = core.getInput('comment_results_in_pr').toLowerCase() === 'true';
const fail_on_policy_violation = core.getInput('fail_on_policy_violation').toLowerCase() === 'true';
const project_risk_score_threshold = parseInt(core.getInput('project_risk_score_threshold')) || -1;

const gh_token = process.env.GITHUB_TOKEN || core.getInput('gh_token');
const owner = core.getInput('owner') || github.context.repo.owner;
const repo = core.getInput('repo') || github.context.repo.repo;
const pr_number = core.getInput('pr_number') || (github.context.payload.pull_request ? github.context.payload.pull_request.number : null);

if (pr_number) {
    core.info(`Pull Request number: ${pr_number}`);
} else {
    core.info('Not a pull request or no PR number provided');
}

const categorizeSecurityScore = (score) => {
    if (score >= 0 && score <= 10) {
        return 'low';
    } else if (score > 10 && score <= 20) {
        return 'medium';
    } else if (score > 20 && score <= 50) {
        return 'high';
    } else if (score > 50) {
        return 'critical';
    } else {
        return 'unknown';
    }
};

const fetchBomProcessingStatus = async (token) => {
    const response = await fetch(`${api_url}/api/v1/event/token/${token}`, {
        headers: { 'X-Api-Key': api_key }
    });
    return await response.json();
};

const fetchProjectInfo = async (projectName, projectVersion) => {
    const response = await fetch(`${api_url}/api/v1/project/lookup?name=${projectName}&version=${projectVersion}`, {
        headers: { 'X-Api-Key': api_key }
    });
    return await response.json();
};

const fetchViolations = async (projectUuid, suppressed = false) => {
    const response = await fetch(`${api_url}/api/v1/violation/project/${projectUuid}?suppressed=${suppressed}`, {
        headers: { 'X-Api-Key': api_key }
    });
    return await response.json();
};

const main = async () => {
    try {
        let processing = true;
        let attempts = 0;
        const maxAttempts = 30;
        const sleepTime = 10000;

        core.info('Checking SBOM processing status');

        while (attempts < maxAttempts) {
            const data = await fetchBomProcessingStatus(sbom_token);
            processing = data.processing;

            if (!processing) {
                core.info('OWASP Dependency Track processing completed');
                break;
            }

            core.info('Waiting for SBOM processing to complete...');
            await new Promise(resolve => setTimeout(resolve, sleepTime));
            attempts += 1;
        }

        if (processing) {
            core.setFailed('SBOM processing did not complete in time. Exiting...');
            return;
        }

        // wait to make sure the score is available, some errors found during tests w/o this wait
        await new Promise(resolve => setTimeout(resolve, 5000));

        core.info('Retrieving project information');

        let projectData;
        let projectUuid;
        try {
            projectData = await fetchProjectInfo(project_name, project_version);
            projectUuid = projectData.uuid;
        } catch (error) {
            core.error(error.message);
            core.setFailed(`Project (${project_name}) with version (${project_version}) could not be found.`);
            return;
        }
        // The "Risk Score" is actually more of a weighted severity score. It is calculated by:
        // ((critical * 10) + (high * 5) + (medium * 3) + (low * 1) + (unassigned * 5))
        const projectRiskScore = projectData.lastInheritedRiskScore;
        const securityScoreCategory = categorizeSecurityScore(projectRiskScore);

        const policyViolations = await fetchViolations(projectUuid);
        const totalPolicyViolationsCount = policyViolations.length;
        const failPolicyViolationsCount = policyViolations.filter(violation => violation.policyCondition.policy.violationState === 'FAIL').length;
        const warnPolicyViolationsCount = policyViolations.filter(violation => violation.policyCondition.policy.violationState === 'WARN').length;

        let dtCheckStatus= 'PASS';
        if ( (fail_on_policy_violation && failPolicyViolationsCount > 0) || (project_risk_score_threshold > -1 && projectRiskScore > project_risk_score_threshold) ) {
            dtCheckStatus = 'FAIL';
        }

        core.setOutput('project_uuid', projectUuid);
        core.setOutput('project_risk_score', projectRiskScore);
        core.setOutput('security_score_category', securityScoreCategory);
        core.setOutput('total_policy_violations_count', totalPolicyViolationsCount);
        core.setOutput('fail_policy_violations_count', failPolicyViolationsCount);
        core.setOutput('warn_policy_violations_count', warnPolicyViolationsCount);

        core.info(`-------------------------------------------------------------------------------------------------`);
        core.info(`> Dependecy-Track check results (${dtCheckStatus})`);
        core.info(`Project: ${projectData.name}`);
        core.info(`Version: ${projectData.version}`);
        core.info(`Uuid: ${projectUuid}`);
        core.info('')
        core.warning(`Dependency-Track Total policy violations: ${totalPolicyViolationsCount}`);
        core.warning(`Dependency-Track FAIL policy violations: ${failPolicyViolationsCount}`);
        core.info(`Project risk score: ${projectRiskScore} (${securityScoreCategory})`);
        core.info("Type | State | Component | License | Policy");
        policyViolations.forEach(violation => {
            core.info(`  - ${violation.type ?? 'N/A'} | ${violation.policyCondition?.policy?.violationState ?? 'N/A'} | ${violation.component?.name ?? 'N/A'}@${violation.component?.version ?? 'N/A'} | ${violation.component?.resolvedLicense?.name ?? 'Other'} | ${violation.policyCondition?.policy?.name ?? 'N/A'}`);
        });
        core.info('')
        core.info(`Visit Dependency-Track dashboard for details: ${api_url}/projects/${projectUuid}/policyViolations`)
        core.info(`-------------------------------------------------------------------------------------------------`);

        if (print_github_summary) {
            core.info('Printing Dependency-Track check results to GitHub Actions summary');
            core.summary
                .addHeading(`${failPolicyViolationsCount > 0 ? ':bangbang: ' : warnPolicyViolationsCount > 0 ? ':warning: ' : ':small_blue_diamond: '}Dependency-Track check results (${dtCheckStatus})`, 3)
                .addList([
                    `Project: ${projectData.name}`,
                    `Uuid: ${projectUuid}`,
                    `Version: ${projectData.version}`
                ], false)
                .addList([
                    `Total policy violations: ${totalPolicyViolationsCount}`,
                    `FAIL policy violations: ${failPolicyViolationsCount}`,
                    `Project risk score: ${projectRiskScore} (${securityScoreCategory})`
                ], false)
                .addTable([
                    [
                        { header: true, data: 'Type' },
                        { header: true, data: 'State' },
                        { header: true, data: 'Component@Version' },
                        { header: true, data: 'License' },
                        { header: true, data: 'Policy' }
                    ],
                    ...policyViolations.map(violation => [
                        violation.type ?? 'N/A',
                        violation.policyCondition?.policy?.violationState ?? 'N/A',
                        `${violation.component?.name ?? 'N/A'}@${violation.component?.version ?? 'N/A'}`,
                        violation.component?.resolvedLicense?.name ?? 'Other',
                        violation.policyCondition?.policy?.name ?? 'N/A'
                    ])
                ])
                .addLink(`Visit Dependency-Track dashboard for details!`, `${api_url}/projects/${projectUuid}/policyViolations`)
                .write();
        }

        if (gh_token && comment_results_in_pr && pr_number) {
            core.info(`Posting Dependency-Track check results to PR #${pr_number}`);
            core.info('Repo Owner: ' + owner);
            core.info('Repo: ' + repo);
            core.info('PR Number: ' + pr_number);
            const octokit = github.getOctokit(gh_token);

            // Fetch existing comments
            const { data: comments } = await octokit.rest.issues.listComments({
                owner: owner,
                repo: repo,
                issue_number: pr_number
            });

            // Identify the existing comment by the hardcoded keyword
            const keyword1 = "Dependency-Track check results";
            const keyword2 = `(${projectData.name})`;
            const existingComment = comments.find(comment => comment.body.includes(keyword1) && comment.body.includes(keyword2));


            const commentBody = `## ${failPolicyViolationsCount > 0 ? ':bangbang: ' : warnPolicyViolationsCount > 0 ? ':warning: ' : ':small_blue_diamond: '}Dependency-Track check results (${dtCheckStatus})\n\n**Project**: (${projectData.name})\n**Version**: ${projectData.version}\n**Uuid**: ${projectUuid}\n\n**Total policy violations**: ${totalPolicyViolationsCount}\n**FAIL policy violations**: ${failPolicyViolationsCount}\n**Project risk score**: ${projectRiskScore} (${securityScoreCategory})\n\n| Type | State | Component@Version | License | Policy |\n| ---- | ----- | ----------------- | ------- | ------ |\n${policyViolations.map(violation => `| ${violation.type ?? 'N/A'} | ${violation.policyCondition?.policy?.violationState ?? 'N/A'} | ${violation.component?.name ?? 'N/A'}@${violation.component?.version ?? 'N/A'} | ${violation.component?.resolvedLicense?.name ?? 'Other'} | ${violation.policyCondition?.policy?.name ?? 'N/A'} |`).join('\n')}\n\nVisit Dependency-Track dashboard for details: ${api_url}/projects/${projectUuid}/policyViolations`;

            if (existingComment) {
                // Update existing comment
                await octokit.rest.issues.updateComment({
                    owner: owner,
                    repo: repo,
                    comment_id: existingComment.id,
                    body: commentBody
                });
                core.info(`Updated existing comment with ID: ${existingComment.id}`);
            } else {
                // Create new comment
                await octokit.rest.issues.createComment({
                    owner: owner,
                    repo: repo,
                    issue_number: pr_number,
                    body: commentBody
                });
                core.info('Created new comment on the PR');
            }
        }

        if (fail_on_policy_violation && failPolicyViolationsCount > 0) {
            core.setFailed(`Failing due to (${failPolicyViolationsCount}) policy violation with FAIL state. Exiting...`);
            return;
        }

        if (project_risk_score_threshold > -1 && projectRiskScore > project_risk_score_threshold) {
            core.setFailed(`Failing due to project risk score (${projectRiskScore}) exceeding threshold (${project_risk_score_threshold}). Exiting...`);
            return;
        }

        core.info('Continuing...');

    } catch (error) {
        core.setFailed(error.message);
        return;
    }
};

main();