package main

const (
	queryListVulnerabilities = `
    query($fullPath: ID!, $severity: [VulnerabilitySeverity!], $state: [VulnerabilityState!],
          $reportType: [VulnerabilityReportType!], $scanner: [String!], $hasIssues: Boolean,
          $hasResolution: Boolean, $identifierName: String, $hasMergeRequest: Boolean,
          $hasAiResolution: Boolean, $hasRemediations: Boolean,
          $dismissalReason: [VulnerabilityDismissalReason!],
          $sort: VulnerabilitySort, $first: Int, $after: String) {
      __SCOPE__(fullPath: $fullPath) {
        vulnerabilitySeveritiesCount(severity: $severity, state: $state, reportType: $reportType,
            scanner: $scanner, hasIssues: $hasIssues, hasResolution: $hasResolution,
            identifierName: $identifierName, hasMergeRequest: $hasMergeRequest,
            hasAiResolution: $hasAiResolution, hasRemediations: $hasRemediations,
            dismissalReason: $dismissalReason) {
          critical high medium low info unknown
        }
        vulnerabilities(severity: $severity, state: $state, reportType: $reportType,
            scanner: $scanner, hasIssues: $hasIssues, hasResolution: $hasResolution,
            identifierName: $identifierName, hasMergeRequest: $hasMergeRequest,
            hasAiResolution: $hasAiResolution, hasRemediations: $hasRemediations,
            dismissalReason: $dismissalReason,
            sort: $sort, first: $first, after: $after) {
          nodes {
            id uuid title severity state reportType detectedAt resolvedAt dismissedAt
            description webUrl dismissalReason falsePositive hasRemediations aiResolutionAvailable
            cveEnrichment { epssScore isKnownExploit }
            primaryIdentifier { name externalType externalId url }
            location {
              ... on VulnerabilityLocationSast { file startLine endLine }
              ... on VulnerabilityLocationDependencyScanning { file dependency { package { name } version } }
              ... on VulnerabilityLocationContainerScanning { image operatingSystem }
              ... on VulnerabilityLocationSecretDetection { file startLine endLine }
              ... on VulnerabilityLocationDast { hostname path }
            }
            scanner { name externalId vendor }
            project { fullPath }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryGetVulnerability = `
    query($id: VulnerabilityID!) {
      vulnerability(id: $id) {
        id uuid title severity state reportType
        detectedAt confirmedAt resolvedAt dismissedAt updatedAt dueDate
        description solution webUrl
        dismissalReason stateComment falsePositive hasRemediations
        presentOnDefaultBranch resolvedOnDefaultBranch
        aiResolutionAvailable aiResolutionEnabled
        cvss { vendor version baseScore overallScore severity vector }
        cveEnrichment { cve epssScore isKnownExploit }
        primaryIdentifier { name externalType externalId url }
        identifiers { name externalType externalId url }
        links { name url }
        location {
          ... on VulnerabilityLocationSast { file startLine endLine blobPath }
          ... on VulnerabilityLocationDependencyScanning { file dependency { package { name } version } blobPath }
          ... on VulnerabilityLocationContainerScanning { image operatingSystem }
          ... on VulnerabilityLocationSecretDetection { file startLine endLine blobPath }
          ... on VulnerabilityLocationDast { hostname path requestMethod }
        }
        scanner { name externalId vendor }
        project { fullPath name webUrl }
        findingTokenStatus { status lastVerifiedAt }
        issueLinks { nodes { linkType issue { iid title webUrl state } } }
        mergeRequests(first: 10) { nodes { iid title state webUrl } pageInfo { hasNextPage } }
        severityOverrides(first: 10) { nodes { originalSeverity newSeverity createdAt author { username } } pageInfo { hasNextPage } }
        notes { nodes { body author { name username } createdAt } }
        stateTransitions { nodes { toState fromState author { name username } createdAt comment } }
      }
    }`

	queryGetVulnerabilityStatistics = `
    query($fullPath: ID!) {
      project(fullPath: $fullPath) {
        vulnerabilitySeveritiesCount {
          critical high medium low info unknown
        }
        vulnerabilityStatistic {
          total
          critical high medium low info unknown
        }
      }
    }`

	queryListPipelineSecurityFindings = `
    query($fullPath: ID!, $pipelineIid: ID!, $reportType: [String!], $severity: [String!],
          $first: Int, $after: String) {
      project(fullPath: $fullPath) {
        pipeline(iid: $pipelineIid) {
          securityReportFindings(reportType: $reportType, severity: $severity,
                                 first: $first, after: $after) {
            nodes {
              uuid title severity reportType
              scanner { name externalId }
              identifiers { name externalType externalId url }
              description solution state
            }
            pageInfo { hasNextPage endCursor }
          }
        }
      }
    }`

	queryListVulnerabilityScanners = `
    query($fullPath: ID!) {
      project(fullPath: $fullPath) {
        vulnerabilityScanners {
          nodes {
            id name externalId reportType
            vendor
          }
        }
      }
    }`

	queryListSecurityPolicies = `
    query($fullPath: ID!, $relationship: SecurityPolicyRelationType, $type: PolicyType, $withYaml: Boolean!) {
      __SCOPE__(fullPath: $fullPath) {
        securityPolicies(relationship: $relationship, type: $type) {
          nodes {
            name description type enabled updatedAt editPath
            yaml @include(if: $withYaml)
            policyScope { complianceFrameworks { nodes { id name } } }
          }
          pageInfo { hasNextPage }
        }
      }
    }`

	queryListScanExecutionPolicies = `
    query($fullPath: ID!, $relationship: SecurityPolicyRelationType) {
      project(fullPath: $fullPath) {
        scanExecutionPolicies(relationship: $relationship) {
          nodes {
            name description enabled updatedAt
            yaml
          }
        }
      }
    }`

	queryGetVulnerabilityStatisticsGroup = `
    query($fullPath: ID!) {
      group(fullPath: $fullPath) {
        vulnerabilitySeveritiesCount {
          critical high medium low info unknown
        }
      }
    }`

	queryListVulnerabilityScannersGroup = `
    query($fullPath: ID!) {
      group(fullPath: $fullPath) {
        vulnerabilityScanners {
          nodes {
            id name externalId reportType
            vendor
          }
        }
      }
    }`

	queryListScanExecutionPoliciesGroup = `
    query($fullPath: ID!, $relationship: SecurityPolicyRelationType) {
      group(fullPath: $fullPath) {
        scanExecutionPolicies(relationship: $relationship) {
          nodes {
            name description enabled updatedAt
            yaml
          }
        }
      }
    }`

	queryListComplianceFrameworksGroup = `
    query($fullPath: ID!, $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        complianceFrameworks(first: $first, after: $after) {
          nodes {
            id name description color default
            pipelineConfigurationFullPath
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListComplianceFrameworks = `
    query($fullPath: ID!, $first: Int, $after: String) {
      project(fullPath: $fullPath) {
        complianceFrameworks(first: $first, after: $after) {
          nodes {
            id name description color default
            pipelineConfigurationFullPath
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryGetAIMetrics = `
query($fullPath: ID!, $startDate: Date!, $endDate: Date!, $ideNames: [String!], $languages: [String!]) {
  __SCOPE__(fullPath: $fullPath) {
    id
    aiMetrics(startDate: $startDate, endDate: $endDate) {
      duoChatContributorsCount duoUsedCount rootCauseAnalysisUsersCount codeContributorsCount
      chat {
        requestDuoChatResponseEventCount completeDuoChatResponseEventCount
        toolSucceededDuoChatEventCount toolFailedDuoChatEventCount
      }
      mcp { startMcpToolCallEventCount finishMcpToolCallEventCount }
      troubleshoot { troubleshootJobEventCount }
      codeReview {
        requestReviewDuoCodeReviewOnMrByAuthorEventCount
        requestReviewDuoCodeReviewOnMrByNonAuthorEventCount
        postCommentDuoCodeReviewOnDiffEventCount
        publishDuoCodeReviewCommentsEventCount
        approveMergeRequestDuoCodeReviewEventCount
        findNoIssuesDuoCodeReviewAfterReviewEventCount
        encounterDuoCodeReviewErrorDuringReviewEventCount
        reactThumbsDownOnDuoCodeReviewCommentEventCount
        reactThumbsUpOnDuoCodeReviewCommentEventCount
      }
      codeSuggestions(ideNames: $ideNames, languages: $languages) {
        contributorsCount shownCount acceptedCount languages
        acceptedLinesOfCode shownLinesOfCode ideNames
      }
      agentPlatformChats: agentPlatform(flowTypes: ["chat"]) { createdSessionEventCount }
      agentPlatformFlows: agentPlatform(not: {flowTypes: ["chat"]}) { createdSessionEventCount }
      agentPlatform {
        createdSessionEventCount startedSessionEventCount finishedSessionEventCount
        droppedSessionEventCount stoppedSessionEventCount resumedSessionEventCount
        flowMetrics { flowType sessionsCount usersCount completionRate medianExecutionTime }
      }
    }
  }
}`

	queryGetGroup = `
    query($fullPath: ID!) {
      group(fullPath: $fullPath) {
        id name fullPath path description visibility webUrl avatarUrl createdAt
        parent { id fullPath }
        emailsEnabled mentionsDisabled requireTwoFactorAuthentication twoFactorGracePeriod
        projectCreationLevel subgroupCreationLevel
        lockMathRenderingLimitsEnabled mathRenderingLimitsEnabled
        lfsEnabled requestAccessEnabled shareWithGroupLock
        rootStorageStatistics {
          storageSize repositorySize lfsObjectsSize buildArtifactsSize packagesSize
          wikiSize snippetsSize pipelineArtifactsSize uploadsSize
          containerRegistrySize dependencyProxySize
        }
        stats { releaseStats { releasesCount releasesPercentage } }
      }
    }`

	queryListGroups = `
    query($search: String, $parentPath: ID, $ownedOnly: Boolean, $topLevelOnly: Boolean,
          $ids: [ID!], $sort: String, $first: Int, $after: String) {
      groups(search: $search, parentPath: $parentPath, ownedOnly: $ownedOnly,
             topLevelOnly: $topLevelOnly, ids: $ids, sort: $sort, first: $first, after: $after) {
        nodes {
          id name fullPath path description visibility webUrl avatarUrl
          parent { id fullPath }
        }
        pageInfo { hasNextPage endCursor }
      }
    }`

	queryListDescendantGroups = `
    query($fullPath: ID!, $search: String, $includeParentDescendants: Boolean,
          $owned: Boolean, $sort: GroupSort, $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        descendantGroups(search: $search, includeParentDescendants: $includeParentDescendants,
                         owned: $owned, sort: $sort, first: $first, after: $after) {
          nodes {
            id name fullPath path description visibility webUrl
            parent { id fullPath }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListGroupProjects = `
    query($fullPath: ID!, $search: String, $includeSubgroups: Boolean,
          $includeArchived: Boolean, $archivedOnly: Boolean, $withMergeRequestsEnabled: Boolean,
          $hasVulnerabilities: Boolean, $sort: NamespaceProjectSort, $ids: [ID!],
          $notAimedForDeletion: Boolean,
          $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        projects(search: $search, includeSubgroups: $includeSubgroups,
                 includeArchived: $includeArchived, archivedOnly: $archivedOnly,
                 withMergeRequestsEnabled: $withMergeRequestsEnabled,
                 hasVulnerabilities: $hasVulnerabilities, sort: $sort, ids: $ids,
                 notAimedForDeletion: $notAimedForDeletion,
                 first: $first, after: $after) {
          nodes {
            id name fullPath path description visibility webUrl archived
            createdAt lastActivityAt starCount forksCount openIssuesCount topics
            namespace { id fullPath }
            complianceFrameworks { nodes { id name color default } }
            statistics {
              repositorySize storageSize lfsObjectsSize buildArtifactsSize
              packagesSize containerRegistrySize
            }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListGroupMembers = `
    query($fullPath: ID!, $search: String, $accessLevels: [AccessLevelEnum!],
          $relations: [GroupMemberRelation!], $sort: MemberSort,
          $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        groupMembers(search: $search, accessLevels: $accessLevels, relations: $relations,
                     sort: $sort, first: $first, after: $after) {
          nodes {
            id createdAt updatedAt expiresAt
            accessLevel { integerValue stringValue }
            user { id username name publicEmail webUrl state lastActivityOn }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`

	queryListGroupMergeRequests = `
    query($fullPath: ID!, $state: MergeRequestState, $labels: [String!],
          $milestoneTitle: String, $assigneeUsername: String, $authorUsername: String,
          $reviewerUsername: String, $search: String,
          $createdAfter: Time, $createdBefore: Time, $mergedAfter: Time, $mergedBefore: Time,
          $targetBranches: [String!], $sourceBranches: [String!], $draft: Boolean,
          $sort: MergeRequestSort, $first: Int, $after: String) {
      group(fullPath: $fullPath) {
        mergeRequests(state: $state, labels: $labels, milestoneTitle: $milestoneTitle,
                      assigneeUsername: $assigneeUsername, authorUsername: $authorUsername,
                      reviewerUsername: $reviewerUsername, search: $search,
                      createdAfter: $createdAfter, createdBefore: $createdBefore,
                      mergedAfter: $mergedAfter, mergedBefore: $mergedBefore,
                      targetBranches: $targetBranches, sourceBranches: $sourceBranches,
                      draft: $draft, sort: $sort, first: $first, after: $after) {
          nodes {
            id iid title state draft createdAt updatedAt mergedAt webUrl
            sourceBranch targetBranch mergeStatus approvalsRequired approvalsLeft
            author { username name }
            assignees { nodes { username name } }
            reviewers { nodes { username name } }
            labels { nodes { title color } }
            milestone { title state }
            project { id fullPath }
          }
          pageInfo { hasNextPage endCursor }
        }
      }
    }`
)

const (
	mutationVulnerabilityConfirm = `
    mutation($id: VulnerabilityID!) {
      vulnerabilityConfirm(input: { id: $id }) {
        vulnerability { id title state severity }
        errors
      }
    }`

	mutationVulnerabilityDismiss = `
    mutation($id: VulnerabilityID!, $comment: String, $dismissalReason: VulnerabilityDismissalReason) {
      vulnerabilityDismiss(input: { id: $id, comment: $comment, dismissalReason: $dismissalReason }) {
        vulnerability { id title state severity }
        errors
      }
    }`

	mutationVulnerabilityResolve = `
    mutation($id: VulnerabilityID!) {
      vulnerabilityResolve(input: { id: $id }) {
        vulnerability { id title state severity }
        errors
      }
    }`

	mutationVulnerabilityRevertToDetected = `
    mutation($id: VulnerabilityID!) {
      vulnerabilityRevertToDetected(input: { id: $id }) {
        vulnerability { id title state severity }
        errors
      }
    }`
)

const (
	queryCurrentUser = `
    query { currentUser { username } }`
)
