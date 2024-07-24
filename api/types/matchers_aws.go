/*
Copyright 2023 Gravitational, Inc.

Licensed under the Apache License, Version 2.0 (the "License");
you may not use this file except in compliance with the License.
You may obtain a copy of the License at

    http://www.apache.org/licenses/LICENSE-2.0

Unless required by applicable law or agreed to in writing, software
distributed under the License is distributed on an "AS IS" BASIS,
WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
See the License for the specific language governing permissions and
limitations under the License.
*/

package types

const (
	// IAMInviteTokenName is the name of the default Teleport IAM
	// token to use when templating the script to be executed.
	IAMInviteTokenName = "aws-discovery-iam-token"

	// SSHDConfigPath is the path to the sshd config file to modify
	// when using the agentless installer
	SSHDConfigPath = "/etc/ssh/sshd_config"

	// AWSInstallerDocument is the name of the default AWS document
	// that will be called when executing the SSM command.
	AWSInstallerDocument = "TeleportDiscoveryInstaller"

	// AWSAgentlessInstallerDocument is the name of the default AWS document
	// that will be called when executing the SSM command .
	AWSAgentlessInstallerDocument = "TeleportAgentlessDiscoveryInstaller"

	// AWSMatcherEC2 is the AWS matcher type for EC2 instances.
	AWSMatcherEC2 = "ec2"
	// AWSMatcherEKS is the AWS matcher type for AWS Kubernetes.
	AWSMatcherEKS = "eks"
	// AWSMatcherRDS is the AWS matcher type for RDS databases.
	AWSMatcherRDS = "rds"
	// AWSMatcherRDSProxy is the AWS matcher type for RDS Proxy databases.
	AWSMatcherRDSProxy = "rdsproxy"
	// AWSMatcherRedshift is the AWS matcher type for Redshift databases.
	AWSMatcherRedshift = "redshift"
	// AWSMatcherRedshiftServerless is the AWS matcher type for Redshift Serverless databases.
	AWSMatcherRedshiftServerless = "redshift-serverless"
	// AWSMatcherElastiCache is the AWS matcher type for ElastiCache databases.
	AWSMatcherElastiCache = "elasticache"
	// AWSMatcherMemoryDB is the AWS matcher type for MemoryDB databases.
	AWSMatcherMemoryDB = "memorydb"
	// AWSMatcherOpenSearch is the AWS matcher type for OpenSearch databases.
	AWSMatcherOpenSearch = "opensearch"
	// AWSMatcherDocumentDB is the AWS matcher type for DocumentDB databases.
	AWSMatcherDocumentDB = "docdb"
)

// SupportedAWSMatchers is list of AWS services currently supported by the
// Teleport discovery service.
var SupportedAWSMatchers = append([]string{
	AWSMatcherEC2,
	AWSMatcherEKS,
}, SupportedAWSDatabaseMatchers...)

// SupportedAWSDatabaseMatchers is a list of the AWS databases currently
// supported by the Teleport discovery service.
// IMPORTANT: when adding new Database matchers, make sure reference configs
// for both Discovery and Database Service are updated in docs.
var SupportedAWSDatabaseMatchers = []string{
	AWSMatcherRDS,
	AWSMatcherRDSProxy,
	AWSMatcherRedshift,
	AWSMatcherRedshiftServerless,
	AWSMatcherElastiCache,
	AWSMatcherMemoryDB,
	AWSMatcherOpenSearch,
	AWSMatcherDocumentDB,
}

// RequireAWSIAMRolesAsUsersMatchers is a list of the AWS databases that
// require AWS IAM roles as database users.
// IMPORTANT: if you add database matchers for AWS keyspaces, OpenSearch, or
// DynamoDB discovery, add them here and in RequireAWSIAMRolesAsUsers in
// api/types.
var RequireAWSIAMRolesAsUsersMatchers = []string{
	AWSMatcherRedshiftServerless,
	AWSMatcherOpenSearch,
	AWSMatcherDocumentDB,
}

// GetTypes gets the types that the matcher can match.
func (m AWSMatcher) GetTypes() []string {
	return m.Types
}

// CopyWithTypes copies the matcher with new types.
func (m AWSMatcher) CopyWithTypes(t []string) Matcher {
	newMatcher := m
	newMatcher.Types = t
	return newMatcher
}

