# This script exists because Helm has no way to take over a file
# See: https://github.com/helm/helm/issues/2730
# And see: https://github.com/helm/helm/issues/10304#issuecomment-2221600021
[CmdletBinding()]
param (
	[string]
	# Identifier for finding the cluster
	$Identifier,

	[string]
	# Name of the cluster
	$ClusterName,

	[bool]
	$K8sAuthRequired = $true
)

$awsAuthNamespace = "kube-system"
$awsAuthName = "aws-auth"

Invoke-Login -AWS -k8s:$K8sAuthRequired -k8sName $ClusterName -region $Identifier

$awsAuthJson = kubectl get configmap $awsAuthName -n $awsAuthNamespace -ojson | ConvertFrom-Json

# If we are already managing the ConfigMap by Helm then we don't need to remove it...
if ($awsAuthJson.metadata.labels.'app.kubernetes.io/managed-by' -eq "Helm")
{
	Write-Host "'${awsAuthName}' ConfigMap from Namespace '${awsAuthNamespace}' is already managed by Helm... Exiting 0..."
	exit 0
}

Write-Host "DELETING '${awsAuthName}' ConfigMap from Namespace '${awsAuthNamespace}', as it's not managed by Helm..."

kubectl delete configmap $awsAuthName -n $awsAuthNamespace
