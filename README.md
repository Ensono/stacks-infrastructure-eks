# stacks-infrastructure-eks

BREAKING CHANGE: `external-dns` chart has moved away from the Bitnami chart to the Kubernetes SIG chart. If migrating upwards the Bitnami Helm Chart should be removed from the cluster manually.

## Kyverno Admission Controller
This repository includes Kyverno which is deployed within the EKS cluster.
Kyverno is a policy engine designed for cloud native platform engineering teams. It enables security, automation, compliance, and governance using policy-as-code. 
By enabling Kyverno into your cluster, it allows you to:
 - Enforce Security Best Practices: Kyverno validate policies can block the creation of resources that do not meet security standards, such as pods running as root or containers with privileged access.
 - Ensure Compliance: Enforce compliance with industry standards like CIS benchmarks, GDPR, or HIPAA by validating resource configurations against predefined rules.
 - Prevent Malicious or Risky Deployments
 - Standardise Configurations: Ensure that all resources adhere to organizational standards, such as labeling, annotations, or resource naming conventions.

### Kyverno Policies
Kyverno policies are declarative YAML files that define rules for validating, mutating, generating, or cleaning up Kubernetes resources. These policies are enforced by the Kyverno admission controller, which evaluates resources during creation, update, or deletion.

Within this repository we have 3 validate policies:
 - baseline-policy.yaml: The baseline profile of the Pod Security Standards is a collection of the most basic and important steps that can be taken to secure Pods. More details can be found here: https://kubernetes.io/docs/concepts/security/pod-security-standards/.
 - disallow-host-namespaces.yaml - Pods should not be allowed access to host namespaces. This was created seperatly because then we can be specific on what namespaces should be included for this check.
 - disallow-host-path.yaml - This policy ensures no hostPath volumes are in use. This was created seperatly because then we can be specific on what namespaces should be included for this check.

#### Adding additional policies
Kyverno provides additional policies that can be installed which can be found here, https://kyverno.io/policies .
When deploying these policies its best to set them as "Audit" first so it will report on what failures are occurring with the existing manifests.
You can run the command below to see which manifests are passing or failing:
```
kubectl get Policyreports --all-namespaces
```

#### UI
As mentioned above you can view results of the "Audit" policies by running the command above. There is a policy reporter tool which can be installed. This can be found here: "https://github.com/kyverno/policy-reporter" and it is a UI that shows what manifests are passing or failing and even produces a compliance report.
