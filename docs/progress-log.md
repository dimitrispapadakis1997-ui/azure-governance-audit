# Progress log

## 2026-11-24: Clean run and screenshots

- **Done:** After the dev and prod resource groups were deleted again, the audit ran clean: 8 resources and resource groups, no network security groups, no high or medium findings, seven low findings (missing tags). Added screenshots of the run and the report to the README and marked the project complete.

## 2026-11-24: First working audit

- **Done:** Python package with six checks, eight unit tests, and a workflow that signs in with OIDC and audits the real subscription. The first report found seven low severity findings, all missing tags on resource groups, the state storage account and the monitoring resources.
- **Problem 1:** The first audit run failed with `ImportError: cannot import name 'ResourceManagementClient'`. The unit tests did not catch it, because they test the checks and never import the Azure SDK.
- **Fix 1:** In `azure-mgmt-resource` 25 and later the client moved to `azure.mgmt.resource.resources`. I reproduced it locally, fixed the import and confirmed the other SDK models still expose the fields the tool reads.
- **Problem 2:** The audit counted four network security groups that should not have existed. The dev and prod networks from the network project had been destroyed, but a later commit to that repository matched the pipeline's path filter (`envs/**`) and applied them again.
- **Fix 2:** Deleted the two resource groups again. Lesson: a pipeline that applies on every push to `main` will recreate destroyed infrastructure as soon as an unrelated commit touches a watched path. The audit found this, which is the kind of thing it is for.
