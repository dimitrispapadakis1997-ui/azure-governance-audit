# Bootstrap

This project reuses the app registration and OIDC setup from [azure-network-foundation](https://github.com/dimitrispapadakis1997-ui/azure-network-foundation/blob/main/docs/bootstrap.md). Only the repository-specific parts are new.

## Added for this repository

| Item | Value |
|---|---|
| Federated credential (main) | `repo:<owner>@<owner_id>/azure-governance-audit@<repo_id>:ref:refs/heads/main` |

The audit job does not run on pull requests, so no pull request credential is needed. The weekly schedule runs on the default branch and uses the `main` credential.

## Repository variables

| Variable | Value |
|---|---|
| `AZURE_CLIENT_ID` | Application (client) ID of the shared app registration |
| `AZURE_TENANT_ID` | Directory (tenant) ID |
| `AZURE_SUBSCRIPTION_ID` | Subscription ID |

## Permissions

The app registration currently has Contributor on the subscription, shared with the Terraform projects. The audit itself only reads. A dedicated app registration with the Reader role would be the least privilege setup and is the next improvement.
