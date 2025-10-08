## ReversePassword design
Overall class diagram:  
![class diagram](class_diagram.svg)

| Class | Description |
|-------|-------------|
| `CredentialProvider` <[ICredentialProvider](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nn-credentialprovider-icredentialprovider), [ICredentialProviderSetUserArray](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nn-credentialprovider-icredentialprovidersetuserarray)> | Parent class that's created by Windows. The `_providerUsers` member is similarly initialized on `SetUserArray` calls. |
| `CredentialView` | Instances are created when `CredentialProvider` initializes its `_view` member when receiving `SetUsageScenario` calls. |
| `CredentialProviderCredential` <[ICredentialProviderCredential](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nn-credentialprovider-icredentialprovidercredential), [ICredentialProviderCredential2](https://learn.microsoft.com/en-us/windows/win32/api/credentialprovider/nn-credentialprovider-icredentialprovidercredential2)>| Instances are created on-demand by `CredentialView` when `CredentialProvider` receives `GetCredentialAt` calls. |


This project is heavily based on the no longer maintained [CredProvider.NET](https://github.com/SteveSyfuhs/CredProvider.NET)
