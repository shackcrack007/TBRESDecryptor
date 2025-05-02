# TBRES Decryptor

A PowerShell tool for extracting and decrypting authentication tokens from the Windows TokenBroker cache.

<video src="Tbres_decryptor_demo.mp4" width="420" height="340" controls></video>

## Overview

TBRES Decryptor is a security assessment tool that helps extract valid access tokens from the Windows TokenBroker cache (`%userprofile%\AppData\Local\Microsoft\TokenBroker\Cache`). TokenBroker is a Windows component that manages authentication tokens for various Microsoft applications and services. These tokens can be used to access Azure and Microsoft 365 resources.

This tool is useful for:
- Security researchers and penetration testers
- Incident response teams
- Security auditors verifying token handling

## The Token Broker Cache

In Windows, the Token Broker cache is part of the Web Account Manager (WAM) and Token Broker system used for modern authentication scenarios, particularly in Microsoft Entra ID (Azure AD) and MSA (Microsoft Account) environments.

#### What is the Token Broker?
Token Broker is a Windows component (introduced in Windows 10) that handles authentication tokens for apps using Web Account Manager (WAM) APIs.
The Token Broker cache refers to the local storage of authentication tokens (like OAuth 2.0 access tokens, refresh tokens, ID tokens) that the Token Broker manages. It allows seamless SSO (Single Sign-On) across applications without needing to prompt the user for credentials every time.
It abstracts the process of obtaining, renewing, and caching tokens for applications, particularly Universal Windows Platform (UWP) apps and some modern Win32 apps.

#### What’s it used for?
- Enables SSO across apps that use WAM.
- Stores tokens to reduce authentication prompts.
- Supports conditional access and MFA scenarios.
- Used in Entra ID login flows, especially on Windows 10+ joined devices (Hybrid/Azure AD joined).

## Features

- Automatically locates and scans TokenBroker cache files (`.tbres`)
- Decrypts tokens using Windows DPAPI (Data Protection API)
- Extracts token metadata including:
  - Tenant ID and name
  - Resource/audience information
  - Application details
  - Token expiration
  - User identity information
- Identifies tokens by service name (Microsoft Graph, Teams, etc.)
- Exports results to a text file for further analysis

## Requirements

- Windows operating system (Windows 10 or later recommended)
- PowerShell 5.1 or later
- Must be run in the context of the user whose tokens you want to extract (tokens are protected by DPAPI)

## Installation

1. Clone this repository or download the PowerShell script:

```powershell
git clone https://github.com/shackcrack007/TBRESDecryptor.git
```

2. No additional installation is required - the script uses built-in PowerShell capabilities.

## Usage

### Basic Usage

Simply run the script without any parameters to scan the default TokenBroker cache location:

```powershell
.\TBRESDecryptor.ps1
```

This will:
1. Scan the default TokenBroker cache location (`%USERPROFILE%\AppData\Local\Microsoft\TokenBroker\Cache`)
2. Find and decrypt any valid tokens
3. Save the results to `validTokens.txt` in the current directory


### Use The Tokens
#### Following on how to conncet to Microsoft Graph Powershell SDK using an extracted token

```powershell
$at = "eyJ"
$secureAt = ConvertTo-SecureString $at -AsPlainText -Force
Connect-MgGraph -AccessToken $secureAt

# Get current user information
$currentUser = (Get-MgContext).Account

# Display basic information about the current identity
Write-Host "Current Identity: $currentUser"
Write-Host "Tenant ID: $(Get-MgContext).TenantId)"
```

### Advanced Usage

You can import the script as a module to use its functions in your own scripts:

```powershell
# Import the module
. .\TBRESDecryptor.ps1

# Scan a custom location
$tokens = Get-ValidTokensFromTBRES -RootPath "C:\CustomPath\TokenBroker" 

# Process individual .tbres files
$result = Get-DecryptedTBRES -FilePath "C:\path\to\specific\file.tbres"

# Access token properties
$result.Token       # The actual JWT token
$result.ResourceId  # The resource the token grants access to
$result.Expires     # When the token expires
```

## Understanding the Output

The script outputs structured information about each token:

- **File**: Path to the .tbres file containing the token
- **TenantId**: Azure AD tenant identifier
- **TenantName**: Display name of the tenant
- **ResourceId**: Resource/audience the token is valid for (GUID)
- **ResourceName**: Friendly name of the resource (if known)
- **AppId**: Application ID that requested the token
- **AppName**: Friendly name of the application (if known)
- **Claims**: Authentication method claims
- **Expires**: Token expiration timestamp
- **Token**: The actual JWT access token
- **ProviderId**: Identity provider identifier
- **UserName**: The username associated with the token

## Security Considerations

- This tool only decrypts tokens protected by the current user's DPAPI key
- Extracted tokens provide the same level of access as the original applications that acquired them
- Handle extracted tokens with care - they represent valid authentication credentials
- Always ensure you have proper authorization before extracting tokens

## How It Works

1. The script locates `.tbres` files in the TokenBroker cache
2. It reads and parses the file format, which contains encrypted token data
3. Using Windows DPAPI, it decrypts the protected data using the current user's key
4. It extracts the JWT token and associated metadata
5. For known application/resource IDs, it maps them to friendly names

## Troubleshooting

- **No tokens found**: Ensure you're running as the user whose tokens you want to extract
- **Decryption errors**: Typically indicates you don't have access to the DPAPI key for those tokens
- **Permission denied**: You need read access to the TokenBroker cache folders

## Contributing

Contributions are welcome! Please feel free to submit a Pull Request.

## License

This project is licensed under the MIT License - see the LICENSE file for details.

## Disclaimer

This tool is provided for legitimate security assessment and research purposes only. Use responsibly and only on systems you own or have explicit permission to test. The author is not responsible for misuse or for any damage that might be caused by this tool.