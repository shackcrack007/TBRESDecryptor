# TBRES Decryptor - Decrypts and extracts tokens from TokenBroker cache files in Windows
# Author: Shaked (Shkedi) Ilan shackrack
# Version: 1.0.0
# 
# This script decrypts and extracts tokens from TokenBroker cache files (.tbres) in Windows.
# TokenBroker is a Windows component that manages authentication tokens for various apps and services.
# The script can be used to extract valid access tokens for security auditing and assessment purposes.
#
# USAGE:
#   .\tbresDecryptor.ps1                     - Scans default TokenBroker cache location
#   Get-ValidTokensFromTBRES -RootPath <path> - Scans a custom location for .tbres files
#
# REQUIREMENTS:
#   - Windows PowerShell 5.1 or later
#   - Run as the user whose tokens you want to extract (tokens are protected by DPAPI)
#
# LICENSE: MIT

Add-Type -AssemblyName System.Security

Function Parse-TBRES {
    <#
    .SYNOPSIS
        Parses a TBRES (TokenBroker Response) file and decrypts its contents.
    
    .DESCRIPTION
        Decrypts and extracts data from a TokenBroker Response file (.tbres), 
        including tokens, account information, and other properties.
    
    .PARAMETER Data
        The raw byte array content of a .tbres file.
    
    .EXAMPLE
        $bytes = [System.IO.File]::ReadAllBytes("C:\path\to\file.tbres")
        Parse-TBRES -Data $bytes
    #>
    [cmdletbinding()]
    param(
        [parameter(Mandatory = $true, ValueFromPipeline)]
        [byte[]]$Data
    )
    
    Process {
        # Strip the null terminator, convert to string and parse json.
        $json = [text.encoding]::Unicode.GetString($Data, 0, $Data.Length).TrimEnd(0x00) | ConvertFrom-Json

        # Get the encrypted content
        $txtEncrypted = $json.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.Value

        # Convert B64 to byte array
        $binEncrypted = Convert-B64ToByteArray -B64 $txtEncrypted

        # If protected, decrypt with DPAPI
        if ($json.TBDataStoreObject.ObjectData.SystemDefinedProperties.ResponseBytes.IsProtected) {
            $binDecrypted = [Security.Cryptography.ProtectedData]::Unprotect($binEncrypted, $null, 'CurrentUser')
        }
        else {
            $binDecrypted = $binEncrypted
        }

        # Parse the expiration time
        $fileTimeUtc = [BitConverter]::ToUInt64((Convert-B64ToByteArray $json.TBDataStoreObject.ObjectData.SystemDefinedProperties.Expiration.Value), 0)
        $expires = [datetime]::FromFileTimeUtc($fileTimeUtc)

        if ((Get-Date).ToUniversalTime() -ge $expires) {
            Write-Warning "Token is expired"
            return 
        }
        
        return Parse-TBRESResponseBytes -Data $binDecrypted
    }
}

# Parses ResponseBytes TBRES files

Function Parse-TBRESResponseBytes {

    param(
        [parameter(Mandatory = $true, ValueFromPipeline)]
        [byte[]]$Data
    )
    Begin {
    }
    Process {
        # Parses version number from TBRES response bytes
        # Nov 20 2021
        Function Parse-TBRESVersion {

            [cmdletbinding()]
            param(
                [parameter(Mandatory = $true, ValueFromPipeline)]
                [byte[]]$Data,
                [parameter(Mandatory = $true, ValueFromPipeline)]
                [ref]$Position,
                [parameter(Mandatory = $false, ValueFromPipeline)]
                [int[]]$ExpectedVersions = @(1, 2)
            )
            Process {
                $p = $Position.Value
                $version = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                if ($ExpectedVersions -notcontains $version) {
                    Throw "Invalid version $version, expected one of $($ExpectedVersions -join ',')"
                }

                $Position.Value = $p
            }
        }

        # Parses key-value pairs from decrypted TBRES response bytes
        # Nov 20 2021
        Function Parse-TBRESKeyValue {

            [cmdletbinding()]
            param(
                [parameter(Mandatory = $true, ValueFromPipeline)]
                [byte[]]$Data,
                [parameter(Mandatory = $true, ValueFromPipeline)]
                [ref]$Position
            )
            Process {
                $p = $Position.Value
                $keyType = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                if ($keyType -ne 0x0c) {
                    Throw "Invalid key type $keyType"
                }
                $keyLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                $binKey = $Data[$p..($p + $keyLength - 1)]; $p += $keyLength
                $key = [text.encoding]::UTF8.GetString($binKey)

                $valueType = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                switch ($valueType) {
                    0x0C {
                        # String
                        $valueLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                        $value = [text.encoding]::UTF8.GetString($Data, $p, $valueLength); $p += $valueLength
                        break
                    }
                    0x04 {
                        # UInt 32
                        $value = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                        break
                    }
                    0x05 {
                        # UInt 32
                        $value = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
                        break
                    }
                    0x06 {
                        # Timestamp
                        $timestamp = [BitConverter]::ToUInt64($Data[($p + 7)..$p], 0); $p += 8
                        $value = [datetime]::FromFileTimeUtc($timestamp)
                        break
                    }
                    0x07 {
                        # UInt 64
                        $value = [BitConverter]::ToUInt64($Data[($p + 7)..$p], 0); $p += 8
                        break
                    }
                    0x0D {
                        # Guid
                        $value = [guid][byte[]]$Data[$p..($p + 15)]; $p += 16
                        break
                    }
                    1025 {
                        # Content identifier?
                        # This is the second content "identifier"
                        if ($binKey.Length -eq 1 -and $binKey[0] -gt 1) {
                            Write-Verbose "Content identifier $($binKey[0]), getting the next Key-Value."
                            # Read the size
                            $length = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4

                            # Parse version
                            Parse-TBRESVersion -Data $Data -Position ([ref]$p)

                            # Get the next value
                            $next = Parse-TBRESKeyValue -Data $Data -Position ([ref]$p)
                            $key = $next.Key
                            $value = $next.Value
                            break
                        }
                        
                        break
                    }
                    default {
                        Write-Verbose "Unknown value type $valueType"
                        $value = $valueType
                        break
                    }
                }

                $Position.Value = $p

                return [PSCustomObject][ordered]@{
                    "Key"   = $key
                    "Value" = $value
                }
            }
        }

        # Parses elements from decrypted TBRES response bytes content
        Function Parse-TBRESElement {

            [cmdletbinding()]
            param(
                [parameter(Mandatory = $true, ValueFromPipeline)]
                [byte[]]$Data,
                [parameter(Mandatory = $true, ValueFromPipeline)]
                [ref]$Position,
                [parameter(Mandatory = $false, ValueFromPipeline)]
                [PSCustomObject]$Element
            )
            Process {
                $p = $Position.Value
                $value = $null

                # Parse element & length
                if (!$Element) {
                    $element = Parse-TBRESKeyValue -Data $Data ([ref]$p)
                }
                Write-Debug $element

                $elementLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4

                if ($element.Key -eq "WTRes_Error") {
                    Write-Verbose "WTRes_Error file, skipping.."
                    return $null
                }
                elseif ($element.Key -eq "WTRes_Token") {
                    Write-Verbose "Parsing WTRes_Token"

                    # We already read the length so adjust
                    $p -= 4
                
                    # Parse status
                    $status = Parse-TBRESKeyValue -Data $Data ([ref]$p)

                    if ($status.Value -ne 0) {
                        Write-Warning "WTRes_Token status $($status.Value)"
                    }

                    $value = $element.Value
                }
                # Parse WTRes_PropertyBag and WTRes_Account
                else {
                    $propertyBagStart = $p

                    Write-Verbose "Parsing $($element.Key), $elementLength bytes"
                
                    # Parse version
                    Parse-TBRESVersion -Data $Data -Position ([ref]$p)

                    $properties = [ordered]@{}
                    While ($p -lt ( $propertyBagStart + $elementLength)) {
                        $property = Parse-TBRESKeyValue -Data $Data ([ref]$p)
                        if ($property.Key -eq "WA_Properties" -or $property.Key -eq "WA_Provier") {
                            $property.Value = Parse-TBRESElement -Data $Data ([ref]$p) -Element $property
                        }
                        $properties[$property.Key] = $property.Value
                    }
                    $value = [PSCustomObject]$properties
                }

                $Position.Value = $p

                return [PSCustomObject][ordered]@{
                    "Key"   = $element.Key
                    "Value" = $value
                }
            }
        }

        $p = 0

        # Parse version
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)

        # Parse expiration timestamp and responses guid
        $expiration = (Parse-TBRESKeyValue -Data $Data ([ref]$p)).value
        $responses = (Parse-TBRESKeyValue -Data $Data ([ref]$p)).value

        # Total response content length
        $responseLen = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4

        # Parse version
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)
        

        # It seems that sometimes the content have multiple "entries"
        # These start with the following key-value pair:
        # First: Key = 0x01 and Value = 1025
        # Second: Key = 0x01 and Value = 1025
        # These are handled in Parse-TBRESKeyValue function
        
        $unk = Parse-TBRESKeyValue -Data $Data ([ref]$p)

        #
        # Content
        #

        # Content length
        $contentLength = [BitConverter]::ToUInt32($Data[($p + 3)..$p], 0); $p += 4
        $contentStart = $p        

        # Parse version
        Parse-TBRESVersion -Data $Data -Position ([ref]$p)
        
        # Return value
        $properties = [ordered]@{}

        while ($p -le ($contentStart + $contentLength)) {
            try {
                $element = Parse-TBRESElement -Data $Data -Position ([ref]$p)
                if ($element -eq $null) {
                    return $null
                }
                $properties[$element.Key] = $element.Value
            }
            catch {
                Write-Verbose "Got exception: $($_.Exception.Message)"
                break
            }
        }

        return [PSCustomObject]$properties
    }
}

function Convert-B64ToByteArray {
    <#
    .SYNOPSIS
        Converts a Base64 string to a byte array.
    
    .PARAMETER B64
        The Base64 encoded string to convert.
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)]
        [string]$B64
    )
    return [Convert]::FromBase64String($B64)
}

function Get-ApplicationNameById {
    <#
    .SYNOPSIS
        Converts an Azure application ID (GUID) to its friendly name.
    
    .DESCRIPTION
        Maps commonly known Azure application IDs to their human-readable names.
        This helps in identifying which Microsoft service the token is for.
    
    .PARAMETER AppId
        The application ID (GUID) to look up.
    
    .EXAMPLE
        Get-ApplicationNameById -AppId "00000003-0000-0000-c000-000000000000"
        # Returns: "Microsoft Graph"
    #>
    param(
        [Parameter(Mandatory = $true)]
        [string]$AppId
    )
    $appIdToName = @{
        '23523755-3a2b-41ca-9315-f81f3f566a95' = 'ACOM Azure Website'
        '74658136-14ec-4630-ad9b-26e160ff0fc6' = 'ADIbizaUX'
        '69893ee3-dd10-4b1c-832d-4870354be3d8' = 'AEM-DualAuth'
        '7ab7862c-4c57-491e-8a45-d52a7e023983' = 'App Service'
        '0cb7b9ec-5336-483b-bc31-b15b5788de71' = 'ASM Campaign Servicing'
        '7b7531ad-5926-4f2d-8a1d-38495ad33e17' = 'Azure Advanced Threat Protection'
        'e9f49c6b-5ce5-44c8-925d-015017e9f7ad' = 'Azure Data Lake'
        '835b2a73-6e10-4aa5-a979-21dfda45231c' = 'Azure Lab Services Portal'
        'c44b4083-3bb0-49c1-b47d-974e53cbdf3c' = 'Azure Portal'
        '022907d3-0f1b-48f7-badc-1ba6abab6d66' = 'Azure SQL Database'
        '37182072-3c9c-4f6a-a4b3-b3f91cacffce' = 'AzureSupportCenter'
        '9ea1ad79-fdb6-4f9a-8bc3-2b70f96e34c7' = 'Bing'
        '20a11fe0-faa8-4df5-baf2-f965f8f9972e' = 'ContactsInferencingEmailProcessor'
        'bb2a2e3a-c5e7-4f0a-88e0-8e01fd3fc1f4' = 'CPIM Service'
        'e64aa8bc-8eb4-40e2-898b-cf261a25954f' = 'CRM Power BI Integration'
        '00000007-0000-0000-c000-000000000000' = 'Dataverse'
        '60c8bde5-3167-4f92-8fdb-059f6176dc0f' = 'Enterprise Roaming and Backup'
        '497effe9-df71-4043-a8bb-14cf78c4b63b' = 'Exchange Admin Center'
        'f5eaa862-7f08-448c-9c4e-f4047d4d4521' = 'FindTime'
        'b669c6ea-1adf-453f-b8bc-6d526592b419' = 'Focused Inbox'
        'c35cb2ba-f88b-4d15-aa9d-37bd443522e1' = 'GroupsRemoteApiRestClient'
        'd9b8ec3a-1e4e-4e08-b3c2-5baf00c0fcb0' = 'HxService'
        'a57aca87-cbc0-4f3c-8b9e-dc095fdc8978' = 'IAM Supportability'
        '16aeb910-ce68-41d1-9ac3-9e1673ac9575' = 'IrisSelectionFrontDoor'
        'd73f4b35-55c9-48c7-8b10-651f6f2acb2e' = 'MCAPI Authorization Prod'
        '944f0bd1-117b-4b1c-af26-804ed95e767e' = 'Media Analysis and Transformation Service'
        '0cd196ee-71bf-4fd6-a57c-b491ffd4fb1e' = 'Media Analysis and Transformation Service'
        '80ccca67-54bd-44ab-8625-4b79c4dc7775' = 'Microsoft 365 Security and Compliance Center'
        'ee272b19-4411-433f-8f28-5c13cb6fd407' = 'Microsoft 365 Support Service'
        '0000000c-0000-0000-c000-000000000000' = 'Microsoft App Access Panel'
        '65d91a3d-ab74-42e6-8a2f-0add61688c74' = 'Microsoft Approval Management'
        '38049638-cc2c-4cde-abe4-4479d721ed44' = 'Microsoft Approval Management'
        '29d9ed98-a469-4536-ade2-f981bc1d605e' = 'Microsoft Authentication Broker'
        '04b07795-8ddb-461a-bbee-02f9e1bf7b46' = 'Microsoft Azure CLI'
        '1950a258-227b-4e31-a9cf-717495945fc2' = 'Microsoft Azure PowerShell'
        '0000001a-0000-0000-c000-000000000000' = 'MicrosoftAzureActiveAuthn'
        'cf36b471-5b44-428c-9ce7-313bf84528de' = 'Microsoft Bing Search'
        '2d7f3606-b07d-41d1-b9d2-0d0c9296a6e8' = 'Microsoft Bing Search for Microsoft Edge'
        '1786c5ed-9644-47b2-8aa0-7201292175b6' = 'Microsoft Bing Default Search Engine'
        '3090ab82-f1c1-4cdf-af2c-5d7a6f3e2cc7' = 'Microsoft Defender for Cloud Apps'
        '60ca1954-583c-4d1f-86de-39d835f3e452' = 'Microsoft Defender for Identity (formerly Radius Aad Syncer)'
        '18fbca16-2224-45f6-85b0-f7bf2b39b3f3' = 'Microsoft Docs'
        '00000015-0000-0000-c000-000000000000' = 'Microsoft Dynamics ERP'
        '6253bca8-faf2-4587-8f2f-b056d80998a7' = 'Microsoft Edge Insider Addons Prod'
        '99b904fd-a1fe-455c-b86c-2f9fb1da7687' = 'Microsoft Exchange ForwardSync'
        '00000007-0000-0ff1-ce00-000000000000' = 'Microsoft Exchange Online Protection'
        '51be292c-a17e-4f17-9a7e-4b661fb16dd2' = 'Microsoft Exchange ProtectedServiceHost'
        'fb78d390-0c51-40cd-8e17-fdbfab77341b' = 'Microsoft Exchange REST API Based Powershell'
        '47629505-c2b6-4a80-adb1-9b3a3d233b7b' = 'Microsoft Exchange Web Services'
        '6326e366-9d6d-4c70-b22a-34c7ea72d73d' = 'Microsoft Exchange Message Tracking Service'
        'c9a559d2-7aab-4f13-a6ed-e7e9c52aec87' = 'Microsoft Forms'
        '00000003-0000-0000-c000-000000000000' = 'Microsoft Graph'
        '74bcdadc-2fdc-4bb3-8459-76d06952a0e9' = 'Microsoft Intune Web Company Portal'
        'fc0f3af4-6835-4174-b806-f7db311fd2f3' = 'Microsoft Intune Windows Agent'
        'd3590ed6-52b3-4102-aeff-aad2292ab01c' = 'Microsoft Office'
        '00000006-0000-0ff1-ce00-000000000000' = 'Microsoft Office 365 Portal'
        '67e3df25-268a-4324-a550-0de1c7f97287' = 'Microsoft Office Web Apps Service'
        'd176f6e7-38e5-40c9-8a78-3998aab820e7' = 'Microsoft Online Syndication Partner Portal'
        '5d661950-3475-41cd-a2c3-d671a3162bc1' = 'Microsoft Outlook'
        '93625bc8-bfe2-437a-97e0-3d0060024faa' = 'Microsoft password reset service'
        '871c010f-5e61-4fb1-83ac-98610a7e9110' = 'Microsoft Power BI'
        '28b567f6-162c-4f54-99a0-6887f387bbcc' = 'Microsoft Storefronts'
        'cf53fce8-def6-4aeb-8d30-b158e7b1cf83' = 'Microsoft Stream Portal'
        '98db8bd6-0cc0-4e67-9de5-f187f1cd1b41' = 'Microsoft Substrate Management'
        'fdf9885b-dd37-42bf-82e5-c3129ef5a302' = 'Microsoft Support'
        '1fec8e78-bce4-4aaf-ab1b-5451cc387264' = 'Microsoft Teams'
        'cc15fd57-2c6c-4117-a88c-83b1d56b4bbe' = 'Microsoft Teams Services'
        '5e3ce6c0-2b1f-4285-8d4b-75ee78787346' = 'Microsoft Teams Web Client'
        '95de633a-083e-42f5-b444-a4295d8e9314' = 'Microsoft Whiteboard Services'
        'dfe74da8-9279-44ec-8fb2-2aed9e1c73d0' = 'O365 SkypeSpaces Ingestion Service'
        '4345a7b9-9a63-4910-a426-35363201d503' = 'O365 Suite UX'
        '00000002-0000-0ff1-ce00-000000000000' = 'Office 365 Exchange Online'
        '00b41c95-dab0-4487-9791-b9d2c32c80f2' = 'Office 365 Management'
        '66a88757-258c-4c72-893c-3e8bed4d6899' = 'Office 365 Search Service'
        '00000003-0000-0ff1-ce00-000000000000' = 'Office 365 SharePoint Online'
        '94c63fef-13a3-47bc-8074-75af8c65887a' = 'Office Delve'
        '93d53678-613d-4013-afc1-62e9e444a0a5' = 'Office Online Add-in SSO'
        '2abdc806-e091-4495-9b10-b04d93c3f040' = 'Office Online Client Microsoft Entra ID- Augmentation Loop'
        'b23dd4db-9142-4734-867f-3577f640ad0c' = 'Office Online Client Microsoft Entra ID- Loki'
        '17d5e35f-655b-4fb0-8ae6-86356e9a49f5' = 'Office Online Client Microsoft Entra ID- Maker'
        'b6e69c34-5f1f-4c34-8cdf-7fea120b8670' = 'Office Online Client MSA- Loki'
        '243c63a3-247d-41c5-9d83-7788c43f1c43' = 'Office Online Core SSO'
        'a9b49b65-0a12-430b-9540-c80b3332c127' = 'Office Online Search'
        '4b233688-031c-404b-9a80-a4f3f2351f90' = 'Office.com'
        '89bee1f7-5e6e-4d8a-9f3d-ecd601259da7' = 'Office365 Shell WCSS-Client'
        '0f698dd4-f011-4d23-a33e-b36416dcb1e6' = 'OfficeClientService'
        '4765445b-32c6-49b0-83e6-1d93765276ca' = 'OfficeHome'
        '4d5c2d63-cf83-4365-853c-925fd1a64357' = 'OfficeShredderWacClient'
        '62256cef-54c0-4cb4-bcac-4c67989bdc40' = 'OMSOctopiPROD'
        'ab9b8c07-8f02-4f72-87fa-80105867a763' = 'OneDrive SyncEngine'
        '2d4d3d8e-2be3-4bef-9f87-7875a61c29de' = 'OneNote'
        '27922004-5251-4030-b22d-91ecd9a37ea4' = 'Outlook Mobile'
        'a3475900-ccec-4a69-98f5-a65cd5dc5306' = 'Partner Customer Delegated Admin Offline Processor'
        'bdd48c81-3a58-4ea9-849c-ebea7f6b6360' = 'Password Breach Authenticator'
        '35d54a08-36c9-4847-9018-93934c62740c' = 'PeoplePredictions'
        '00000009-0000-0000-c000-000000000000' = 'Power BI Service'
        'ae8e128e-080f-4086-b0e3-4c19301ada69' = 'Scheduling'
        'ffcb16e8-f789-467c-8ce9-f826a080d987' = 'SharedWithMe'
        '08e18876-6177-487e-b8b5-cf950c1e598c' = 'SharePoint Online Web Client Extensibility'
        'b4bddae8-ab25-483e-8670-df09b9f1d0ea' = 'Signup'
        '00000004-0000-0ff1-ce00-000000000000' = 'Skype for Business Online'
        '61109738-7d2b-4a0b-9fe3-660b1ff83505' = 'SpoolsProvisioning'
        '91ca2ca5-3b3e-41dd-ab65-809fa3dffffa' = 'Sticky Notes API'
        '13937bba-652e-4c46-b222-3003f4d1ff97' = 'Substrate Context Service'
        '26abc9a8-24f0-4b11-8234-e86ede698878' = 'SubstrateDirectoryEventProcessor'
        'a970bac6-63fe-4ec5-8884-8536862c42d4' = 'Substrate Search Settings Management Service'
        '905fcf26-4eb7-48a0-9ff0-8dcc7194b5ba' = 'Sway'
        '97cb1f73-50df-47d1-8fb0-0271f2728514' = 'Transcript Ingestion'
        '268761a2-03f3-40df-8a8b-c3db24145b6b' = 'Universal Store Native Client'
        '00000005-0000-0ff1-ce00-000000000000' = 'Viva Engage (formerly Yammer)'
        'fe93bfe1-7947-460a-a5e0-7a5906b51360' = 'Viva Insights'
        '3c896ded-22c5-450f-91f6-3d1ef0848f6e' = 'WeveEngine'
        '00000002-0000-0000-c000-000000000000' = 'Windows Azure Active Directory'
        '8edd93e1-2103-40b4-bd70-6e34e586362d' = 'Windows Azure Security Resource Provider'
        '797f4846-ba00-4fd7-ba43-dac1f8f63013' = 'Windows Azure Service Management API'
        'a3b79187-70b2-4139-83f9-6016c58cd27b' = 'WindowsDefenderATP Portal'
        '26a7ee05-5602-4d76-a7ba-eae8b7b67941' = 'Windows Search'
        '1b3c667f-cde3-4090-b60b-3d2abd0117f0' = 'Windows Spotlight'
        '45a330b1-b1ec-4cc1-9161-9f03992aa49f' = 'Windows Store for Business'
        'c1c74fed-04c9-4704-80dc-9f79a2e515cb' = 'Yammer Web'
        'e1ef36fd-b883-4dbf-97f0-9ece4b576fc6' = 'Yammer Web Embed'
        'de8bc8b5-d9f9-48b1-a8ad-b748da725064' = 'Graph Explorer'
        '14d82eec-204b-4c2f-b7e8-296a70dab67e' = 'Microsoft Graph Command Line Tools'
        '7ae974c5-1af7-4923-af3a-fb1fd14dcb7e' = 'OutlookUserSettingsConsumer'
        '5572c4c0-d078-44ce-b81c-6cbf8d3ed39e' = 'Vortex [wsfed enabled]'
        "4813382a-8fa7-425e-ab75-3b753aab3abb" = "Microsoft Authenticator App"
        "872cd9fa-d31f-45e0-9eab-6e460a02d1f1" = "Visual Studio"
        "af124e86-4e96-495a-b70a-90f90ab96707" = "OneDrive iOS App"
        "844cca35-0656-46ce-b636-13f48b0eecbd" = "Microsoft Stream Mobile Native"
        "87749df4-7ccf-48f8-aa87-704bad0e0e16" = "Microsoft Teams - Device Admin Agent"
        "0ec893e0-5785-4de6-99da-4ed124e5296c" = "Office UWP PWA"
        "22098786-6e16-43cc-a27d-191a01a1e3b5" = "Microsoft To-Do client"
        "4e291c71-d680-4d0e-9640-0a3358e31177" = "PowerApps"
        "57336123-6e14-4acc-8dcf-287b6088aa28" = "Microsoft Whiteboard Client"
        "57fcbcfa-7cee-4eb1-8b25-12d2030b4ee0" = "Microsoft Flow"
        "66375f6b-983f-4c2c-9701-d680650f588f" = "Microsoft Planner"
        "9ba1a5c7-f17a-4de9-a1f1-6178c8d51223" = "Microsoft Intune Company Portal"
        "a40d7d7d-59aa-447e-a655-679a4107e548" = "Accounts Control UI"
        "a569458c-7f2b-45cb-bab9-b7dee514d112" = "Yammer iPhone"
        "b26aadf8-566f-4478-926f-589f601d9c74" = "OneDrive"
        "c0d2a505-13b8-4ae0-aa9e-cddd5eab0b12" = "Microsoft Power BI"
        "d326c1ce-6cc6-4de2-bebc-4591e5e13ef0" = "SharePoint"
        "e9c51622-460d-4d3d-952d-966a5b1da34c" = "Microsoft Edge"
        "eb539595-3fe1-474e-9c1d-feb3625d1be5" = "Microsoft Tunnel"
        "ecd6b820-32c2-49b6-98a6-444530e5a77a" = "Microsoft Edge"
        "f05ff7c9-f75a-4acd-a3b5-f4b6a870245d" = "SharePoint Android"
        "f44b1140-bc5e-48c6-8dc0-5cf5a53c0e34" = "Microsoft Edge"
        "be1918be-3fe3-4be9-b32b-b542fc27f02e" = "M365 Compliance Drive Client"
        "cab96880-db5b-4e15-90a7-f3f1d62ffe39" = "Microsoft Defender Platform"
        "d7b530a4-7680-4c23-a8bf-c52c121d2e87" = "Microsoft Edge Enterprise New Tab Page"
        "dd47d17a-3194-4d86-bfd5-c6ae6f5651e3" = "Microsoft Defender for Mobile"
        "e9b154d0-7658-433b-bb25-6b8e0a8a7c59" = "Outlook Lite"
    }
    return $appIdToName[$AppId]
}

function Get-TBRESFiles {
    <#
    .SYNOPSIS
        Finds all .tbres files in the specified directory and its subdirectories.
    
    .PARAMETER DirectoryPath
        The root directory path to search for .tbres files.
    
    .EXAMPLE
        Get-TBRESFiles -DirectoryPath "C:\Users\username\AppData\Local\Microsoft\TokenBroker\Cache"
    #>
    param(
        [string]$DirectoryPath
    )
    return Get-ChildItem -Path $DirectoryPath -Filter *.tbres -File -Recurse
}

function Get-AudFromAccessToken {
    <#
    .SYNOPSIS
        Extracts the audience (aud) claim from a JWT access token.
    
    .DESCRIPTION
        Parses the JWT token to extract the audience (aud) claim, which identifies
        the intended recipient of the token (usually an Azure service).
    
    .PARAMETER AccessToken
        The JWT access token to parse.
    
    .EXAMPLE
        Get-AudFromAccessToken -AccessToken "eyJ0eXAi..."
    #>
    param (
        [string]$AccessToken
    )

    try {
        # Split the access token (JWT) into its parts
        $tokenParts = $AccessToken.Split('.')
        if ($tokenParts.Length -ne 3) {
            Write-Warning "Invalid access token format."
            return $null
        }

        # Decode the payload (the second part) which contains the claims
        $payload = $tokenParts[1]

        # Powershell doesnt have padding, so we need to add it
        $padding = 4 - ($payload.Length % 4)
        if ($padding -ne 4) {
            $payload += ("=" * $padding)
        }

        $decodedPayload = [System.Text.Encoding]::UTF8.GetString([Convert]::FromBase64String($payload))

        # Parse the JSON payload
        $claims = ConvertFrom-Json -InputObject $decodedPayload

        # Extract the 'aud' property
        $aud = $claims.aud
        return $aud

    }
    catch {
        Write-Warning "Error parsing access token: $($_.Exception.Message)"
        return $null
    }
}


function Get-DecryptedTBRES {
    <#
    .SYNOPSIS
        Decrypts and extracts information from a TBRES file.
    
    .DESCRIPTION
        Reads and parses a .tbres file, extracting token data, application information,
        and account details into a structured format.
    
    .PARAMETER FilePath
        The path to the .tbres file to decrypt.
    
    .EXAMPLE
        Get-DecryptedTBRES -FilePath "C:\path\to\file.tbres"
    #>
    param(
        [string]$FilePath
    )

    try {
        $rawBytes = [System.IO.File]::ReadAllBytes($FilePath)
        $parsed = Parse-TBRES -Data $rawBytes

        if ($parsed -ne $null) {
            $aud = Get-AudFromAccessToken -AccessToken $parsed.WTRes_Token
            return [PSCustomObject]@{
                File         = $FilePath
                TenantId     = $parsed.WTRes_Account.WA_Properties.Value.TenantId
                TenantName   = $parsed.WTRes_PropertyBag.tenant_display_name
                ResourceId   = $aud
                ResourceName = if (![string]::IsNullOrEmpty($aud)) { Get-ApplicationNameById -AppId $aud } else { $null }
                AppId        = $parsed.WTRes_PropertyBag.aud
                AppName      = if (![string]::IsNullOrEmpty($parsed.WTRes_PropertyBag.aud)) { Get-ApplicationNameById -AppId $parsed.WTRes_PropertyBag.aud } else { $null }
                Claims       = $parsed.WTRes_PropertyBag.amr
                Expires      = $parsed.WTRes_PropertyBag.exp
                Token        = $parsed.WTRes_Token
                ProviderId   = $parsed.WTRes_Account.WA_Provier.Value.WAP_Id
                UserName     = $parsed.WTRes_Account.WA_UserName
            }
        }
    }
    catch {
        Write-Warning "Failed to parse $FilePath : $($_.Exception.Message)"
    }
    return $null
}

function Get-ValidTokensFromTBRES {
    <#
    .SYNOPSIS
        Finds and extracts valid tokens from TokenBroker cache files.
    
    .DESCRIPTION
        Scans a directory for .tbres files, decrypts them, and returns any valid tokens found.
        By default, searches the standard TokenBroker cache location.
    
    .PARAMETER RootPath
        The directory path to search for .tbres files. Defaults to the standard TokenBroker cache location.
    
    .EXAMPLE
        Get-ValidTokensFromTBRES
        
    .EXAMPLE
        Get-ValidTokensFromTBRES -RootPath "C:\CustomPath\TokenBroker"
    #>
    param(
        [string]$RootPath = (Join-Path $env:USERPROFILE 'AppData\Local\Microsoft\TokenBroker\Cache')
    )

    $results = @()
    $files = Get-TBRESFiles -DirectoryPath $RootPath
    foreach ($file in $files) {
        $result = Get-DecryptedTBRES -FilePath $file.FullName
        if ($result -ne $null -and $result.Token) {
            Write-Host "[+] Valid token found in: $($file.FullName)"
            $results += $result
            $results += "-------------------"
        }
    }
    return $results
}

$validTokens = Get-ValidTokensFromTBRES

# Write valid tokens to a file
$outputFilePath = 'validTokens.txt'
$validTokens | Out-File -FilePath $outputFilePath -Encoding UTF8
Write-Host "Valid tokens written to: $outputFilePath"