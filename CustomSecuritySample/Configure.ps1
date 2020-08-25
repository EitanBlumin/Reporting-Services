param(
	[string]$UserAccountsSqlInstance = ".",
	[string]$UserAccountsDatabaseName = "ReportServerAccounts",
    [string]$SSRSAdminUsername = "SSRSAdmin",
    [string]$SSRSWebUsername = "WebUser",
    [string]$SSRSHost = "http://localhost:80",
	[string]$SSRSInstallPath = "C:\Program Files\Microsoft Report Server\SSRS"
	#[string]$SSRSInstallPath = "C:\Program Files\Microsoft Power BI Report Server\PBIRS"
	#[string]$SSRSInstallPath = "C:\Program Files\Microsoft SQL Server\MSRS13.MSSQLSERVER\Reporting Services"
	#[string]$SSRSInstallPath = "C:\Program Files\Microsoft SQL Server\MSRS12.MSSQLSERVER\Reporting Services"
)

Write-Verbose "UserAccountsSqlInstance: $UserAccountsSqlInstance"
Write-Verbose "UserAccountsDatabaseName: $UserAccountsDatabaseName"
Write-Verbose "SSRSAdminUsername: $SSRSAdminUsername"
Write-Verbose "SSRSWebUsername: $SSRSWebUsername"
Write-Verbose "SSRSHost: $SSRSHost"
Write-Verbose "SSRSInstallPath: $SSRSInstallPath"

if (-not (Test-Path "$SSRSInstallPath"))
{
	Write-Error "Path not found: $SSRSInstallPath"
	Exit
}

$appConfigFilePath = "Microsoft.Samples.ReportingServices.CustomSecurity.dll.config"
Write-Host "Updating $appConfigFilePath `n"
[xml]$appConfigFile = (Get-Content $appConfigFilePath)
$appConfigFile.configuration.applicationSettings.'Microsoft.Samples.ReportingServices.CustomSecurity.Properties.Settings'.setting|where {$_.name -eq "AnonymousUser"} | ForEach-Object { $_.value = $SSRSWebUsername }
$appConfigFile.configuration.applicationSettings.'Microsoft.Samples.ReportingServices.CustomSecurity.Properties.Settings'.setting|where {$_.name -eq "Microsoft_Samples_ReportingServices_CustomSecurity_localhost_ReportingService2010"} | ForEach-Object { $_.value = "$SSRSHost/ReportServer/ReportService2010.asmx" }
$appConfigFile.configuration.applicationSettings.'Microsoft.Samples.ReportingServices.CustomSecurity.Properties.Settings'.setting|where {$_.name -eq "Database_ConnectionString"} | ForEach-Object { $_.value = "Server=$UserAccountsSqlInstance;Integrated Security=SSPI;database=$UserAccountsDatabaseName" }
$appConfigFile.Save($appConfigFilePath)

$SetupScriptParameters = @("DBName=$UserAccountsDatabaseName")
Write-Host "Creating the User Store Database"
Invoke-SqlCmd -S "." -i "Setup\CreateUserStore.Sql" -Variable $SetupScriptParameters

Write-Host "Copying Logon.aspx page `n" -ForegroundColor Green
Copy-Item -Path Logon.aspx -Destination "$SSRSInstallPath\ReportServer\"

Write-Host "Copying Microsoft.Samples.ReportingServices.CustomSecurity.dll `n" -ForegroundColor Green
Copy-Item -Path Microsoft.Samples.ReportingServices.CustomSecurity.dll -Destination "$SSRSInstallPath\ReportServer\Bin\"
Copy-Item -Path Microsoft.Samples.ReportingServices.CustomSecurity.dll -Destination "$SSRSInstallPath\Portal\"
if (Test-Path "$SSRSInstallPath\PowerBi") Copy-Item -Path Microsoft.Samples.ReportingServices.CustomSecurity.dll -Destination "$SSRSInstallPath\PowerBi"

Write-Host "Copying $appConfigFilePath `n" -ForegroundColor Green
Copy-Item -Path $appConfigFilePath -Destination "$SSRSInstallPath\ReportServer\Bin\"
Copy-Item -Path $appConfigFilePath -Destination "$SSRSInstallPath\Portal\"
if (Test-Path "$SSRSInstallPath\PowerBi") Copy-Item -Path $appConfigFilePath -Destination "$SSRSInstallPath\PowerBi"

Write-Host "Copying Microsoft.Samples.ReportingServices.CustomSecurity.pdb `n" -ForegroundColor Green
Copy-Item -Path Microsoft.Samples.ReportingServices.CustomSecurity.pdb -Destination "$SSRSInstallPath\ReportServer\Bin\"
Copy-Item -Path Microsoft.Samples.ReportingServices.CustomSecurity.pdb -Destination "$SSRSInstallPath\Portal\"
if (Test-Path "$SSRSInstallPath\PowerBi") Copy-Item -Path Microsoft.Samples.ReportingServices.CustomSecurity.pdb -Destination "$SSRSInstallPath\PowerBi"

Write-Host "Updating rsreportserver.config `n" -ForegroundColor Green
$rsConfigFilePath = "$SSRSInstallPath\ReportServer\rsreportserver.config"
[xml]$rsConfigFile = (Get-Content $rsConfigFilePath)
Write-Host "Copy of the original config file in $rsConfigFilePath.backup"
$rsConfigFile.Save("$rsConfigFilePath.backup")
$rsConfigFile.Configuration.Authentication.AuthenticationTypes.InnerXml = "<Custom />"

$extension = $rsConfigFile.CreateElement("Extension")
$extension.SetAttribute("Name","Forms")
$extension.SetAttribute("Type","Microsoft.Samples.ReportingServices.CustomSecurity.Authorization, Microsoft.Samples.ReportingServices.CustomSecurity")
$configuration =$rsConfigFile.CreateElement("Configuration")
$configuration.InnerXml="<AdminConfiguration>`n<UserName>$SSRSAdminUsername</UserName>`n</AdminConfiguration>"
$extension.AppendChild($configuration)
$rsConfigFile.Configuration.Extensions.Security.AppendChild($extension)
$rsConfigFile.Configuration.Extensions.Authentication.Extension.Name ="Forms"
$rsConfigFile.Configuration.Extensions.Authentication.Extension.Type ="Microsoft.Samples.ReportingServices.CustomSecurity.AuthenticationExtension,Microsoft.Samples.ReportingServices.CustomSecurity"

$rsConfigFile.Save($rsConfigFilePath)

Write-Host "Updating RSSrvPolicy.config `n" -ForegroundColor Green
$rsPolicyFilePath = "$SSRSInstallPath\ReportServer\rssrvpolicy.config"
[xml]$rsPolicy = (Get-Content $rsPolicyFilePath)
Write-Host "Copy of the original config file in $rsPolicyFilePath.backup"
$rsPolicy.Save("$rsPolicyFilePath.backup")

$codeGroup = $rsPolicy.CreateElement("CodeGroup")
$codeGroup.SetAttribute("class","UnionCodeGroup")
$codeGroup.SetAttribute("version","1")
$codeGroup.SetAttribute("Name","SecurityExtensionCodeGroup")
$codeGroup.SetAttribute("Description","Code group for the sample security extension")
$codeGroup.SetAttribute("PermissionSetName","FullTrust")
$codeGroup.InnerXml ="<IMembershipCondition class=""UrlMembershipCondition"" version=""1"" Url=""$SSRSInstallPath\ReportServer\bin\Microsoft.Samples.ReportingServices.CustomSecurity.dll""/>"
$rsPolicy.Configuration.mscorlib.security.policy.policylevel.CodeGroup.CodeGroup.AppendChild($codeGroup)
$rsPolicy.Save($rsPolicyFilePath)


Write-Host "Updating web.config `n" -ForegroundColor Green
$webConfigFilePath = "$SSRSInstallPath\ReportServer\web.config"
[xml]$webConfig = (Get-Content $webConfigFilePath)
Write-Host "Copy of the original config file in $webConfigFilePath.backup"
$webConfig.Save("$webConfigFilePath.backup")
$webConfig.configuration.'system.web'.identity.impersonate="false"
$webConfig.configuration.'system.web'.authentication.mode="Forms"
$webConfig.configuration.'system.web'.authentication.InnerXml="<forms loginUrl=""logon.aspx"" name=""sqlAuthCookie"" timeout=""60"" path=""/""></forms>"
$authorization = $webConfig.CreateElement("authorization")
$authorization.InnerXml="<deny users=""?"" />"
$webConfig.configuration.'system.web'.AppendChild($authorization)
$webConfig.Save($webConfigFilePath)

$decryptionAlgorithm = 'AES'
$validationAlgorithm = 'SHA1'

# Generates a <machineKey> element that can be copied + pasted into a Web.config file.
#function Generate-MachineKey {
#  [CmdletBinding()]
#  param (
#    [ValidateSet("AES", "DES", "3DES")]
#    [string]$decryptionAlgorithm = 'AES',
#    [ValidateSet("MD5", "SHA1", "HMACSHA256", "HMACSHA384", "HMACSHA512")]
#    [string]$validationAlgorithm = 'HMACSHA256'
#  )
#  process {
    function BinaryToHex {
        [CmdLetBinding()]
        param($bytes)
        process {
            $builder = new-object System.Text.StringBuilder
            foreach ($b in $bytes) {
              $builder = $builder.AppendFormat([System.Globalization.CultureInfo]::InvariantCulture, "{0:X2}", $b)
            }
            $builder
        }
    }
    switch ($decryptionAlgorithm) {
      "AES" { $decryptionObject = new-object System.Security.Cryptography.AesCryptoServiceProvider }
      "DES" { $decryptionObject = new-object System.Security.Cryptography.DESCryptoServiceProvider }
      "3DES" { $decryptionObject = new-object System.Security.Cryptography.TripleDESCryptoServiceProvider }
    }
    $decryptionObject.GenerateKey()
    $decryptionKey = BinaryToHex($decryptionObject.Key)
    $decryptionObject.Dispose()
    switch ($validationAlgorithm) {
      "MD5" { $validationObject = new-object System.Security.Cryptography.HMACMD5 }
      "SHA1" { $validationObject = new-object System.Security.Cryptography.HMACSHA1 }
      "HMACSHA256" { $validationObject = new-object System.Security.Cryptography.HMACSHA256 }
      "HMACSHA385" { $validationObject = new-object System.Security.Cryptography.HMACSHA384 }
      "HMACSHA512" { $validationObject = new-object System.Security.Cryptography.HMACSHA512 }
    }
    $validationKey = BinaryToHex($validationObject.Key)
    $validationObject.Dispose()
    #[string]::Format([System.Globalization.CultureInfo]::InvariantCulture,
    #  "<machineKey decryption=`"{0}`" decryptionKey=`"{1}`" validation=`"{2}`" validationKey=`"{3}`" />",
    #  $decryptionAlgorithm.ToUpperInvariant(), $decryptionKey,
    #  $validationAlgorithm.ToUpperInvariant(), $validationKey)
#  }
#}
#Generate-MachineKey -validation sha1

Write-Host "Adding Machine Keys to $rsConfigFilePath `n" -ForegroundColor Green
[xml]$rsConfigFile = (Get-Content $rsConfigFilePath)
$machineKey = $rsConfigFile.CreateElement("MachineKey")
$machineKey.SetAttribute("ValidationKey", $decryptionKey)
$machineKey.SetAttribute("DecryptionKey", $validationKey)
$machineKey.SetAttribute("Validation", $validationAlgorithm)
$machineKey.SetAttribute("Decryption", $decryptionAlgorithm)
$rsConfigFile.Configuration.AppendChild($machineKey)
$rsConfigFile.Save($rsConfigFilePath)


Write-Host "Configuring Passthrough cookies `n" -ForegroundColor Green
[xml]$rsConfigFile = (Get-Content $rsConfigFilePath)
$customUI = $rsConfigFile.CreateElement("CustomAuthenticationUI")
$customUI.InnerXml ="<PassThroughCookies><PassThroughCookie>sqlAuthCookie</PassThroughCookie></PassThroughCookies>"
$rsConfigFile.Configuration.UI.AppendChild($customUI)
$rsConfigFile.Save($rsConfigFilePath)

Write-Host "Done."