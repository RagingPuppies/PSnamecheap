
function Create-Cert {
    param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$APIkey,
        [Parameter(Mandatory=$true)]
        [string]$ClientIP,
        [Parameter(Mandatory=$true)]
        [string]$Years,
        [ValidateSet( 'PositiveSSL', 'EssentialSSL', 'InstantSSL', 'InstantSSL Pro', 'PremiumSSL', 'EV SSL', 'PositiveSSL Wildcard', 'EssentialSSL Wildcard', 'PremiumSSL Wildcard', 'PositiveSSL Multi Domain', 'Multi Domain SSL', 'Unified Communications', 'EV Multi Domain SSL')]
        $SSLType,
        [Parameter(Mandatory=$true)]
        [ValidateSet('api.sandbox','api')]
        $APIEnvironment
    )

    try {

        $URI = "https://$APIEnvironment.namecheap.com/xml.response?ApiUser=$User&APIKey=$APIkey&UserName=$User&ClientIp=$ClientIP&Command=namecheap.ssl.create&Years=$Years&Type=$SSLType"
        [xml]$call = (Invoke-WebRequest -Method GET -uri $URI ).content

        if($call.ApiResponse.Status -eq 'OK'){

            $New_SSL = New-Object -TypeName psobject
            $New_SSL | Add-Member -MemberType NoteProperty -Name Status -Value $call.ApiResponse.Status
            $New_SSL | Add-Member -MemberType NoteProperty -Name SSLtype -Value $SSLType
            $New_SSL | Add-Member -MemberType NoteProperty -Name CertificateID -Value $call.ApiResponse.CommandResponse.SSLCreateResult.SSLCertificate.CertificateID
            return $New_SSL

        }

        else {

            write-host -ForegroundColor Red "ERROR:" $call.ApiResponse.Errors.Error.'#text'

            }

    }
    catch {

        $ErrorMessage = $_.Exception.Message

        write-host -ForegroundColor Red "ERROR:" $ErrorMessage

    }
    }


function Activate-Cert {
    param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$APIkey,
        [Parameter(Mandatory=$true)]
        [string]$ClientIP,
        [Parameter(Mandatory=$true)]
        [string]$CertificateID,
        [Parameter(Mandatory=$true)]
        $CSR,
        [Parameter(Mandatory=$true)]
        [string]$AdminEmail,
        [Parameter(Mandatory=$true)]
        [ValidateSet('HTTPDCValidation','DNSDCValidation')]
        [string]$Validation,
        [Parameter(Mandatory=$true)]
        [ValidateSet('api.sandbox','api')]
        $APIEnvironment,
        [Parameter(Mandatory=$false)]
        $Additional = ''
    )

    try {

        Add-Type -AssemblyName System.Web

        $CSR_ENCODED = [System.Web.HttpUtility]::UrlEncode($CSR)
        $AdminEmail_ENCODED = [System.Web.HttpUtility]::UrlEncode($AdminEmail)

        $URI = "https://$APIEnvironment.namecheap.com/xml.response?ApiUser=$User&APIKey=$APIkey&UserName=$User&ClientIp=$ClientIP&Command=namecheap.ssl.activate&CertificateID=$CertificateID&csr=$CSR_ENCODED&AdminEmailAddress=$AdminEmail_ENCODED&$Validation=True$Additional"

        [xml]$call = (Invoke-WebRequest -Method GET -uri $URI ).content

        if($call.ApiResponse.Status -eq 'OK'){

            $Active_SSL = New-Object -TypeName psobject
            $Active_SSL | Add-Member -MemberType NoteProperty -Name Status -Value $call.ApiResponse.Status
            if ($Validation = 'DNSDCValidation'){
                $Active_SSL | Add-Member -MemberType NoteProperty -Name HostName -Value $call.ApiResponse.CommandResponse.SSLActivateResult.DNSDCValidation.dns.HostName.'#cdata-section'
                $Active_SSL | Add-Member -MemberType NoteProperty -Name Target -Value $call.ApiResponse.CommandResponse.SSLActivateResult.DNSDCValidation.dns.Target.'#cdata-section'
            }
            else {
                $Active_SSL | Add-Member -MemberType NoteProperty -Name FileName -Value $call.ApiResponse.CommandResponse.SSLActivateResult.HttpDCValidation.dns.FileName.'#cdata-section'
                $Active_SSL | Add-Member -MemberType NoteProperty -Name FileContent -Value $call.ApiResponse.CommandResponse.SSLActivateResult.HttpDCValidation.dns.FileContent.'#cdata-section'
            }
            return $Active_SSL

        }

        else {

            write-host -ForegroundColor Red "ERROR:" $call.ApiResponse.Errors.Error.'#text'

            }

    }
    catch {

        $ErrorMessage = $_.Exception.Message

        write-host -ForegroundColor Red "ERROR:" $ErrorMessage

    }
    }


function Get-Cert {
    param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$APIkey,
        [Parameter(Mandatory=$true)]
        [string]$ClientIP,
        [Parameter(Mandatory=$true)]
        [string]$CertificateID,
        [Parameter(Mandatory=$true)]
        [ValidateSet('api.sandbox','api')]
        $APIEnvironment,
        [Parameter(Mandatory=$false)]
        [ValidateSet('Individual','PKCS7')]
        $CertType = 'Individual'
    )

    try {

        $URI = "https://$APIEnvironment.namecheap.com/xml.response?ApiUser=$User&APIKey=$APIkey&UserName=$User&ClientIp=$ClientIP&Command=namecheap.ssl.getinfo&certificateID=$CertificateID&returncertificate=true&returntype=$CertType"
        [xml]$call = (Invoke-WebRequest -Method GET -uri $URI ).content

        if($call.ApiResponse.Status -eq 'OK'){

            $Get_SSL = New-Object -TypeName psobject
            $Get_SSL | Add-Member -MemberType NoteProperty -Name Status -Value $call.ApiResponse.CommandResponse.SSLGetInfoResult.Status
            $Get_SSL | Add-Member -MemberType NoteProperty -Name Expires -Value $call.ApiResponse.CommandResponse.SSLGetInfoResult.Expires
            $Get_SSL | Add-Member -MemberType NoteProperty -Name CRT -Value $call.ApiResponse.CommandResponse.SSLGetInfoResult.CertificateDetails.Certificates.Certificate.'#cdata-section' 
            $Get_SSL | Add-Member -MemberType NoteProperty -Name CSR -Value $call.ApiResponse.CommandResponse.SSLGetInfoResult.CertificateDetails.CSR.'#cdata-section'
            $Get_SSL | Add-Member -MemberType NoteProperty -Name Type -Value $call.ApiResponse.CommandResponse.SSLGetInfoResult.Type

                return $Get_SSL

        }

        else {

            write-host -ForegroundColor Red "ERROR:" $call.ApiResponse.Errors.Error.'#text'

            }

    }
    catch {

        $ErrorMessage = $_.Exception.Message

        write-host -ForegroundColor Red "ERROR:" $ErrorMessage

    }
    }


function Get-CertList {
    param(
        [Parameter(Mandatory=$true)]
        [string]$User,
        [Parameter(Mandatory=$true)]
        [string]$APIkey,
        [Parameter(Mandatory=$true)]
        [string]$ClientIP,
        [Parameter(Mandatory=$true)]
        [ValidateSet('api.sandbox','api')]
        $APIEnvironment

    )

    try {

        $URI = "https://$APIEnvironment.namecheap.com/xml.response?ApiUser=$User&APIKey=$APIkey&UserName=$User&ClientIp=$ClientIP&Command=namecheap.ssl.getList&pagesize=100&ListType=active"
        [xml]$call = (Invoke-WebRequest -Method GET -uri $URI ).content

        if($call.ApiResponse.Status -eq 'OK'){

            $SSL_LIST = @()

                foreach( $ssl in $call.ApiResponse.CommandResponse.SSLListResult.SSL){
                    $Get_SSL_LIST = New-Object -TypeName psobject
                    $Get_SSL_LIST | Add-Member -MemberType NoteProperty -Name HostName -Value $ssl.Hostname
                    $Get_SSL_LIST | Add-Member -MemberType NoteProperty -Name CertificateID -Value $ssl.CertificateID
                    $Get_SSL_LIST | Add-Member -MemberType NoteProperty -Name PurchaseDate -Value $ssl.PurchaseDate
                    $Get_SSL_LIST | Add-Member -MemberType NoteProperty -Name ExpireDate -Value $ssl.ExpireDate
                    $Get_SSL_LIST | Add-Member -MemberType NoteProperty -Name Status -Value $ssl.Status

                    $SSL_LIST += $Get_SSL_LIST

                }
            
                    


                return $call

        }

        else {

            write-host -ForegroundColor Red "ERROR:" $call.ApiResponse.Errors.Error.'#text'

            }

    }
    catch {

        $ErrorMessage = $_.Exception.Message

        write-host -ForegroundColor Red "ERROR:" $ErrorMessage

    }
    }
