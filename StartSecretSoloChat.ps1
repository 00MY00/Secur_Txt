#####################################################################
# Proof of Concept
# Créé par : Kuroakashiro
# Pour plus de sécurité, on pourrait supprimer les variables inutiles
# et adopter une autre méthode de chiffrement qui éviterait le déchiffrement basé sur les probabilités en ajoutant un faux random au txt.
#####################################################################



# Verrifi que les fichier exist
if (-Not (Test-Path "Hash_Login.txt")) {
    New-Item -Type File -Path "Hash_Login.txt"
}
if (-Not (Test-Path "Hash_tchek_msgApp.txt")) {
    New-Item -Type File -Path "Hash_tchek_msgApp.txt"
}
if (-Not (Test-Path "MSG.txt")) {
    New-Item -Type File -Path "MSG.txt"
}



# New Login
function Is-FileEmpty {
    param (
        [string]$filePath = "Hash_Login.txt"
    )

    if (-not (Test-Path $filePath)) {
        Write-Error "Le fichier $filePath n'existe pas."
        return $false
    }

    $fileContent = Get-Content -Path $filePath -Raw

    # Vérifiez si le contenu est null ou vide
    if (-not $fileContent) {
        return $true
    }

    # Retire les espaces en début et en fin de chaîne
    $trimmedContent = $fileContent.Trim()

    # Si le contenu est vide ou uniquement des espaces, considérez le fichier comme vide
    return [string]::IsNullOrEmpty($trimmedContent)
}


function Is-File2Empty {
    param (
        [string]$filePath = "Hash_tchek_msgApp.txt"
    )

    if (-not (Test-Path $filePath)) {
        Write-Error "Le fichier $filePath n'existe pas."
        return $false
    }

    $fileContent = Get-Content -Path $filePath -Raw

    # Vérifiez si le contenu est null ou vide
    if (-not $fileContent) {
        return $true
    }

    # Retire les espaces en début et en fin de chaîne
    $trimmedContent = $fileContent.Trim()

    # Si le contenu est vide ou uniquement des espaces, considérez le fichier comme vide
    return [string]::IsNullOrEmpty($trimmedContent)
}

function Is-File3Empty {
    param (
        [string]$filePath = "MSG.txt"
    )

    if (-not (Test-Path $filePath)) {
        Write-Error "Le fichier $filePath n'existe pas."
        return $false
    }

    $fileContent = Get-Content -Path $filePath -Raw

    # Vérifiez si le contenu est null ou vide
    if (-not $fileContent) {
        return $false # Le fichier est vide
    }

    # Retire les espaces en début et en fin de chaîne
    $trimmedContent = $fileContent.Trim()

    # Si le contenu n'est pas vide ou uniquement des espaces, considérez le fichier comme non vide
    return -not [string]::IsNullOrEmpty($trimmedContent)
}



function Get-PasswordHash {
    # Demande à l'utilisateur d'entrer un mot de passe
    $password = Read-Host "Veuillez entrer un mot de passe" -AsSecureString

    # Convertir le SecureString en String normal (à ne pas faire en production, pour des raisons de sécurité)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    # Hacher le mot de passe
    $hashValue = Get-Hash -inputString $plainPassword
    
    # Enregistrer le hash dans Hash_Login.txt
    $hashValue | Out-File -FilePath 'Hash_Login.txt' -Append

    return $hashValue
}

function Get-PasswordHash2 {
    # Demande à l'utilisateur d'entrer un mot de passe
    $password = Read-Host "Veuillez entrer un mot de passe" -AsSecureString

    # Convertir le SecureString en String normal (à ne pas faire en production, pour des raisons de sécurité)
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    # Hacher le mot de passe
    $hashValue = Get-Hash -inputString $plainPassword
    
    # Enregistrer le hash dans Hash_Login.txt
    ($hashValue.Substring(0, 10)) | Out-File -FilePath 'Hash_tchek_msgApp.txt' -Append

    return $hashValue
}

function Get-Hash($inputString) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
    $hashBytes = $hasher.ComputeHash($inputBytes)
    return [BitConverter]::ToString($hashBytes) -replace '-'
}

function Validate-Password {
    # Demande à l'utilisateur d'entrer un mot de passe
    $password = Read-Host "Veuillez entrer un mot de passe" -AsSecureString

    # Convertir le SecureString en String normal 
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    # Hacher le mot de passe
    $inputHash = Get-Hash -inputString $plainPassword

    # Lire le hash du fichier Hash_Login.txt
    $storedHash = Get-Content -Path 'Hash_Login.txt' -Raw

    # Comparer les deux hashes
    return $inputHash -eq $storedHash.trim()
}

function Validate-Password2 {
    # Demande à l'utilisateur d'entrer un mot de passe
    $password = Read-Host "MSG : Veuillez entrer un mot de passe" -AsSecureString

    # Convertir le SecureString en String normal 
    $bstr = [System.Runtime.InteropServices.Marshal]::SecureStringToBSTR($password)
    $plainPassword = [System.Runtime.InteropServices.Marshal]::PtrToStringAuto($bstr)

    # Hacher le mot de passe
    $inputHash = Get-Hash -inputString $plainPassword
    $firstTenChars = $inputHash.Substring(0, 10)


    # Lire le hash du fichier Hash_Login.txt
    $storedHash = (Get-Content -Path 'Hash_tchek_msgApp.txt' -Raw).Substring(0, 10)

    # Créer un objet personnalisé pour stocker le hash et le résultat de la comparaison
    $result = [PSCustomObject]@{
        Hash           = $inputHash
        IsPasswordValid = ($firstTenChars.trim() -eq $storedHash.trim())
    }

    return $result
}





# Charger les assemblages nécessaires
Add-Type -AssemblyName System.Security

function Encrypt-AES {
    param (
        [Parameter(Mandatory = $true)]
        [string]$PlainText,

        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.IV = New-Object byte[] $aes.IV.Length

    $encryptor = $aes.CreateEncryptor()
    $encryptedBytes = $encryptor.TransformFinalBlock([System.Text.Encoding]::UTF8.GetBytes($PlainText), 0, $PlainText.Length)

    return [Convert]::ToBase64String($encryptedBytes)
}

function Decrypt-AES {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EncryptedText,

        [Parameter(Mandatory = $true)]
        [string]$Key
    )

    $aes = New-Object System.Security.Cryptography.AesManaged
    $aes.Key = [System.Text.Encoding]::UTF8.GetBytes($Key)
    $aes.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aes.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7
    $aes.IV = New-Object byte[] $aes.IV.Length

    $decryptor = $aes.CreateDecryptor()
    $encryptedBytes = [Convert]::FromBase64String($EncryptedText)
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

    return [System.Text.Encoding]::UTF8.GetString($decryptedBytes)
}



function Get-ConcatenatedHash {
    param (
        [string]$Key
    )

    # Initialise une variable vide pour stocker le résultat final
    $finalHash = ""

    # Pour chaque caractère dans $Key, hachez le caractère et ajoutez le hachage à $finalHash
    foreach ($char in $Key.ToCharArray()) {
        $hashValue = Get-Hash -inputString $char
        $finalHash += $hashValue
    }

    return $finalHash
}

function Get-Hash($inputString) {
    $hasher = [System.Security.Cryptography.SHA256]::Create()
    $inputBytes = [System.Text.Encoding]::UTF8.GetBytes($inputString)
    $hashBytes = $hasher.ComputeHash($inputBytes)
    return [BitConverter]::ToString($hashBytes) -replace '-'
}

function Get-Last32Digits {
    param (
        [string]$Key
    )

    # Retirer tous les caractères qui ne sont pas des chiffres (0-9)
    $numericOnly = $Key -replace '[^\d]', ''

    # Prendre les 32 derniers chiffres
    $last32Digits = $numericOnly.Substring([Math]::Max(0, $numericOnly.Length - 32))

    return $last32Digits
}






# Main
cls
if (Is-FileEmpty) {
    Write-Host "Bonjour, entrez un MDP"
    Get-PasswordHash
} else {
    $isPasswordValid = Validate-Password
    if ($isPasswordValid) {
        Write-Host "Le mot de passe est correct." -ForegroundColor Green
        
    } else {
        Write-Host "Le mot de passe est incorrect." -ForegroundColor Red
        exit(0)
    }
}

#Passer au messages
if (Is-File2Empty) {
    Write-Host "Messages"
    Write-Host "Bonjour, entrez un MDP"
    $key = Get-PasswordHash2
} else {
    $validationResult = Validate-Password2
    if ($validationResult.IsPasswordValid) {
        Write-Host "Le mot de passe est correct." -ForegroundColor Green
        $Key = $validationResult.Hash
    } else {
        Write-Host "Le mot de passe est incorrect." -ForegroundColor Red
        exit(0)
    }
}



#Write-Host "La clé est $Key"
#Write-Host "------------------------------"
$Key = Get-ConcatenatedHash -Key $Key
$Key = Get-Last32Digits -Key $Key
#Write-Host "La clé complaite est $Key"


while ($True) {
    cls

    if (Is-File3Empty) {
        Write-Host "Messages trouvée !`n" -ForegroundColor Yellow
        Get-Content -Path 'MSG.txt' | ForEach-Object {
            $decryptedText = Decrypt-AES -EncryptedText $_ -Key $Key
            Write-Host "- " -NoNewline -ForegroundColor Magenta
            Write-Host $decryptedText -ForegroundColor Cyan
        }

    } else {
        Write-Host "Auccun Messages trouvée !`n" -ForegroundColor Gray
    }

    Write-Host "`n`nEntrez votre Message secret !`nexit pour quitter`n"

    $txt = Read-Host "-> "

    if ($txt -eq "exit") {
        cls
        Write-Host "BYE BYE !" -ForegroundColor Green
        break
    }

    if (-Not ($txt -eq "")) {
        $encryptedText = Encrypt-AES -PlainText "$txt" -Key $Key
        $encryptedText | Out-File 'MSG.txt' -Append

    }

}

exit(0)

