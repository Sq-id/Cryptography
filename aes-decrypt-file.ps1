function Convert-HexToByteArray($hex) {
    $byteArray = New-Object Byte[] ($hex.Length / 2)
    for ($i = 0; $i -lt $hex.Length; $i+=2) {
        $byteArray[$i / 2] = [Convert]::ToByte($hex.Substring($i, 2), 16)
    }
    return $byteArray
}

function AES-Decrypt {
    param(
        [string]$iv,  
        [string]$key, 
        [byte[]]$encryptedBytes
    )

    $b_iv = Convert-HexToByteArray $iv
    $b_key = Convert-HexToByteArray $key

    $rijndaelManaged = New-Object System.Security.Cryptography.RijndaelManaged
    $rijndaelManaged.KeySize = $b_key.Length * 8  
    $rijndaelManaged.Key = $b_key
    $rijndaelManaged.BlockSize = $b_iv.Length * 8 
    $rijndaelManaged.IV = $b_iv
    $rijndaelManaged.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $rijndaelManaged.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    $decryptor = $rijndaelManaged.CreateDecryptor()


    $memoryStream = New-Object System.IO.MemoryStream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream($memoryStream, $decryptor, [System.Security.Cryptography.CryptoStreamMode]::Write)
    $cryptoStream.Write($encryptedBytes, 0, $encryptedBytes.Length)
    $cryptoStream.FlushFinalBlock()

    return $memoryStream.ToArray()
}

function Decrypt-Files {
    param(
        [string]$folderPath, 
        [array]$keys, 
        [array]$ivs
    )

    if ($keys.Length -ne $ivs.Length) {
        Write-Host "Error: The number of keys does not match the number of IVs."
        return
    }

    $files = Get-ChildItem -Path $folderPath -Recurse -Filter "*.encrypted"

    foreach ($file in $files) {
        $encryptedBytes = [System.IO.File]::ReadAllBytes($file.FullName)

        for ($i = 0; $i -lt $keys.Length; $i++) {
            $key = $keys[$i]
            $iv = $ivs[$i]

            try {
                $decryptedBytes = AES-Decrypt -iv $iv -key $key -encryptedBytes $encryptedBytes
                
                $decryptedFilePath = Join-Path $folderPath "$($file.BaseName)_decrypted.pdf"
                
                [System.IO.File]::WriteAllBytes($decryptedFilePath, $decryptedBytes)
                
                Write-Host "Decrypted $($file.FullName) using IV: $iv and KEY: $key and saved as $decryptedFilePath"
                break 
            }
            catch {
                Write-Host "Decryption failed for $($file.FullName) using IV: $iv and KEY: $key"
            }
        }
    }
}


$Keys = Get-Content .\Keys.csv
$IVs = Get-Content .\IVs.csv


$folderPath = "C:\folder\with\encrypted\files"

Decrypt-Files -folderPath $folderPath -keys $Keys -ivs $IVs
