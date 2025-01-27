function Decrypt-String {
    param (
        [Parameter(Mandatory = $true)]
        [string]$EncryptedText,

        [Parameter(Mandatory = $true)]
        [string]$Key,

        [Parameter(Mandatory = $true)]
        [string]$InitializationVector
    )

    # Convert the encrypted text, key, and IV to byte arrays
    $encryptedBytes = [Convert]::FromBase64String($EncryptedText)
    $keyBytes = [Text.Encoding]::UTF8.GetBytes($Key)
    $ivBytes = [Text.Encoding]::UTF8.GetBytes($InitializationVector)

    # Ensure the key and IV lengths match the AES block size
    if ($keyBytes.Length -ne 16) { throw "AES requires a 16-byte key." }
    if ($ivBytes.Length -ne 16) { throw "AES requires a 16-byte IV." }

    # Create an AES object for decryption
    $aesAlg = [System.Security.Cryptography.Aes]::Create()
    $aesAlg.Key = $keyBytes
    $aesAlg.IV = $ivBytes
    $aesAlg.Mode = [System.Security.Cryptography.CipherMode]::CBC
    $aesAlg.Padding = [System.Security.Cryptography.PaddingMode]::PKCS7

    # Create a decryptor
    $decryptor = $aesAlg.CreateDecryptor()

    # Perform decryption
    $decryptedBytes = $decryptor.TransformFinalBlock($encryptedBytes, 0, $encryptedBytes.Length)

    # Convert decrypted bytes to string
    $decryptedText = [Text.Encoding]::UTF8.GetString($decryptedBytes)

    return $decryptedText
}

# Example usage
# Replace these values with actual encrypted text, key, and IV
$encryptedText = "Sd5ELBxFX6x/IBP2BazVig=="
$key = "JQ07hTr42Vb0T11a"  # Must be 16 bytes for AES-128
$InitializationVector = "PlEnk3YsW0T1Gr43"  # Must be 16 bytes for AES-128

$decryptedText = Decrypt-String -EncryptedText $encryptedText -Key $key -InitializationVector $InitializationVector
Write-Output $decryptedText
