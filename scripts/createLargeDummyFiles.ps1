$folder = $args[0]

$numberDirs = $args[1]
$numberFiles = $args[2]

#create series of x directories in $Folder
for ($x = 0; $x -lt $numberDirs; $x++) {
    $dirname = "$((Get-Random -Minimum 1 -Maximum 10000).ToString())_BIGFOLDER"
    New-Item -ItemType Directory -Path "$folder\$dirname"

    Write-Host "[+] Number of directories created: $numberDirs in $folder\$dirname"
    Write-host "[+] Number of files created: $numberFiles"

    # Create a series of x files
    for ($y = 0; $y -lt $numberFiles; $y++) {
        $filename = "$Folder\$dirname\$((Get-Random -Minimum 1 -Maximum 100000).ToString())_BIGFILE.txt"
        $content = [byte[]]@(0) * (10MB)  # Change to modify the size
        [System.IO.File]::WriteAllBytes($filename, $content)
    }
}