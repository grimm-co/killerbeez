param (
  $from = "killerbeez-x64.zip",
  $into = $(pwd),
  $lockfile = "$into\unpack_killerbeez-x64.lock",
  $hashfile = "$into\killerbeez-x64.sha256",
  $extracted_name = "$into\killerbeez-x64"
)

# Try to prevent multiple copies from running at once. Yes, this has a TOCTOU
# race condition, but fixing it makes the script a lot more complicated, and it
# should just cause failed jobs that will be retried anyway.
while (Test-Path $lockfile) {
  sleep 10
}
echo $pid > $lockfile

# Check the hash of our killerbeez zip against the last one that was extracted
# to see if we have a new zip
$hash = (Get-FileHash $from -Algorithm SHA256).Hash
if (Test-Path $hashfile) {
  $old_hash = $(cat $hashfile).Trim()
  if ($old_hash -eq $hash) {
    echo "Killerbeez already unpacked, skipping archive extraction"
    rm $lockfile
    exit 0
  }
}
# Hash wasn't saved or didn't match, extract the zip
rmdir -r $extracted_name -ErrorAction 'silentlycontinue'
Expand-Archive $from -DestinationPath $into
echo $hash > $hashfile
rm $lockfile
