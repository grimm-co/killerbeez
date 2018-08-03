echo "Results from a killerbeez run. This file ensures an empty zip file is not generated." > README.txt
Foreach($type in "crashes", "hangs", "new_paths") {
  Get-ChildItem output\$type |
  Foreach-Object {
    cp $_.FullName $('killerbeez_result_{0}_{1}' -f $type, $_.Name)
  }
}
