Foreach($type in "crashes", "hangs", "new_paths") {
  Get-ChildItem output\$type |
  Foreach-Object {
    cp $_.FullName $('killerbeez_result_{0}_{1}' -f $type, $_.Name)
  }
}
