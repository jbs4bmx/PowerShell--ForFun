$shellApp = New-Object -ComObject Shell.Application
$appsFolder = $shellApp.Namespace('shell:::{4234d49b-0245-4df3-b780-3893943456e1}')

$appsFolder.Items() | ForEach-Object {
    $name = $_.Name
    $verbs = $_.Verbs() | ForEach-Object { $_.Name.Replace('&','').Trim() }
    $match = $verbs | Where-Object { $_ -in @('Unpin from Start','Unpin from taskbar') }
    if ($match) { "$name -> $($match -join ', ')" }
}
