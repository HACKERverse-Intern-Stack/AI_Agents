# AI_Agents
This repository includes scripts of attack AI agents 

To host test server on Windows VM, use this command on Powershell while running as an administrator. Shown below:
<br>
```
$listener = [System.Net.Sockets.TcpListener]::new(8080)
$listener.Start()
Write-Host "Listening on port 8080..."
while ($true) {
    $client = $listener.AcceptTcpClient()
    $stream = $client.GetStream()
    $writer = New-Object System.IO.StreamWriter($stream)
    $writer.WriteLine("Hello from test server")
    $writer.Flush()
    $client.Close()
}
```
