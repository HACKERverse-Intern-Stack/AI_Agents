# AI_Agents
This repository includes scripts of attack AI agents 

To host test server on Windows VM, use this command on Powershell while running as an administrator.
<br>
```$listener = [System.Net.Sockets.TcpListener]<PORT>```
<br>
```$listener.Start()```
<br>
```Write-Host "Listening on port <PORT>...```
<br>
```while($true){```
<br>
  ```$client = $listener.AcceptTcpClient()```
  <br>
  ```$stream = $client.GetStream()```
  <br>
  ```$writer = New-Object System.IO.StreamWriter($stream)```
  <br>
  ```$writer.WriteLine("Hello from test server")```
  <br>
  ```$writer.Flush()```
  <br>
  ```$client.Close()```
  <br>
```}```
