#WCFDSer-ngng



A Burp Extender plugin, that will make binary soap objects readable and modifiable. Based on the original work of Brian Holyfield, all hail Brian http://blog.gdssecurity.com/labs/2009/11/19/wcf-binary-soap-plug-in-for-burp.html

Why? This release fixes a bug where serialization wasn't being performed properly. It also adds in the (proper) ability to use the scanner/intrude in conjunction with WCF. It also works with SQLMap if you right click -> send deserialized to intruder, and then copy/paste that into a file, then run sqlmap -r file.txt with the --proxy option. 

Basically, it will deserialize, modify, reserialize, send on and (only in the case of the scanner) deserialize any responses that look like WCF objects (to allow burp to flag any exception strings, etc.).

nb. that it does make use of the "Via" header to allow it to mark requests that need serialization (and let it pass properly formatted http checks in sqlmap). If you need the via header for something, you're going to have to use something else, change the SERIALIZEHEADER in the utils file and recompile.

## How to use:
1- Run the NBFSNetService.exe file which listens on port 7686 by default

2- Add the extension and view decoded requests or responses in editor

## HackerVertor usecase example:
```
<@d_base64><@_runCommand('valid_token_from_HV_extension')>NBFS.exe base64 encode "<@replace('\r\n','')><@replace('"','\\"')>

SOAP XML Message which will be converted to binary (application/soap+msbin1)

<@/replace><@/replace>"<@/_runCommand><@/d_base64>
```

The `runCommand` custom Java tag in HackVertor is:
```
var result = "";

Runtime rt = Runtime.getRuntime();
String[] commands = input.split(" ");
Process proc = rt.exec(input);

BufferedReader stdInput = new BufferedReader(new 
     InputStreamReader(proc.getInputStream()));

BufferedReader stdError = new BufferedReader(new 
     InputStreamReader(proc.getErrorStream()));

// Read the output from the command
String s = null;
while ((s = stdInput.readLine()) != null) {
    if(result.equals("")){
        result = s;
    }else{
        result += "\r\n" + s;
    }
    
}

// Read any errors from the attempted command
System.out.println("Here is the standard error of the command (if any):\n");
while ((s = stdError.readLine()) != null) {
    System.out.println(s);
}

output = result;
```



For any problems, look in stdout (ie. run java -jar burp.jar and look in the console window)

A vulnerable WCF service (and client) has been included to practice. It is vulnerable to SQL injection, and has its own readme. 


Some screenshots:

Changing in repeater:
![alt changing repeater](http://i.imgur.com/Udwd9mk.png)


request/response
![alt req/resp](http://i.imgur.com/ZQa4D6o.png)

flagged in scanner
![alt scanner](http://i.imgur.com/aokg1Gy.png)

SQLMap supported
![alt SQLMap](http://i.imgur.com/5gqSAz5.png)
