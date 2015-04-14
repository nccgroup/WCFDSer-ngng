#BurpJDSer-ng



A Burp Extender plugin, that will make binary soap objects readable and modifiable. Based on the original work of Brian Holyfield, all hail Brian http://blog.gdssecurity.com/labs/2009/11/19/wcf-binary-soap-plug-in-for-burp.html

Why? This release fixes a bug where serialization wasn't being performed properly. It also adds in the (proper) ability to use the scanner/intrude in conjunction with WCF. It also works with SQLMap if you right click -> send deserialized to intruder, and then copy/paste that into a file, then run sqlmap -r file.txt with the --proxy option. 

Basically, it will deserialize, modify, reserialize, send on and (only in the case of the scanner) deserialize any responses that look like WCF objects (to allow burp to flag any exception strings, etc.).

nb. that it does make use of the "Via" header to allow it to mark requests that need serialization (and let it pass properly formatted http checks in sqlmap). If you need the via header for something, you're going to have to use something else, change the SERIALIZEHEADER in the utils file and recompile.

Usage:
	Place the NBFS.exe wherever you run burp.
	For any problems, look in stdout (ie. run java -jar burp.jar and look in the console window)


I've also included a vulnerable WCF service (and client) as there don't seem to be any around. It is vulnerable to SQL injection, and has its own readme. 
	
cheers


Some screenshots:

Changing in repeater:
![alt changing repeater](http://i.imgur.com/Udwd9mk.png)


request/response
![alt req/resp](http://i.imgur.com/ZQa4D6o.png)

flagged in scanner
![alt scanner](http://i.imgur.com/aokg1Gy.png)

SQLMap supported
![alt SQLMap](http://i.imgur.com/5gqSAz5.png)
