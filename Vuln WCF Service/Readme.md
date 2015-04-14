To install this, build and run the service exe as an admin
run burp on localhost:1234 and forward requests towards localhost:8080, just to be awkward.

you should have sql server express set up with the northwind DB running. The 2012 db runs in 2014 fine, and can be downloaded at http://msftdbprodsamples.codeplex.com/ 

all the service is is a sample WCF binary formatted message which selects all names from some northwind table where name equals <input>. it is vulnerable to SQL injection jon' or '1'='1