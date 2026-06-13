## X-Content-Type-Options  

It prevent browsers from performing MIME-type sniffing - the behavior where a browser ignores the declared content-type and tries to guess the actual file type. This was designed to help broken servers but creates a serious security hole.   

### Why it is used  
Without this header : A server return a javascript file as Content-Type : text/plain.  Without sniffing protection. IE/Edge used to execute it anyway. Attackers can upload "image" files containing executables Javascript, which gets sniffed and run.


Header Format  
```
X-Content-Type-Options : nosniff
```

Diretives -- 
* nosniff : Only accepted value. Force browser to respect the Content-Type header exactly. Blocks script and stylesheet MIME sniffing. No other values are valid.

What Happens if Missing?  
* No header at all : Old browser (IE, edge legacy) will MIME-sniff and possibly execute uploaded HTML/JS as scripts.
* Wrong value (anything other than nosniff) :: Header is ignored. same as absent.

Attack senario:  
User upload avatar.jpg that contains <script> malicious code <Script>. Server stores and serves it as text/plain but browser sniffs it as text/html and executes. nosniff blocks this because the browser must use Content-Type: text/plain -- not script-executable.


Detection :   
1) curl -I https://example.com | grep -i x-content-type.   
2) Google Lighthouse -- flag missing X-Content-Type-Options.  
3) OWASP ZAP passive scan - detects absence.   
