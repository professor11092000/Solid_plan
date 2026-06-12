## HTTP Strict Transport Security (HSTS)


HSTS Header has 3 directive:  
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
HSTS header enforce browser to make https:// request. server send the HSTS header and browser remember to make further request and enforce any http:// request to https:// by following set of rule :  

  
### 1. HSTS with Preload

Let's say HSTS is configured correctly with the "preload" directive and the domain is included in the browser's HSTS preload list. If a user types "http://example.com", the browser will automatically convert it to "https://example.com" before making any network request.

No HTTP request reaches the server and no redirect is needed. This protects even the very first visit from downgrade attacks.

The "preload" directive itself does not enforce anything. It is only a signal that the site wants to be included in the browser vendors' HSTS preload list. The actual enforcement comes from the browser's built-in preload database.

### 2. HSTS without Preload

If HSTS is configured but the domain is not preloaded, then on the first visit when a user types "http://example.com", the browser does not yet know that the site requires HTTPS.

The HTTP request is sent to the server, which typically responds with a redirect to "https://example.com". Once the HTTPS connection is established, the server sends the "Strict-Transport-Security" header containing the "max-age" value. The browser stores this policy for the specified duration.

From the second visit onward (while the HSTS policy is still valid), if the user types "http://example.com", the browser automatically upgrades the request to "https://example.com" before sending any request. No HTTP request is sent and no redirect is required because the browser already remembers the HSTS policy.

### 3. includeSubDomains

The directive name is "includeSubDomains".

When "includeSubDomains" is configured on "example.com", the HSTS policy applies not only to the main domain but also to all its subdomains such as "abc.example.com", "xyz.example.com", and "api.example.com".

After the browser learns the HSTS policy, if a user types "http://abc.example.com" or any other subdomain, the browser automatically upgrades the request to HTTPS before sending it. This ensures that all subdomains are forced to use secure HTTPS connections and cannot be accessed over HTTP.



--- 
One important interview point:
Preload = protects the first visit.
HSTS without preload = protects only after the browser has seen the HSTS header at least once.
---



HSTS Header in Response Example:

```
HTTP/1.1 200 OK
Content-Type: text/html
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
or after a redirect:
```
HTTP/1.1 301 Moved Permanently
Location: https://example.com
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
When the browser receives:
```
Strict-Transport-Security: max-age=31536000; includeSubDomains; preload
```
it stores the HSTS policy for 31,536,000 seconds (1 year).
After that, whenever the user tries to visit: http://example.com
the browser upgrades it to: https://example.com
before sending the request (assuming the policy is still valid).

