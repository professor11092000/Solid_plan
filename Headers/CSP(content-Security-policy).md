## CSP (Content Security policy)

CSP allows server-side control of which resources (script, styles, images, fonts, frames etc) the browsers is allowed to load and execute. It is the primary defense against XSS and data injection attacks.  

### Why it is used  
1) Prevent execution of Injected scripts.
2) Restrict which domains can serve resources.
3) Blocks inline scripts/style execution unless explicitly allowed.
4) Controls framing behavior (replaces X-Frame-options)
5) Prevents protocol downgrade attacks.


### Header format  
```
Content-Security-Policy: directive1 value1 value2; directive2 value1; directive3
```

All directive --   
* default-src : Fallback for all fetch directive not explicitly set. Acts as a catch-all policy.    
* script-src : Controls which script can execute. Most critical directive.  
* Style-src : Controls which stylesheets can be applied.   
* img-src : controls which image can be loaded    
* font-src : Controls where fonts can be loaded from   
* frame-src : Controls which origins can be embedded in <frame> and <iframe>  
* frame-ancestors : controls which pages can embed This page in an iframe. Supersedes X-Frame-Options.  
and many more

Source Value Keyword  --  
* `none` : Block everything from this directive. Most restrictive.
* `self` : Allow only same origin (same scheme + host + port)
* `unsafe-inline` : Allow inline scripts/styles. DANGEROUS. Weakens XSS protection significantly.
* `unsafe-eval` : Allow eval(), new Function(), setTimeout(String). DANGEROUS
* `strict-dynamic` :Trust the script that are explicitly allowed by nonce/hash,, even if they load other scripts. Ignores whitelist.
* `unsafe-hashes`: Allow specific inline event handler hashes. Partial unsafe-inline replacement.
* `nonce-<base64> : Allow a specific script/style with matching nonce attribute. Rotate every request.
* `sha256-<hash> : Allow a script/style matching the SHA-256 hash of its content.





