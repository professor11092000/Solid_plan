## X-Frame-Options

It controls whether a browser is allowed to render a page inside an <iframe>, <frame>, <embed>, or <object>.  
It defends against clickjacking; where an attacker overlays an invisible frame of your page over a fake UI to trick users into clickjacking buttons on your site.


### Why it is Used 
- Prevents clickjacking attacks
- Stops UI redress attacks where users are tricked into performing unintended actions.
- Protects authenticated pages (like banking transfers, delete account buttons)

  
**Header Format** :  
```
X-Frame-Options : DENY
X-Frame-Options : SAMEORIGIN
X-Frame-Options : ALLOW_FROM https://trusted.com -> deprecated, not supported by modern browser replace by frame-ancestor.
```

