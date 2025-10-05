# pkt-cert
ACME certificate requestor for PKT domains.

## How to use
1. Generate a config file `pkt-cert --genconf` - this will by default be placed in `/etc/pkt-cert`.
If you want it elsewhere, you can specify with the `--path` flag.

2. By default, this will bind `127.0.0.1:9987` for it's http server, if this doesn't work for you,
then edit the config file to change it.

3. Create a file called `default.conf` in your nginx conf directory which proxies
`/.well-known/acme-challenge` to 9987 (or whatever port you chose). If you are also using `certbot`
this should be okay because it uses a config specific to a particular domain (be sure to test anyway).

4. Check that your DNS (in the PKT dashboard) is pointing to your server.

5. Run `pkt-cert --add <your name>.pkt` to acquire your first certificate.

6. Use the include file in `/etc/pkt-cert/<your name>.pkt.nginx.inc` to include your server_name and
certificate lines.

7. Add a cronjob as follows: `3 0 * * * pkt-cert --check --reload-command 'service nginx reload'`


## Nginx default.conf

```nginx
server {
    listen 80 default_server;
    listen [::]:80 default_server;
    server_name _;
 
    location /.well-known/acme-challenge {
        proxy_pass http://127.0.0.1:9987;
    }
}
```

## Nginx example config

```nginx
server {
    listen 443 ssl;
    listen [::]:443 ssl;
    include /etc/pkt-cert/YOUR_PKT_DOMAIN.pkt.nginx.inc; ## Edit this
    ssl_dhparam /etc/nginx/dhparam.pem;
    ssl_protocols TLSv1.2;
    ssl_ciphers EECDH+AESGCM:EDH+AESGCM;
    ssl_ecdh_curve secp384r1;
    
    location / {
        return 404;
    }
}
```