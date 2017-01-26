# MySQL Proxy's configuration file (mysql-proxy.cnf)
 
[mysql-proxy]
daemon = true
keepalive = true
plugins = proxy
pid-file = /mysql-proxy/dconf/d{id}/mysql-proxy.pid
log-file = /var/log/mysql-proxy/mysql-proxy-d{id}.log
log-level = message
proxy-address = {listen_mysql-proxy_ip}:{listen_mysql-proxy_port}
proxy-backend-addresses = {forward_mysql-db_ip}:{forward_mysql-db_port}
proxy-lua-script = /mysql-proxy/dconf/d{id}/view.lua
