temp_log = '/var/log/mysql-proxy-temp'
remote_log = '/var/log/mysql-proxy/users-queries.log'
lost_log = '/var/log/mysql-proxy/lost-users-queries.log'

local function ldap_filter_escape(s) return (s:gsub("[\\*\\(\\)\\\\%z]", function(c) return ("\\%02x"):format(c:byte()) end)); end

local b='ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/'

local ldap_slave={'ldap-slave3.local','ldap-slave2.local','ldap-slave1.local','ldap-master.local'}

local priv_users = {"{exclude_user}"}

function write_query(local_packet,l_log,name)
	local ctime = os.date('%Y-%m-%d %H:%M:%S')
	local ip_dst = proxy.global.backends[proxy.connection.backend_ndx].dst["address"]
	local ip_src = proxy.connection.client.src["address"]
	local user = proxy.connection.client["username"]
	if string.byte(local_packet) == proxy.COM_QUERY then
		str = string.sub(local_packet, 2)
		str = magic_quotes(str)
		local file = io.open(temp_log, "a")
		file:write('mysql-proxy: ', ctime, ' ', ip_dst, ' ', ip_src, ' ', user, ' ', str .. "\n")
		file:close()
	end
end

function write_auth_result(auth,l_log,name)
	local ctime = os.date('%Y-%m-%d %H:%M:%S')
	local ip_dst = proxy.global.backends[proxy.connection.backend_ndx].dst["address"]
	local ip_src = proxy.connection.client.src["address"]
	local user = proxy.connection.client["username"]
	local state = auth.packet:byte()
	if state == proxy.MYSQLD_PACKET_ERR then
		local file = io.open(temp_log, "a")
		file:write('mysql-proxy: ', ctime, ' ', ip_dst, ' ', ip_src, ' ', user, ' ', "auth_failed" .. "\n")
		file:close()
	end
end

function magic_quotes(data)
	data = string.gsub(data, "\a", "")
	data = string.gsub(data, "\b", "")
	data = string.gsub(data, "\f", "")
	data = string.gsub(data, "\n", "")
	data = string.gsub(data, "\r", "")
	data = string.gsub(data, "\t", "")
	data = string.gsub(data, "\v", "^")
	data = string.gsub(data, "\\", "^")
	data = string.gsub(data, "\"", "^")
	data = string.gsub(data, "\'", "^")
	data = string.gsub(data, "\`", "^")
	clear_data = data
	return clear_data
end


function ascii_to_num(c)
    if (c >= string.byte("0") and c <= string.byte("9")) then
        return c - string.byte("0")
    elseif (c >= string.byte("A") and c <= string.byte("F")) then
        return (c - string.byte("A"))+10
    elseif (c >= string.byte("a") and c <= string.byte("f")) then
        return (c - string.byte("a"))+10
    else
        error "Wrong input for ascii to num convertion."
    end
end

function hex(s)
    local i
    local h = ""

    for i = 1, #s do
        h = h .. string.format("%02x",string.byte(s,i))
    end
    return h
end


function unhex(h)
    local i
    local s = ""
    for i = 1, #h, 2 do
        high = ascii_to_num(string.byte(h,i))
        low = ascii_to_num(string.byte(h,i+1))
        s = s .. string.char((high*16)+low)
    end
    return s
end

--mysql ldap account read attribute
local function ldap_connect()
        for i=1, #ldap_slave do
                local port_check=os.execute("nc -w 1 -z " .. ldap_slave[i] .. " {ldap_port}")
                if port_check == 0 then
                        ld = lualdap.open_simple(ldap_slave[i],"uid=Administrator,cn=users,dc=domain,dc=local","{ldap_connect_user_passwd}",true) 
                        
                        return ld
                end
        end
        return false

end

function find_userdn(username, ld)
        local iter = ld:search {
                base = "cn=users,dc=domain,dc=local";
                scope = "onelevel";
                filter = "(uid="..ldap_filter_escape(username)..")";
        }
        for dn, attribs in iter do
                   return dn;
        end
        return false
end

function find_passdn(username, ld)
        local iter = ld:search {
                base = "cn=users,dc=domain,dc=local";
                scope = "onelevel";
                filter = "(uid="..ldap_filter_escape(username)..")";
        }
        for dn, attribs in iter do
                for name, values in pairs(attribs) do
                        if name == "sambaNTPassword" then
                                return values;
                        end

                end
        end
        return false
end

function find_role(ld,ip_dst,username)
        local iter = ld:search {
                base = "cn=groups,dc=domain,dc=local";
                scope = "onelevel";
                filter = "(&(memberUid="..username..")(description="..ip_dst.."))"
        }
        for dn, attribs in iter do
                for name, values in pairs(attribs) do
                        if name == "cn" then 
                                if string.sub(values,0,6) == "sql_w_" then
                                        return "write" 
                                elseif string.sub(values,0,6) == "sql_r_" then
                                        return "read" end
                        end     
                end
        end
        return false
end

function ldap_roles(l_log,name)
	local roles = {
                ["read"] = {
                        user = "rbac_read",
                        password = "0b1fc363d1e0c50b1d45c02d791f7bc2c7b47615"}, -- password_hash_example
                ["write"] = {
                        user = "rbac_write",
                        password = "cbd069e50a464b5e8075a646d80e2f1b645e321e"} -- password_hash_example
        }
        local lua = assert(require "lualdap")
        local password = assert(require("mysql.password"))
        local proto = assert(require("mysql.proto"))
        local CLIENT_PROTOCOL_41       = 512    -- New 4.1 protocol
        local CLIENT_SECURE_CONNECTION = 32768  -- New 4.1 authentication
        local MYSQL_AUTH_CAPABILITIES  = ( CLIENT_PROTOCOL_41 + CLIENT_SECURE_CONNECTION )
        local c = proxy.connection.client
        local s = proxy.connection.server
        local file = io.open(temp_log, "a")
        local ctime = os.date('%Y-%m-%d %H:%M:%S')
        ip_dst = proxy.global.backends[proxy.connection.backend_ndx].dst["address"]
        local ip_src = proxy.connection.client.src["address"]

        for i=1, #priv_users do         
                if c.username == priv_users[i] then
                        return proxy.PROXY_SEND_QUERY
                end
        end
       	 
        ld = ldap_connect()
	if not ld then
                file:write('mysql-proxy: ', ctime, ' ', ip_dst, ' ', ip_src, ' ', 'Cant connect to LDAP server'.."\n")
                file:close()
                return false; 
        end

        local ldap_user = find_userdn(c.username, ld)   
        if not ldap_user then
                file = io.open(temp_log, "a")
                ld:close()
		file:write('mysql-proxy: ', ctime, ' ', ip_dst, ' ', ip_src, ' ', 'User '.. c.username ..' not found in LDAP'.."\n")
                file:close()
--                return false; 
		proxy.response.type = proxy.MYSQLD_PACKET_ERR
                proxy.response.errmsg = "This account not found in LDAP"
                return proxy.PROXY_SEND_RESULT
        end
        
        local ldap_password=find_passdn(c.username,ld)
                if password.check(
                        s.scramble_buffer:sub(1,20),
                        c.scrambled_password,
                        unhex(ldap_password))
                then 
                        local mysql_role=roles[find_role(ld,ip_dst,c.username)]
                        ld:close()
                        if not mysql_role then
                                file = io.open(temp_log, "a")
                                file:write('mysql-proxy: ', ctime, ' ', ip_dst, ' ', ip_src, ' ', 'Role for ' .. c.username .. ' not found'.."\n")
                                file:close()
                                return false; 
                        end
                        proxy.queries:append(1,
                                proto.to_response_packet({
                                username = mysql_role.user,
                                response = password.scramble((s.scramble_buffer):sub(1,20), unhex(mysql_role.password)),
                                charset  = 8, -- default charset
                                database = c.default_db,
                                max_packet_size = 1 * 1024 * 1024,
                                server_capabilities = MYSQL_AUTH_CAPABILITIES
                                }))
                        file = io.open(temp_log, "a")
                        file:write('mysql-proxy: ', ctime, ' ', ip_dst, ' ', ip_src, ' ', c.username, ' ', "logged as " .. mysql_role.user .. "\n")
                        file:close()
                        return proxy.PROXY_SEND_QUERY;
                end
                ld:close()
                file = io.open(temp_log, "a")
                file:write('mysql-proxy: ', ctime, ' ', ip_dst, ' ', ip_src, ' ', 'Password for ' .. c.username .. ' is wrong'.."\n")
                file:close()
                return false;

end
