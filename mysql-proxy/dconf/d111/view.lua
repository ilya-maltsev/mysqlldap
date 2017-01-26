id = '1111'
dofile('/mysql-proxy/share_lib.lua')
local_log = '/mysql-proxy/dconf/d'..id..'/local-users-queries.log'
dname = 'mysql-proxy-d'..id

function read_query(packet)
        write_query(packet,local_log,dname)
end

function read_auth_result(auth)
        write_auth_result(auth,local_log,dname)
end

function read_auth()
	return ldap_roles(local_log,dname)
end

