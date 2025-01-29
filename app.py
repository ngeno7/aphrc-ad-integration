from flask import Flask, jsonify
from ldap3 import Server, Connection, ALL, NTLM
from getpass import getpass

import ldap

app = Flask(__name__)
server = '' # ip address
port = ''
username = ''
password = ''
admindomain = ''
ou = "users"
dc="your_domain,DC=com"
cn = "sAMAccountName"

def connect_to_ad():
    server = Server(f'ldap://{server}:{port}', get_info=ALL)

    conn = Connection(server, user=f'{admindomain}\\{username}', password=password, authentication=NTLM)
    
    if not conn.bind():
        print('Error in connection:', conn.result)
        return None
    print('Connection established successfully')
    return conn

def advanced_ad_query(conn, search_base, search_filter, attributes):
    conn.search(search_base, search_filter, attributes=attributes)

    return conn.entries

@app.route("/")
def active_directory_users():
    conn = connect_to_ad()

    users = advanced_ad_query(conn, f'OU={users},DC={dc}', '(objectClass=user)', ['cn', f'{cn}'])

    return jsonify(users)

@app.route('/login')
def authenticate():
    conn = ldap.initialize('ldap://' + server+':'+port)
    conn.protocol_version = ldap.VERSION3
    conn.set_option(ldap.OPT_REFERRALS, 0)
    try:
        result = conn.simple_bind_s(username, password)
    except ldap.INVALID_CREDENTIALS:
        return "Invalid credentials"
    except ldap.SERVER_DOWN:
        return "Server down"
    except ldap.LDAPError as e:
        if type(e.message) == dict and e.message.has_key('desc'):
            return "Other LDAP error: " + e.message['desc']
        else: 
            return "Other LDAP error: " + e
    finally:
        print(result)
        conn.unbind_s()
    return "Succesfully authenticated"

if __name__ == '__main__':
    app.run(debug=True)