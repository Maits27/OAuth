import requests
import urllib
import webbrowser
import socket
import json


app_key = "s52l0y4vxjn9***"
app_secret ="dzczyhoxo8xtv**"
server_addr ="127.0.0.1"
server_port =8090
redirect_uri = "http://" + server_addr + ":" + str(server_port)
global fitxategi_kop


def local_server():
    print("\n\tStep 4: Handle the OAuth 2.0 server response")
    # https://developers.google.com/identity/protocols/oauth2/native-app#handlingresponse
    # 8090. portuan dagoen zerbitzaria sartu
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.bind(('localhost', 8090))
    server_socket.listen(1)
    print("\t\tSocket listening on port 8090")

    print("\t\tWaiting for client requests...")
    # ondorengo lerroan programa gelditzen da zerbitzariak 302 eskaera jasotzen duen arte
    client_connection, client_address = server_socket.accept()

    # nabitzailetik 302 eskaera jaso
    eskaera = client_connection.recv(1024).decode()
    print("\t\tNabigatzailetik ondorengo eskaera jaso da:")
    print("\n" + eskaera)
    # eskaeran "auth_code"-a bilatu
    # TODO OAUTH TOKEN ERABILTZEN DU ACCESS TOKEN BAT LORTZEKO ERABILTZEN DA
    lehenengo_lerroa = eskaera.split('\n')[0]
    aux_auth_code = lehenengo_lerroa.split(' ')[1]
    auth_code = aux_auth_code[7:].split('&')[0]
    print("auth_code: " + auth_code)


    ############################################################################################
    # erabiltzaileari erantzun bat bueltatu
    http_response = """\
    HTTP/1.1 200 OK

    <html>
    <head><title>Proba</title></head>
    <body>
    The authentication flow has completed. Close this window.
    </body>
    </html>
    """

    client_connection.sendall(str.encode(http_response))
    client_connection.close()
    server_socket.close()

    ############################################################################################
    return auth_code

def do_oauth():
    print("\nObtaining OAuth  access tokens")
    # Authorization
    print("\tStep 2: Send a request to Google's OAuth 2.0 server")
    base_uri = 'https://www.dropbox.com/oauth2/authorize'
    goiburuak = {'Host': 'www.dropbox.com'}
    datuak = {'response_type': 'code',
              'client_id': app_key,
              'redirect_uri': 'http://127.0.0.1:8090',
              'scope': 'files.content.read'}
    datuak_kodifikatuta = urllib.parse.urlencode(datuak)
    step2_uri = base_uri + '?' + datuak_kodifikatuta
    print("\t" + step2_uri)
    webbrowser.open_new(step2_uri)

    ###############################################################################################################

    print("\n\tStep 3: DropBox prompts user for consent")

    auth_code = local_server()

    ###############################################################################################################
    # Exchange authorization code for access token
    print("\n\tStep 5: Exchange authorization code for refresh and access tokens")

    uri = 'https://api.dropboxapi.com/oauth2/token'
    goiburuak = {'Host': 'oauth2.googleapis.com',
                 'Content-Type': 'application/x-www-form-urlencoded'}
    datuak = {'code': auth_code,
              'grant_type': 'authorization_code',
              'redirect_uri': 'http://127.0.0.1:8090',
              'client_id': app_key,
              'client_secret': app_secret}
    datuak_kodifikatuta = urllib.parse.urlencode(datuak)
    goiburuak['Content-Length'] = str(len(datuak_kodifikatuta))
    erantzuna = requests.post(uri, data=datuak, allow_redirects=False)
    status = erantzuna.status_code
    print(status)
    # Google responds to this request by returning a JSON object
    # that contains a short-lived access token and a refresh token.

    edukia = erantzuna.content
    print("\nEdukia\n")
    print(edukia)
    edukia_json = json.loads(edukia)
    access_token = edukia_json['access_token']
    print("\nAccess token: " + access_token)

    return access_token


def list_folder(access_token, cursor="", edukia_json_entries=[]):
    global fitxategi_kop
    print('Cursor: '+cursor)
    if not cursor:
        print("/list_folder")
        uri ='https://api.dropboxapi.com/2/files/list_folder'
        datuak ={'path': '', 'recursive': True}

    else:
        print("/list_folder/continue")
        uri ='https://api.dropboxapi.com/2/files/list_folder/continue'
        datuak ={'cursor': cursor}


    # Call Dropbox API
    goiburuak = {'Host': 'api.dropboxapi.com', 'Authorization': 'Bearer ' + access_token, 'Content-Type': 'application/json'}
    datuak_json=json.dumps(datuak) #TODO en la eskaera hay que mandar un JSON asi que hay que pasar los datos de hiztegi de python a JSON
    erantzuna = requests.post(uri, headers=goiburuak, data=datuak_json, allow_redirects=False)
    print(erantzuna.status_code)
    print("\nErantzuna\n")
    edukia = erantzuna.content
    print(edukia)


    # See if there are more entries available. Process data.
    edukia_json = json.loads(edukia)
    print('###############################################################################')
    print('\n FITXATEGIAK INPRIMATUKO DIRA')
    print('###############################################################################')
    for entry in edukia_json['entries']:
        fitxategi_kop=fitxategi_kop+1
        name= entry['name']
        print(str(fitxategi_kop) + '. fitxategia ------>  ' + name)
    if edukia_json['has_more']:
        list_folder(access_token, edukia_json['cursor'])
        # sartu kodea hemen


access_token = do_oauth()
input("The authentication flow has completed. Close browser window and press enter to continue...")
print("\nCalling Dropbox APIs")
fitxategi_kop=0
list_folder(access_token)


