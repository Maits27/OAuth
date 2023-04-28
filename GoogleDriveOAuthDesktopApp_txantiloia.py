import requests
import urllib
import webbrowser
import socket
import json


print("###################################")
print("OAuth 2.0 for Mobile & Desktop Apps")
print("###################################")
# https://developers.google.com/identity/protocols/oauth2/native-app

print("\nPrerequisites on Google Cloud Console")
# https://developers.google.com/identity/protocols/oauth2/native-app#prerequisites

print("\tEnable APIs for your project")
# https://developers.google.com/identity/protocols/oauth2/native-app#enable-apis

print("\tIdentify access scopes")
# https://developers.google.com/identity/protocols/oauth2/native-app#identify-access-scopes
scope = "https://www.googleapis.com/auth/drive.readonly" # See and download all your Google Drive files

print("\tCreate authorization credentials")
# https://developers.google.com/identity/protocols/oauth2/native-app#creatingcred
client_id = "836557562780-k0sem43mbsahu8qugo4edc6790j6nsn5.apps.googleusercontent.com"
client_secret = "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"

print("\tConfigure OAuth consent screen")
print("\t\tAdd access scopes and test users")



#TODO AUTENTIKAZIO ETA BAIMENTZE

print("\nObtaining OAuth 2.0 access tokens")
# https://developers.google.com/identity/protocols/oauth2/native-app#obtainingaccesstokens
print("\tStep 2: Send a request to Google's OAuth 2.0 server")
# https://developers.google.com/identity/protocols/oauth2/native-app#step-2:-send-a-request-to-googles-oauth-2.0-server
base_uri = 'https://accounts.google.com/o/oauth2/v2/auth'
goiburuak = {'Host': 'accounts.google.com'}
datuak = {'client_id': client_id,
          'redirect_uri': 'http://127.0.0.1:8090',
          'response_type': 'code',
          'scope': scope}
datuak_kodifikatuta = urllib.parse.urlencode(datuak)
step2_uri = base_uri + '?' + datuak_kodifikatuta
print("\t" + step2_uri)
webbrowser.open_new(step2_uri)

print("\n\tStep 3: Google prompts user for consent")


print("\n\tStep 4: Handle the OAuth 2.0 server response")
# https://developers.google.com/identity/protocols/oauth2/native-app#handlingresponse
#8090. portuan dagoen zerbitzaria sartu
server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
server_socket.bind(('localhost', 8090))
server_socket.listen(1)
print("\t\tSocket listening on port 8090")

print("\t\tWaiting for client requests...")
# ondorengo lerroan programa gelditzen da zerbitzariak 302 eskaera jasotzen duen arte
client_connection, client_address=server_socket.accept()

# nabitzailetik 302 eskaera jaso
eskaera = client_connection.recv(1024).decode()
print("\t\tNabigatzailetik ondorengo eskaera jaso da:")
print("\n"+eskaera)
# eskaeran "auth_code"-a bilatu
#TODO OAUTH TOKEN ERABILTZEN DU ACCESS TOKEN BAT LORTZEKO ERABILTZEN DA
lehenengo_lerroa = eskaera.split('\n')[0]
aux_auth_code = lehenengo_lerroa.split(' ')[1]
auth_code = aux_auth_code[7:].split('&')[0]
print("auth_code: " + auth_code)

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


print("\n\tStep 5: Exchange authorization code for refresh and access tokens")
# https://developers.google.com/identity/protocols/oauth2/native-app#exchange-authorization-code

uri = 'https://oauth2.googleapis.com/token'
goiburuak = {'Host': 'oauth2.googleapis.com',
            'Content-Type': 'application/x-www-form-urlencoded'}
datuak = {'client_id': client_id,
          'client_secret': client_secret,
          'code': auth_code,
          'grant_type': 'authorization_code',
          'redirect_uri': 'http://127.0.0.1:8090'}
datuak_kodifikatuta = urllib.parse.urlencode(datuak)
goiburuak['Content-Length'] = str(len(datuak_kodifikatuta))
erantzuna = requests.post(uri, headers=goiburuak, data=datuak_kodifikatuta, allow_redirects=False)
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


input("The authentication flow has completed. Close browser window and press enter to continue...")


print("\nCalling Google APIs")
# https://developers.google.com/identity/protocols/oauth2/native-app#callinganapi
# Drive API --> Files --> list --> https://developers.google.com/drive/api/v3/reference/files/list

uri = 'https://www.googleapis.com/drive/v3/files'
goiburuak = {'Host': 'www.googleapis.com', 'Authorization': 'Bearer '+access_token}
datuak = {}
datuak_kodifikatuta = urllib.parse.urlencode(datuak)
erantzuna = requests.get(uri, headers=goiburuak, allow_redirects=False)

status = erantzuna.status_code
print(status)
edukia = erantzuna.text
print("\nEdukia\n")
print(edukia)
edukia_json = json.loads(edukia)

if 'nextPageToken' in edukia_json:
    uri = 'https://www.googleapis.com/drive/v3/files'
    goiburuak = {'Host': 'www.googleapis.com', 'Authorization': 'Bearer ' + access_token}
    datuak = {'pageToken': edukia_json['nextPageToken']}
    datuak_kodifikatuta = urllib.parse.urlencode(datuak)
    erantzuna = requests.get(uri+'?'+datuak_kodifikatuta, headers=goiburuak, allow_redirects=False)

    status = erantzuna.status_code
    print(status)
    edukia = erantzuna.text
    print("\nEdukia\n")
    print(edukia)
