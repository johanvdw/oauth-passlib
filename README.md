# Oauthv2 provider using kerberos backend

This project is a small Oauthv2 provider using a kerberos backend.
It is based on the original authlib example server that you can find here: https://github.com/authlib/example-oauth2-server .


## development installation

```
sudo apt install libkrb5-dev # required to compile gssapi
pip install -r requirements.txt
```

In development, you probably want to allow insecure transport

```bash
# disable check https (DO NOT SET THIS IN PRODUCTION)
$ export AUTHLIB_INSECURE_TRANSPORT=1
```

Finally run in debug mode (this will give nice error messages and reload when the app code changes)

```bash
$ flask run --debug
```

## settings files
The main settings file `settings.yml` contains the realm against which the server should work, and link to the `users.yml` file and `clients.yml` file

You can specify the location of the settings file by setting the `OAUTH_SETTINGS` environmental variable.

The clients file should contain a friendly name of the application, a client_id and client_secret and rediret_urls:

```
etherpad:
  client_id: 5VU7NWyRdFYRldWDuac8k6eR
  client_secret: "UeS7aDxByNSwIuQ9U7kdSCFBxxzOf6Xbn1yNVLf7gZbp1fnQ"
  token_endpoint_auth_method: "client_secret_basic"
  redirect_uris: ["http://localhost:8000"]
```

The user_info.yml file contains extra info for the users which kerberos will not provide, such as a full_name and group membership.

```
johanvdw:
  full_name: "Johan Van de Wauw"
  groups:
  - nav
  - program
  - website
```

Note that users not present in kerberos but not in the `user_info.yml` file, can still login.

After changes to the files, the service must be restarted (also in dev mode, that only reloads if code changes).

## Test kerberos server

I have used a docker image https://github.com/NORDUnet/krb5-docker for testing:

```
git clone git@github.com:NORDUnet/krb5-docker.git
cd krb5-docker
docker build -f Dockerfile.mit -t krb5-alpine .
podman run --rm -ti -p 127.0.0.1:8888:88 -p 127.0.0.1:7749:749 -v $(pwd)/keytabs:/opt/keytabs -e PRINCIPALS="pwman:pwmantest markus:test" -e REALM=NORDU.NET krb5-alpine
```

Make sure you add NORDU.NET as a realm to your /etc/krb5.conf file:
```
	NORDU.NET = {
	       kdc=localhost:8888
}
```

## a more complete test session:
Note you can set up https://oauth.tools/ for some steps:

Go to:
https://oauth.tools/c/de47032bcdf825a8569b3600#XOXLo14oFjE6MRlrHbviNsjPVm6QbeYT9Ic3Od1u3/Y=

This will launch a call to 

```
http://localhost:5000/oauth/authorize?
&client_id=5VU7NWyRdFYRldWDuac8k6eR
&response_type=code
&redirect_uri=http://localhost:8000
&state=1727628405305-rPu
&scope=profile
```

if not logged in, this will show a login screen where you can login (pwman/pwmantest if using the testserver). If you consent the request, a code is returned. Copy this code and set as an environmental variable, eg:

```bash
export CODE=i5NWNr03Vz6WyGt99sKpk1CM6DWtGnixARM0XmzqqqflAVFQ
export CLIENT=5VU7NWyRdFYRldWDuac8k6eR:UeS7aDxByNSwIuQ9U7kdSCFBxxzOf6Xbn1yNVLf7gZbp1fnQ

curl -u $CLIENT -XPOST http://127.0.0.1:5000/oauth/token -F grant_type=authorization_code -F code=$CODE -F redirect_uri=http://localhost:8000


{"access_token": "JqZmOLbYnel4oWt5aIHAr2nUsQsmbAsGjg15QnUSfF", "expires_in": 864000, "scope": "profile", "token_type": "Bearer"}
```

use this token for requesting info about the user
```bash
curl -H "Authorization: Bearer $TOKEN" http://127.0.0.1:5000/api/me
{
  "extra_info": {
    "full_name": "test other kdc",
    "groups": []
  },
  "username": "pwman"
}
```

