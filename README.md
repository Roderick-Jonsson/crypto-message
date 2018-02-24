
<h1 align="center">
  <br>
  <img align="center"
     title="Size Limit logo" src="./crypto-message-logo.png">

</h1>


     
<p align="center">
<b>Encrypts and decrypts text with your ssh generated public private key's</b>
</p> 
<p align="center">
  Project state: Fun mode
</p>
<p align="center">
  <a href="#prerequisites">Prerequisites</a> •
  <a href="#encrypt-a-message">Encrypt a message</a> •
  <a href="#decrypt-a-message">Decrypt a message</a> •
  <a href="#contribute">Contribute</a>
</p>

# Prerequisites

To work, this script will need following python libraries

- cement
  - Advanced CLI Application Framework for Python
- cryptography
  - Provides cryptographic recipes and primitives to Python developers

Install prerequisites

~~~
pip install cement
pip install cryptography
~~~

# Encrypt a message

This will encrypt the string "This is top ssecret information nobody should be able to read" to a file secretmessage.txt by using the the public key "public-key"

~~~
python3.6 crypto-message.py -i /path/to/public-key /path/to/secretmessage.txt This is top secret information nobody should be able to read
~~~

# Decrypt a message

This will decrypt the file secretmessage.txt by using the private key "private-key"

~~~
python3.6 crypto-message.py -d /path/to/private-key /path/to/secretmessage.txt 
~~~

# Contribute

Heck yeah! :)
