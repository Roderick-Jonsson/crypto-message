#!/usr/bin/env python3
# Cement library http://cement.readthedocs.io
from cement.core.foundation import CementApp
from cement.core.controller import CementBaseController, expose

# cryptography Library https://cryptography.io/en/latest/
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
from cryptography.hazmat.primitives import serialization

class CryptoMessageController(CementBaseController):
    class Meta:
        label = 'base'
        description = "Crypto Message encrypts and decrypts messages with ssh public private keys"
        arguments = [
            ( ['-i', '--inpubkey'],
              dict(action='store', help='Encrypt message with public key') ),
            (['-d', '--inprivkey'],
             dict(action='store', help='Decrypt message with private key')),
            (['extra_arguments'],
             dict(action='store', nargs='*', help='When encrypting it is output file path + text when decrypting it is cipher file path'))
            ]

    @expose(hide=True)
    def default(self):
        if self.app.pargs.inpubkey:
            if len(self.app.pargs.extra_arguments) > 0:
                publicKeyPem = self.app.pargs.inpubkey
                outputPath = self.app.pargs.extra_arguments[0]
                message = ' '.join(self.app.pargs.extra_arguments[1:])
                self.encryptMessage(publicKeyPem,outputPath,message)
            else:
                print("Misssing arguments")
                print("Ex: cmd.py -i <PATH:public key> <PATH:output file> $TEXT")
        elif self.app.pargs.inprivkey:
            if len(self.app.pargs.extra_arguments) > 0:
                privateKeyPath = self.app.pargs.inprivkey
                cipherFilePath = self.app.pargs.extra_arguments[0]
                self.decryptMessage(privateKeyPath,cipherFilePath)
            else:
                print("Missing arguments")
                print("Ex: cmd.py -d <PATH:private key> <PATH:cipher file>")

    def encryptMessage(self,publicKeyPem,outputPath,message):
        # Load public ssh key
        with open(publicKeyPem, "rb") as key_file:
            public_key = serialization.load_ssh_public_key(
                key_file.read(),
                backend=default_backend()
            )

        # Create cipher text (byte type) with public key and from variable message which is byte encoded
        ciphertext = public_key.encrypt(
            message.encode(),
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        )

        # Write byte encoded text to file path from variable ciphertext
        f = open(outputPath,"wb")
        f.write(ciphertext)
        f.close()

    def decryptMessage(self,privateKeyPath,cipherFilePath):
        # Load private key (though ssh generated it is already in the right format) in byte format
        with open(privateKeyPath, "rb") as key_file:
            private_key = serialization.load_pem_private_key(
                key_file.read(),
                password=None,
                backend=default_backend()
            )

        # Load cipher file with encrypted message into variable ciphertext (byte type)
        cipherfileHandle = open(cipherFilePath,"rb")
        ciphertext = cipherfileHandle.read()

        # Decrypt cipher byte text and decode to utf-8 into plaintext variable
        plaintext = private_key.decrypt(
            ciphertext,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA1()),
                algorithm=hashes.SHA1(),
                label=None
            )
        ).decode("utf-8")

        # output encrypted plaintext
        print(plaintext)



class cryptoMessage(CementApp):
    class Meta:
        label = 'cryptomessage'
        base_controller = 'base'
        handlers = [CryptoMessageController]

with cryptoMessage() as app:
    app.run()
