import os
import binascii
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import string

def generate_dsa_key_pairs(num_pairs):
    key_pairs = []
    for i in range(num_pairs):
        key = DSA.generate(1024)
        key_pairs.append(key)
    return key_pairs

def sign_message(private_key, message):
    hashvalue = SHA256.new(message.encode())
    signer = DSS.new(private_key, 'fips-186-3')
    signature = signer.sign(hashvalue)
    return signature

def prompt():
    #Getting user input
    num_signatures = int(input("Enter the number of signatures (M): "))
    num_public_keys = int(input("Enter the number of public keys (N): "))

    #Data validation
    while (num_public_keys < num_signatures):
        num_public_keys = int(input("Enter the number of public keys (N): "))

    #Generate N pairs of DSA 1024-bit public keys/private keys randomly
    key_pairs = generate_dsa_key_pairs(num_public_keys)

    #Generate M DSA signatures using the private keys
    signatures = []
    for i in range(num_signatures):
        signature = sign_message(key_pairs[i], message)
        signatures.append(signature) #adds to list of digital signatures
    
    #Save scriptPubKey to file
    with open("scriptPubKey.txt", "wb") as file:
        file.write(b"OP_" + str(num_signatures).encode() + b" ")
        for public_key in key_pairs:
            public_key_der = public_key.publickey().export_key(format='DER')
            file.write(binascii.hexlify(public_key_der))
            file.write(b" ")  # Add a space delimiter between public keys
        file.write(b"OP_" + str(num_public_keys).encode())
        file.write(b" OP_CHECKMULTISIG")

    #Save scriptSig to file
    with open("scriptSig.txt", "wb") as file:  
        file.write(b"OP_0 ")     #bug feature??
        for signature in signatures:
            file.write(binascii.hexlify(signature))
            file.write(b" ")
        file.close()    

    print("P2MS scriptPubKey and scriptSig generated successfully.")
    
def main():
    prompt()

if __name__ == "__main__":
    message = "CSCI301 Contemporary Topics in Security 2023"
    main()
    	        
