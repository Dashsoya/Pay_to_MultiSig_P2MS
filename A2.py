import os
import binascii
from Crypto.PublicKey import DSA
from Crypto.Signature import DSS
from Crypto.Hash import SHA256
import string

def exemultisig(): #Function called when OP_CHECKMULTISIG is reached
    number_of_pk = int(stack.pop()) #get the number of public key

    pklist = []
    for i in range (number_of_pk):
        pk_der = stack.pop()
        publick_key = DSA.import_key(pk_der)	
        pklist.append(publick_key) #adds public key 1 by 1 to pklist
 
    number_of_sig = int(stack.pop()) #get the number of signatures

    siglist=[]
    for i in range (number_of_sig):
        siglist.append(stack.pop()) #adds signatures 1 by 1 to siglist
     
    verified = 0 
    for i in range (len(siglist)):   #double for loop to test all public 
        for j in range(len(pklist)): #keys against all unverified signatures
            verifier = DSS.new(pklist[j],'fips-186-3') 
            try:
                verifier.verify((SHA256.new(message.encode())),siglist[i])
                verified = verified + 1
                siglist.pop(i) #If verified, remove signature
                print("success")
            except ValueError:
                print("fail")
              
        if verified == number_of_sig: #as long as all signatures are verified it is done
    	    stack.append(True)
    	    break
        else:
    	    stack.append(False)    

def createStack(): #Function to push all elements from scriptSig and scriptPubKey into a stack

    #Read file and remove whitespaces behind
    with open("scriptSig.txt", "rb") as file:
        content = file.read().strip()  
        
    #Split the content by spaces to separate each signature including "OP_0"    
    sigs = content.split()  

    #Ignore the first element "OP_0" and convert the remaining elements back to bytes
    signatures = [binascii.unhexlify(signature) for signature in sigs[1:]]
    
    for signature in signatures:  #adds signature to stack 1 by 1
        stack.append(signature)

    #Read file and remove whitespaces behind
    with open("scriptPubKey.txt", "rb") as file:
        content1 = file.read().strip() 
    
    #Split the content by spaces to separate each signature and "OP_"
    pk = content1.split()
   
    pks = []
    for pubk in pk:
        #Check if the element is a valid hexadecimal value
        if all(c in string.hexdigits for c in pubk.decode()):
            pks.append(binascii.unhexlify(pubk))
        else:
            pks.append(pubk)    

    for pk in pks:
        if b"OP_CHECKMULTISIG" in pk: #if its "OP_CHECKMULTISIG"
            exemultisig()   	      #then execute exemultisig() function
        elif b"OP_" in pk:            #if its "OP_" then ignore the "OP_"
    	    stack.append(pk[3:])      #and just get the integer behind
        else:
    	    stack.append(pk)	      #the rest is just public key and  	append to stack as usual

def main():
    createStack()
    if stack[0] == True:	#if last element in stack is True then 
        print("Verification Success")	#verification success
    else:			#if last element in stack is False then
        print("Verification Fail")  	#verification fail

if __name__ == "__main__":
    message = "CSCI301 Contemporary Topics in Security 2023"
    stack = [] 
    main()
                
                
        
            
            
        
       



