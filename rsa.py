from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric import utils
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

#generate a private key used by person a and person b
key_a = rsa.generate_private_key(public_exponent=65537,key_size=2048)
key_b = rsa.generate_private_key(public_exponent=65537,key_size=2048)
print("PRIVATE KEY A")
print(key_a.private_bytes(encoding=serialization.Encoding.PEM,format=serialization.PrivateFormat.TraditionalOpenSSL,encryption_algorithm=serialization.NoEncryption()))
print("")

#retrieve public keys which will be used for encryption and verification of messages
public_key_a = key_a.public_key()
print("PRIVATE KEY B")
print(public_key_a.public_bytes(encoding=serialization.Encoding.PEM,format=serialization.PublicFormat.SubjectPublicKeyInfo))
print("")
public_key_b = key_b.public_key()

#create a message that we want to send
message = "this is my secret message"
print("ORIGINAL MESSAGE")
print(message)
print("")

#create a signature for the message using the private key from person a
chosen_hash = hashes.SHA256()
hasher = hashes.Hash(chosen_hash)
hasher.update(bytes(message,"utf-8"))
digest = hasher.finalize()
signature = key_a.sign(digest,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),utils.Prehashed(chosen_hash))
print("SIGNED MESSAGE")
print(signature)
print("")

#create an encrypted message using public key from person b that way only person b can decrypt it with their private key
encrypted_message = public_key_b.encrypt(bytes(message,"utf-8"),padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
print("ENCRYPTED MESSAGE")
print(encrypted_message)
print("")

#Then we would send the encrypted_message and decrypt it with the private key from person b
decrypted_message = key_b.decrypt(encrypted_message,padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()),algorithm=hashes.SHA256(),label=None))
print("DECRYPTED MESSAGE")
print(decrypted_message.decode())
print("")

#Then we verify the signature of the message using the public key of person A
#In the case of this python library the verification function will throw an error if the verification fails
public_key_a.verify(signature,decrypted_message,padding.PSS(mgf=padding.MGF1(hashes.SHA256()),salt_length=padding.PSS.MAX_LENGTH),hashes.SHA256())

#To summarize we encrypted a message with person b's public key that way only their private key can decrypt it. Thus, only the intended recipient, person b,
#can see the message. We then use person a's private key to sign the message before sending it. Only the person a's public key can be used to verify the signature. Thus we can
#use this to verify the message came from person a


