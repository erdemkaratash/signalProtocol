import math
import time
import random
import sympy
import warnings
from random import randint, seed
import sys
from ecpy.curves import Curve, Point
from Crypto.Hash import SHA3_256, HMAC, SHA256
import requests
from Crypto.Cipher import AES
from Crypto import Random
from Crypto.Util.Padding import pad
from Crypto.Util.Padding import unpad
import random
import re
import json

import os

API_URL = 'http://10.92.52.255:5000/'

stuID = 28175


def egcd(a, b):
    x, y, u, v = 0, 1, 1, 0
    while a != 0:
        q, r = b//a, b % a
        m, n = x-u*q, y-v*q
        b, a, x, y, u, v = a, r, u, v, m, n
    gcd = b
    return gcd, x, y


def modinv(a, m):
    gcd, x, y = egcd(a, m)
    if gcd != 1:
        return None  # modular inverse does not exist
    else:
        return x % m


def Setup():
    global E
    E = Curve.get_curve('secp256k1')
    return E


# //ephemeral key generation
def KeyGen(E):
    n = E.order
    P = E.generator
    sA = randint(1, n-1)
    QA = sA*P
    return sA, QA


def SignGen(message, E, sA):
    n = E.order
    P = E.generator
    k = randint(1, n-2)
    R = k*P
    r = R.x % n
    h = int.from_bytes(SHA3_256.new(r.to_bytes(
        (r.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big') % n
    s = (sA*h + k) % n
    return h, s


def SignVer(message, h, s, E, QA):
    n = E.order
    P = E.generator
    V = s*P - h*QA
    v = V.x % n
    h_ = int.from_bytes(SHA3_256.new(v.to_bytes(
        (v.bit_length()+7)//8, byteorder='big')+message).digest(), byteorder='big') % n
    if h_ == h:
        return True
    else:
        return False




def IKRegReq(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'IKPUB.X': x, 'IKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegReq"), json=mes)
    if ((response.ok) == False):
        print(response.json())


def IKRegVerify(code):
    mes = {'ID': stuID, 'CODE': code}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "IKRegVerif"), json=mes)
    if ((response.ok) == False):
        raise Exception(response.json())
    print(response.json())


def SPKReg(h, s, x, y):
    mes = {'ID': stuID, 'H': h, 'S': s, 'SPKPUB.X': x, 'SPKPUB.Y': y}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SPKReg"), json=mes)
    if (response.ok == False):
        print(response.json())
    else:
        res = response.json()
        return res['SPKPUB.X'], res['SPKPUB.Y'], res['H'], res['S']


def OTKReg(keyID, x, y, hmac):
    mes = {'ID': stuID, 'KEYID': keyID,
           'OTKI.X': x, 'OTKI.Y': y, 'HMACI': hmac}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "OTKReg"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetIK(rcode):
    mes = {'ID': stuID, 'RCODE': rcode}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetIK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetSPK(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetSPK"), json=mes)
    print(response.json())
    if ((response.ok) == False):
        return False
    else:
        return True


def ResetOTK(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.delete('{}/{}'.format(API_URL, "ResetOTK"), json=mes)
    print(response.json())


def PseudoSendMsgPH3(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.put(
        '{}/{}'.format(API_URL, "PseudoSendMsgPH3"), json=mes)
    print(response.json())


def ReqMsg(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqMsg"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        #return res["IDB"], res["OTKID"], res["MSGID"], res["MSG"], res["EK.X"], res["EK.Y"]
        return res



def ReqDelMsg(h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "ReqDelMsgs"), json=mes)
    print(response.json())
    if ((response.ok) == True):
        res = response.json()
        return res["MSGID"]


def Checker(stuID, stuIDB, msgID, decmsg):
    mes = {'IDA': stuID, 'IDB': stuIDB, 'MSGID': msgID, 'DECMSG': decmsg}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "Checker"), json=mes)
    print(response.json())


def SendMsg(idA, idB, otkID, msgid, msg, ekx, eky):
    mes = {"IDA": idA, "IDB": idB, "OTKID": int(
        otkID), "MSGID": msgid, "MSG": msg, "EK.X": ekx, "EK.Y": eky}
    print("Sending message is: ", mes)
    response = requests.put('{}/{}'.format(API_URL, "SendMSG"), json=mes)
    print(response.json())


def reqOTKB(stuID, stuIDB, h, s):
    OTK_request_msg = {'IDA': stuID, 'IDB': stuIDB, 'S': s, 'H': h}
    print("Requesting party B's OTK ...")
    response = requests.get(
        '{}/{}'.format(API_URL, "ReqOTK"), json=OTK_request_msg)
    print(response.json())
    if ((response.ok) == True):
        print(response.json())
        res = response.json()
        return res['KEYID'], res['OTK.X'], res['OTK.Y']

    else:
        return -1, 0, 0


def Status(stuID, h, s):
    mes = {'ID': stuID, 'H': h, 'S': s}
    print("Sending message is: ", mes)
    response = requests.get('{}/{}'.format(API_URL, "Status"), json=mes)
    print(response.json())
    if (response.ok == True):
        res = response.json()
        return res['numMSG'], res['numOTK'], res['StatusMSG']


E = Curve.get_curve('secp256k1')
n = E.order
p = E.field
P = E.generator
a = E.a
b = E.b


IKey_Sec = 78578733693645789122690162523565083783325290442976549549151847529009528396144
IKey_Pub = IKey_Sec * P


def randomGen(modulus):  # Returns randomly generated cyptographically secure number
    k = Random.new().read(int(math.log(modulus, 2)))
    k = int.from_bytes(k, byteorder='big') % modulus
    return k


def signature_generation(m, sA=IKey_Sec, P=P, n=n):
    k = randomGen(n)

    R = (k * P)

    r = R.x % n

    r = r.to_bytes(length=(r.bit_length()+7)//8, byteorder='big')
    if not isinstance(m, int):
        print("Got unexpected type")
        return
    else:
        m = m.to_bytes(length=(m.bit_length()+7)//8, byteorder='big')

    h = SHA3_256.new(r + m)
    h = int.from_bytes(h.digest(), byteorder='big') % n

    s = (k + sA * h) % n

    return (h, s)

# -----------------------------CODE STARTS HERE---------------------------


Setup()
Sa, Qa = KeyGen(E)
#stuIDB = 25355
stuIDB = 26045
stuIDA = 28175


h, s = signature_generation(stuID)
print("Resetting OTK's")
ResetOTK(h, s)
print("Creating new OTK's")
SPKey_Sec = 23486081322754753993120828544320268377602601205581983914150749871829893553343
SPKey_S_Pub = Point(85040781858568445399879179922879835942032506645887434621361669108644661638219,
                    46354559534391251764410704735456214670494836161052287022185178295305851364841, E)
# Generating HMAC KEY
T = SPKey_Sec * SPKey_S_Pub
message = b'CuriosityIsTheHMACKeyToCreativity'

# Convert T.y and T.x to bytes
T_y_bytes = T.y.to_bytes(length=(T.y.bit_length() + 7) // 8, byteorder='big')
T_x_bytes = T.x.to_bytes(length=(T.x.bit_length() + 7) // 8, byteorder='big')

# Concatenate myString_bytes, T_y_bytes, and T_x_bytes
U = message + T_y_bytes + T_x_bytes

# Create a SHA3-256 hash object
hmac_key = SHA3_256.new(U).digest()
all_otk = []
for i in range(10):
    otk = randomGen(n)
    all_otk.append(otk)

for i in range(len(all_otk)):
    curr_otk = all_otk[i]
    curr_otk = curr_otk * P
    curr_otk_xcoord = curr_otk.x
    curr_otk_ycoord = curr_otk.y
    curr_otk_xcoord_bytes = curr_otk_xcoord.to_bytes(
        (curr_otk_xcoord.bit_length() + 7) // 8, byteorder='big')
    curr_otk_ycoord_bytes = curr_otk_ycoord.to_bytes(
        (curr_otk_ycoord.bit_length() + 7) // 8, byteorder='big')
    curr_otk_concat = curr_otk_xcoord_bytes + curr_otk_ycoord_bytes
    hmac = HMAC.new(hmac_key, digestmod=SHA256)
    hmac.update(curr_otk_concat)
    hmac_val = hmac.hexdigest()
    OTKReg(i, curr_otk_xcoord, curr_otk_ycoord, hmac_val)


PseudoSendMsgPH3(h, s)
messages_list = []

for i in range(5):
    server_response = ReqMsg(h, s)
    msg_id = server_response.get('MSGID')
    print('-----------------------------------------------------')
    print('Processing message ', msg_id)

    if (i == 0):
        curr_otk = server_response.get('OTKID')
        ek_x = server_response.get('EK.X')
        ek_y = server_response.get('EK.Y')
        EK_Pub = Point(ek_x, ek_y, E)
        # Session Key
        T = all_otk[curr_otk] * EK_Pub
        # Convert T.y and T.x to bytes
        T_y_bytes = T.y.to_bytes(
            length=(T.y.bit_length() + 7) // 8, byteorder='big')
        T_x_bytes = T.x.to_bytes(
            length=(T.x.bit_length() + 7) // 8, byteorder='big')
        # Concatenate myString_bytes, T_y_bytes, and T_x_bytes
        U = T_x_bytes + T_y_bytes + b'ToBeOrNotToBe'
        Session_KEY = SHA3_256.new(U).digest()
        curr_kdf = Session_KEY

    # curr_ENC_KEY
    myString = b'YouTalkingToMe'
    temp_u = curr_kdf + myString
    curr_ENC_KEY = SHA3_256.new(temp_u).digest()
    # curr_HMAC_KEY
    temp_u = curr_kdf + curr_ENC_KEY + b'YouCannotHandleTheTruth'
    curr_HMAC_KEY = SHA3_256.new(temp_u).digest()
    # next_kdf
    temp_u = curr_ENC_KEY + curr_HMAC_KEY + b'MayTheForceBeWithYou'
    next_kdf = SHA3_256.new(temp_u).digest()
    curr_kdf = next_kdf

    msg = server_response.get('MSG')
    msg_in_bytes = msg.to_bytes(
        length=(msg.bit_length() + 7) // 8, byteorder='big')
    nonce = msg_in_bytes[0:8]
    message = msg_in_bytes[8:-32]
    mac_val = msg_in_bytes[-32:]

    hmac = HMAC.new(curr_HMAC_KEY, digestmod=SHA256)
    hmac.update(message)
    hmac_val = hmac.digest()
    print("HMAC is: ", hmac_val)

    if mac_val == hmac_val:
        print("Hmac value is verified.")
        aes = AES.new(curr_ENC_KEY, AES.MODE_CTR, nonce=nonce)
        plaintext = aes.decrypt(message).decode('utf-8')
        print("The collected plaintext is: ", plaintext)

        Checker(stuID, stuIDB, msg_id, plaintext)
        messages_list.append(plaintext)
    else:
        print('Invalid HMAC value.')
        messages_list.append("NOTVALID")
 

h1,s1 = signature_generation(stuIDB)        
otk_response = reqOTKB(stuID,stuIDB,h1,s1)
print('otk response is: ',otk_response)
otk1_id = otk_response[0]




count = 0
for plaintext in messages_list:
    if plaintext != "NOTVALID":
        count += 1
        
        if (count == 1):
            sA, QA = KeyGen(E)
            print('sA: ',sA, 'QA:', QA,'\n')
            T = sA * Point(QA.x, QA.y, E)
            T_y_bytes = T.y.to_bytes(length=(T.y.bit_length() + 7) // 8, byteorder='big')
            T_x_bytes = T.x.to_bytes(length=(T.x.bit_length() + 7) // 8, byteorder='big')
            U = T_x_bytes + T_y_bytes + b'ToBeOrNotToBe'
            Session_KEY = SHA3_256.new(U).digest()
            curr_kdf = Session_KEY

        # curr_ENC_KEY
        myString = b'YouTalkingToMe'
        temp_u = curr_kdf + myString
        curr_ENC_KEY = SHA3_256.new(temp_u).digest()
        # curr_HMAC_KEY
        temp_u = curr_kdf + curr_ENC_KEY + b'YouCannotHandleTheTruth'
        curr_HMAC_KEY = SHA3_256.new(temp_u).digest()
        # next_kdf
        temp_u = curr_ENC_KEY + curr_HMAC_KEY + b'MayTheForceBeWithYou'
        next_kdf = SHA3_256.new(temp_u).digest()
        curr_kdf = next_kdf
   
        wordToBeEncrypted = plaintext.encode('UTF-8') 
        # Encrypt the message
        aes = AES.new(curr_ENC_KEY,AES.MODE_CTR)
        nonce = aes.nonce
        ciphertext = aes.encrypt(wordToBeEncrypted)

        # Compute the HMAC value of the ciphertext
        hmac = HMAC.new(curr_HMAC_KEY, digestmod=SHA256)
        hmac.update(ciphertext)
        mac_val = hmac.digest()

        # Concatenate the nonce, ciphertext, and HMAC value
        msg_in_bytes = nonce + ciphertext + mac_val
        msg_as_int = int.from_bytes(msg_in_bytes, byteorder='big')
        
        SendMsg(stuIDA,stuIDB,otk1_id,count,msg_as_int,QA.x,QA.y)
        
        