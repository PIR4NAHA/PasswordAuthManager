import os, socket, sys
from random import randint
from hashlib import sha256, blake2b

def password_in_clear(usr:str, pwd:str) -> str:
    msg = f"{usr}, {pwd}"
    return msg

def password_digest(usr:str, pwd:str) -> str:
    h = sha256()
    h.update(pwd.encode())
    msg = f"{usr}, {h.hexdigest()}"
    return msg

def password_digest_with_salt(usr:str, pwd:str) -> str:
    salt = os.urandom(blake2b.SALT_SIZE)
    h = blake2b(salt)
    h.update(pwd.encode())
    msg = f"{usr}, {h.hexdigest()}, {salt}"
    return msg

def challenge_response(usr:str, pwd:str, chal:bytes) -> str:
    h = blake2b(chal)
    h.update(pwd.encode())
    msg = f"{usr}, {h.hexdigest()}"
    return msg

def challenge_response_with_salt(usr:str, pwd:str, chal:bytes) -> str:
    salt = os.urandom(blake2b.SALT_SIZE)
    h = blake2b(salt)
    h.update(chal)
    h.update(pwd.encode())
    msg = f"{usr}, {salt}, {h.hexdigest()}"
    return msg

def challenge_response_with_salt_and_pepper(usr:str, pwd:str, chal:bytes, pepper:bytes) -> str:
    salt = os.urandom(blake2b.SALT_SIZE)
    h = blake2b(salt)
    h.update(chal)
    
    hh = blake2b(pepper)
    hh.update(pwd.encode())
    
    h.update(hh.digest())
    msg = f"{usr}, {salt}, {h.hexdigest()}"
    return msg

def main() -> None:
    mode = 0
    
    while (mode < 1) or (mode > 6):
        try:
            print("Select server mode:")
            print("1. Password in Clear")
            print("2. Password Digest")
            print("3. Password Digest with Salt")
            print("4. Challenge Response")
            print("5. Challenge Response with Salt")
            print("6. Challenge Response with Salt and Pepper")
            mode = int(input())
            print("Select valid mode.") if (mode < 1) or (mode > 6) else print("Server Starting...")
        except ValueError:
            os.system("cls||clear")
            print(f"{mode} is not a valid response.")
            print("\nValid responses are integers from 1-6\n")
    
    try:
        usr = 'admin'
        pwd = 'password'

        client = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        client.connect(('192.168.1.142', 4444))
        if mode > 3:
            msg = client.recv(4096)
            print(msg)

            if mode == 6:
                chal =  msg.split(b':')[0]
                pepper = msg.split(b':')[1]

        if mode == 1: msg = password_in_clear(usr, pwd)
        if mode == 2: msg = password_digest(usr, pwd)
        if mode == 3: msg = password_digest_with_salt(usr, pwd)
        if mode == 4: msg = challenge_response(usr, pwd, chal)
        if mode == 5: msg = challenge_response_with_salt(usr, pwd, chal)
        if mode == 6: msg = challenge_response_with_salt_and_pepper(usr, pwd, chal, pepper)

        client.send(msg.encode())
        response = client.recv(4096)

        client.close()
        print(response.decode())
    except:
        print("Error connecting to server.")
        sys.exit()

if __name__=='__main__':
    main()

