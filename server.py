from hashlib import blake2b, sha256
import os, sys, socket

usr = 'admin'
pwd = 'password'
pepper = os.urandom(blake2b.SALT_SIZE)

def password_in_clear(msg:str) -> bool:
    rcv_usr, rcv_pwd = msg.split[':']
    auth = True if (rcv_usr == usr) and (rcv_pwd == pwd) else False
    return auth

def password_digest(msg:str) -> bool:
    rcv_usr, rcv_hash = msg.split[':']
    h = sha256()
    h.update(pwd)
    auth = True if (rcv_usr == usr) and (rcv_hash == h.hexdigest()) else False
    return auth

def password_digest_with_salt(msg:str) -> bool:
    rcv_usr, rcv_hash, rcv_salt = msg.split(':')
    h = blake2b(rcv_salt)
    h.update(pwd.encode())
    auth = True if (rcv_usr == usr) and (rcv_hash == h.hexdigest()) else False
    return auth

def challenge_response(msg:str, chal:bytes) -> bool:
    rcv_usr, rcv_hash = msg.split(':')
    h = blake2b(chal)
    h.update(pwd.encode())
    auth = True if (rcv_usr == usr) and (rcv_hash == h.hexdigest()) else False
    return auth

def challenge_response_with_salt(msg:str, chal:bytes) -> bool:
    rcv_usr, rcv_salt, rcv_hash = msg.split(':')
    h = blake2b(rcv_salt)
    h.update(chal)
    h.update(pwd.encode())
    auth = True if (rcv_usr == usr) and (rcv_hash == h.hexdigest()) else False
    return auth

def challenge_response_with_salt_and_pepper(msg:str, chal:bytes) -> bool:
    rcv_usr, rcv_salt, rcv_hash = msg.split(':')
    h = blake2b(rcv_salt)
    h.update(chal)
    
    hh = blake2b(pepper)
    hh.update(pwd.encode())
    
    h.update(hh.digest)
    auth = True if (rcv_usr == usr) and (rcv_hash == h.hexdigest()) else False
    return auth

def main():
    mode = 0
    cli_auth = False
    
    while (mode < 1) or (mode > 6):
        print("Select server mode:")
        print("1. Password in Clear")
        print("2. Password Digest")
        print("3. Password Digest with Salt")
        print("4. Challenge Response")
        print("5. Challenge Response with Salt")
        print("6. Challenge Response with Salt and Pepper")
        mode = input()
        print("Select valid mode.") if (mode < 1) or (mode > 6) else print("Server Starting...")
    
    try:
        server = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        server.bind(('0.0.0.0', 4444))
        server.listen(5)
        while True:
            conn, addr = server.accept()
            if mode >= 4:
                chal = os.urandom(blake2b.SALT_SIZE)
                conn.send(chal+b':'+pepper) if mode == 7 else conn.send(chal)
            request = ""
            while True:
                data = conn.recv(4096)
                if not data: break
                request += data.decode('uft8')
                print(f"{addr}: {request}")
                
                if mode == 1: cli_auth = password_in_clear(request)
                if mode == 2: cli_auth = password_digest(request)
                if mode == 3: cli_auth = password_digest_with_salt(request)
                if mode == 4: cli_auth = challenge_response(request, chal)
                if mode == 5: cli_auth = challenge_response_with_salt(request, chal)
                if mode == 6: cli_auth = challenge_response_with_salt_and_pepper(request, chal)
                
                conn.send("OK".encode()) if cli_auth == True else conn.send("NOK".encode())
            conn.close()
            print("client disconnected and shutdown")
    except:
        print("\nServer Shutdown.")
        sys.exit()

if __name__=='__main__':
    main()