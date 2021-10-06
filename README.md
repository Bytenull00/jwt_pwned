# jwt_pwned
A tool to test the security of Json Web Token

# jwt_pwned

It is a tool that allows forging and manipulating JWT (JSON Web Tokens).
### Requirements

This tool uses the common libraries that come natively in Python 3.9.2+, however it requires some additional libraries for aesthetic purposes.

### Installation

Installing 

```
git clone https://github.com/Bytenull00/jwt_pwned.git
cd jwt_pwned
python3 jwt_pwned --help
```

# Usage 

```
usage: jwt_pwned.py [-h] {bruteforce,kid,jku,none,konfusion} ...

positional arguments:
  {bruteforce,kid,jku,none,konfusion}
    bruteforce          Brute force to JWT, only algorithm hash SHA256
    kid                 Injection kid header attack
    jku                 Injection jku header attack
    none                Algorithm None attack
    konfusion           Key confusion attack

optional arguments:
  -h, --help            show this help message and exit
```

### Brute Force

With symmetric encryption, a cryptographic signature is only as strong as the secret used. If an application uses a weak secret, the attacker can simply brute-force it by trying different secret values until the original signature matches the forged one. Having discovered the secret, the attacker can use it to generate valid signatures for malicious tokens
```
python3 jwt_pwned.py bruteforce -t (JWT) -f dictionary.txt
```

```
usage: jwt_pwned.py bruteforce [-h] -t TOKEN -f FILENAME

optional arguments:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
                        JWT to attack
  -f FILENAME, --filename FILENAME
                        File containing possible secret keys
```

### Allowing the None algorithm

The None algorithm specifies that the token is not signed. If this algorithm is permitted, we can bypass signature checking by changing an existing algorithm to None and stripping the signature.

If None is permitted as the algorithm value, an attacker can simply use it to replace the valid algorithm and then get rid of the signature.

```
python3 jwt_pwned.py none -t (JWT)
```

```
usage: jwt_pwned.py none [-h] -t TOKEN
optional arguments:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
                        JWT to attack
```

### Algorithm confusion

 The algorithm confusion vulnerability arises when an application does not check whether the algorithm of the received token matches the expected algorithm.
 
```
python3 jwt_pwned.py konfusion -t (JWT) -s (HS256/HS384/HS512) -pk public_key.pem
```

```
usage: jwt_pwned.py konfusion [-h] -t TOKEN -s SIGN -pk PUBKEY
optional arguments:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
                        JWT to attack
  -s SIGN, --sign SIGN  Signature algorithm (HS256/HS384/HS512)
  -pk PUBKEY, --pubkey PUBKEY
                        File containing the public key
```
### Kid parameter injections

The JWT header can contain the Key Id parameter kid. It is often used to retrieve the key from a database or filesystem. The application verifies the signature using the key obtained through the kid parameter. If the parameter is injectable, it can open the way to signature bypass or even attacks such as RCE, SQLi, and LFI.

```
python3 jwt_pwned.py kid -t (JWT) -s (HS256/HS384/HS512) -i (PAYLOAD) -k (KEY_SECRET) 
```

```
usage: jwt_pwned.py kid [-h] -t TOKEN -i INJECTION -s SIGN -k KEY
optional arguments:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
                        JWT to attack
  -i INJECTION, --injection INJECTION
                        Value to inject into the kid parameter
  -s SIGN, --sign SIGN  Signature algorithm (HS256/HS384/HS512)
  -k KEY, --key KEY     Specific secret key
```
### Jku parameter injections

 An attacker can change the jku parameter value to point to their own JWK instead of the valid one. If accepted, this allows the attacker to sign malicious tokens using their own private key. After the malicious token is sent, the application will fetch the attacker’s JWK and use it to verify the signature.
 
```
python3 jwt_pwned.py kid -t (JWT) -i (PAYLOAD)
``` 

```
usage: jwt_pwned.py jku [-h] -t TOKEN -i INJECTION
optional arguments:
  -h, --help            show this help message and exit
  -t TOKEN, --token TOKEN
                        JWT to attack
  -i INJECTION, --injection INJECTION
                        Value to inject into the jku parameter
``` 

# Demo

![img1](https://user-images.githubusercontent.com/19710178/136139507-059956a0-7485-4d92-870c-75db2b9b0336.png)

### Credits 

* Gustavo Segundo - ByteNull%00 
