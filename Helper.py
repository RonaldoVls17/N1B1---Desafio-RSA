import math
import secrets
       
def generateE(phi_n):
    while True:
        e = secrets.randbelow(phi_n - 1) + 1
        if math.gcd(e, phi_n) == 1:
            return e
           
def generateD(e, totient):
    return pow(e, -1, totient)

def generateTotient(p, q):
    return (p-1)*(q-1)

def generateN(p, q):
    return p * q
