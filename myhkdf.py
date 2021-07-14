import hmac
import hashlib

# https://datatracker.ietf.org/doc/html/rfc5869
def HKDF_Extract(salt, IKM, hashtype):
    if hashtype == "sha256":
        PRK = hmac.new(salt, IKM, hashlib.sha256)
    elif hashtype == "sha384":
        PRK = hmac.new(salt, IKM, hashlib.sha384)
    return PRK.digest()

def HKDF_Expand(PRK, info, L, hashtype):
    T = b''
    T_i = b''
    cnt = 0
    if hashtype == "sha256":
        while len(T) < L:
            cnt += 1
            h = hmac.new(PRK, T_i + info + cnt.to_bytes(1,'big'), hashlib.sha256)
            T_i = h.digest()
            T += T_i
            
    elif hashtype == "sha384":
        while len(T) < L:
            cnt += 1
            h = hmac.new(PRK, T_i + info + cnt.to_bytes(1,'big'), hashlib.sha384)
            T_i = h.digest()
            T += T_i
    OKM = T[:L]
    return OKM

# https://datatracker.ietf.org/doc/html/rfc8446#section-7
def HKDF_Expand_Label(Secret, Label, Context, Length, hashtype):
    Label = b"tls13 " + Label
    HkdfLabel = Length.to_bytes(2,'big') + len(Label).to_bytes(1,'big') + Label + \
                len(Context).to_bytes(1,'big') + Context
    return HKDF_Expand(Secret, HkdfLabel, Length, hashtype)

def Derive_Secret(Secret, Label, Messages, hashtype):
    if hashtype == "sha256":
        Hash_length = 32
    elif hashtype == "sha384":
        Hash_length = 48
    return HKDF_Expand_Label(Secret, Label, Transcript_Hash(Messages, hashtype), Hash_length, hashtype)

# https://datatracker.ietf.org/doc/html/rfc8446#section-4.4.1
def Transcript_Hash(Messages, hashtype):
    if type(Messages) is list:
        Messages = b''.join(Messages)
    if hashtype == "sha256":
        h = hashlib.sha256(Messages).digest()        
    elif hashtype == "sha384":
        h = hashlib.sha384(Messages).digest()
    return h