import hashlib
import base64
from pathlib import Path
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import hashes, serialization
def a():
    x = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    y = x.public_key()
    return x, y
def b(target):
    res = hashlib.sha256()
    with open(target, "rb") as f:
        while ans := f.read(4096):
            res.update(ans)
    return res.hexdigest()
def c(res, a):
    ans = a.sign(
        res.encode(),
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )
    return base64.b64encode(ans).decode()
def d(res, ans, a):
    try:
        x = base64.b64decode(ans)
        a.verify(
            x,
            res.encode(),
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception:
        return False

def e(res, ans):
    with open("security_record.txt", "w") as f:
        f.write("SHA256_HASH=" + res + "\n")
        f.write("RSA_SIGNATURE=" + ans + "\n")

def f():
    res = {}
    with open("security_record.txt", "r") as x:
        for line in x:
            a, b = line.strip().split("=", 1)
            res[a] = b
    return res

def g(a, b):
    x = a.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    y = b.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    with open("private_key.pem", "wb") as f:
        f.write(x)
    with open("public_key.pem", "wb") as f:
        f.write(y)

def h():
    with open("private_key.pem", "rb") as f:
        a = serialization.load_pem_private_key(
            f.read(),
            password=None
        )
    with open("public_key.pem", "rb") as f:
        b = serialization.load_pem_public_key(
            f.read()
        )

    return a, b


def i(target):
    print("\nCreating security record...")

    a, b = a()

    res = b(target)

    print("SHA-256 Hash:")
    print(res)

    ans = c(res, a)

    print("\nRSA signature generated.")

    g(a, b)
    e(res, ans)

    print("Security record saved.")
    print("Status: RECORD CREATED")


def j(target):
    print("\nVerifying file...")

    res = f()

    a = res["SHA256_HASH"]
    b = res["RSA_SIGNATURE"]

    _, ans = h()

    x = b(target)

    print("\nStored SHA-256:")
    print(a)

    print("\nCurrent SHA-256:")
    print(x)

    if x != a:
        print("\n❌ TAMPERED")
        print("Reason: File content has changed.")
        return False

    y = d(a, b, ans)

    if not y:
        print("\n❌ TAMPERED")
        print("Reason: RSA signature is invalid.")
        return False

    print("\n✅ VERIFIED")
    print("File integrity is valid.")
    print("RSA signature is valid.")

    return True


if __name__ == "__main__":

    print("====================================")
    print("       VERITRACE SECURITY MVP")
    print("       SHA-256 + RSA")
    print("====================================")

    print("\n1. Create security record")
    print("2. Verify file")

    a = input("\nEnter choice: ")
    target = input("Enter file path: ")

    if not Path(target).exists():
        print("\nFile does not exist.")
        exit()

    if a == "1":
        i(target)

    elif a == "2":
        j(target)

    else:
        print("Invalid choice.")
