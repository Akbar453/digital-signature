
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding


def generate_keys():
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048,
        backend=default_backend()
    )
    public_key = private_key.public_key()
    return private_key, public_key


def sign(message, private_key):
    message = bytes(str(message), 'utf-8')

    signature = private_key.sign(
        message,
        padding.PSS(
            mgf=padding.MGF1(hashes.SHA256()),
            salt_length=padding.PSS.MAX_LENGTH
        ),
        hashes.SHA256()
    )

    return signature


def verify(message, sig, public_key):
    message = bytes(str(message), 'utf-8')
    try:
        public_key.verify(
            sig,
            message,
            padding.PSS(
                mgf=padding.MGF1(hashes.SHA256()),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            hashes.SHA256()
        )
        return True
    except Exception as e:
        print("Error verifying signature:", str(e))
        return False


if __name__ == '__main__':
    private_key, public_key = generate_keys()
    print(private_key)
    print(public_key)

    message = "Hi, I'm a Blockchain developer"
    sig = sign(message, private_key)
    print(sig)
    correct = verify(message, sig, public_key)
    if correct:
        print("Successful")
    else:
        print("Failed")

