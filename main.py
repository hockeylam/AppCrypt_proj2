import os
from phe import paillier
from dotenv import load_dotenv

# -------------------------
# Key Management
# -------------------------

# Always write/read .env next to this script
ENV_PATH = os.path.join(os.path.dirname(__file__), ".env")

def generate_env_if_missing():
    """Generate Paillier keypair and write to .env if it doesn't exist."""
    if os.path.exists(ENV_PATH):
        return

    public_key, private_key = paillier.generate_paillier_keypair()

    with open(ENV_PATH, "w") as f:
        # Persist only what phe can reconstruct:
        # - Public key: n
        # - Private key: p, q
        f.write(f"PUBLIC_KEY_N={public_key.n}\n")
        f.write(f"PRIVATE_KEY_P={private_key.p}\n")
        f.write(f"PRIVATE_KEY_Q={private_key.q}\n")

    print(f".env file created at {ENV_PATH}")


def load_keys():
    """Load Paillier keys from .env and reconstruct the key objects."""
    load_dotenv(ENV_PATH)

    n = os.getenv("PUBLIC_KEY_N")
    p = os.getenv("PRIVATE_KEY_P")
    q = os.getenv("PRIVATE_KEY_Q")

    if not (n and p and q):
        raise RuntimeError("Missing keys in .env. Delete .env and rerun to regenerate, or populate values.")

    n = int(n)
    p = int(p)
    q = int(q)

    public_key = paillier.PaillierPublicKey(n)
    private_key = paillier.PaillierPrivateKey(public_key, p, q)
    return public_key, private_key


# -------------------------
# Core Classes
# -------------------------

class Translator:
    def __init__(self, public_key):
        self.public_key = public_key

    def encrypt(self, value: int):
        """Encrypt a plaintext integer using the public key."""
        return self.public_key.encrypt(value)


class Server:
    def __init__(self, public_key):
        self.public_key = public_key
        # Encrypted zero as starting balance
        self.balance = public_key.encrypt(0)

    def deposit(self, enc_amount):
        """Add encrypted amount to balance."""
        self.balance += enc_amount
        return self.balance

    def withdraw(self, enc_amount):
        """Subtract encrypted amount from balance."""
        self.balance -= enc_amount
        return self.balance

    def get_balance(self):
        """Return encrypted balance (server never decrypts)."""
        return self.balance


class User:
    def __init__(self, name: str, public_key, private_key):
        self.name = name
        self.public_key = public_key
        self.private_key = private_key
        self.translator = Translator(self.public_key)

    def deposit(self, server: Server, amount: int):
        """Encrypt and deposit a plaintext amount to the server."""
        enc_amount = self.translator.encrypt(amount)
        server.deposit(enc_amount)

    def withdraw(self, server: Server, amount: int):
        """
        Encrypt and withdraw a plaintext amount.
        Overdraft protection: user checks decrypted balance before sending.
        """
        current_balance = self.check_balance(server)
        if amount > current_balance:
            print(f"{self.name}: Insufficient funds (balance={current_balance}, attempted={amount})")
            return None
        enc_amount = self.translator.encrypt(amount)
        server.withdraw(enc_amount)
        return self.check_balance(server)

    def check_balance(self, server: Server) -> int:
        """Decrypt and return the current balance from the server."""
        enc_balance = server.get_balance()
        return self.private_key.decrypt(enc_balance)


# -------------------------
# Example Usage
# -------------------------

if __name__ == "__main__":
    # 1) Create .env with keys if missing
    generate_env_if_missing()

    # 2) Load keys from .env
    public_key, private_key = load_keys()

    # 3) Wire up server and user
    server = Server(public_key)
    alice = User("Alice", public_key, private_key)

    # 4) Operations with plaintext amounts
    alice.deposit(server, 100)
    alice.withdraw(server, 40)

    # 5) Check balance
    print("Alice's balance:", alice.check_balance(server))  # Expected: 60

    # 6) Overdraft attempt
    alice.withdraw(server, 70)  # Should print "Insufficient funds"
