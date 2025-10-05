from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from cryptography.hazmat.primitives import serialization, hashes

import os
from resources import help_message


class Keypair:
    def __init__(self, private_key=None):
        if private_key is None:
            self.private_key = rsa.generate_private_key(
                public_exponent=65537,
                key_size=2048,
                backend=default_backend()
            )
        else:
            self.private_key = private_key
        self.public_key = self.private_key.public_key()

    def serialize_private_key(self):
        return self.private_key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def export_private_key_pem(self, filepath):
        with open(filepath, 'wb') as f:
            f.write(self.serialize_private_key())

    def export_public_key_pem(self, filepath):
        with open(filepath, 'wb') as f:
            f.write(self.serialize_public_key())

    def decrypt_message(self, encrypted_message: bytes) -> bytes:
        return self.private_key.decrypt(
            encrypted_message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def load_private_key_pem(filepath):
        with open(filepath, 'rb') as f:
            private_key = serialization.load_pem_private_key(
                f.read(),
                password=None,
                backend=default_backend()
            )
        return Keypair(private_key)


class PublicKey:
    def __init__(self, public_key):
        self.public_key = public_key

    def serialize_public_key(self):
        return self.public_key.public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
        )

    def export_public_key_pem(self, filepath):
        with open(filepath, 'wb') as f:
            f.write(self.serialize_public_key())

    def encrypt_message(self, message: bytes) -> bytes:
        return self.public_key.encrypt(
            message,
            padding.OAEP(
                mgf=padding.MGF1(algorithm=hashes.SHA256()),
                algorithm=hashes.SHA256(),
                label=None
            )
        )

    @staticmethod
    def load_from_file(filepath):
        with open(filepath, 'rb') as f:
            public_key = serialization.load_pem_public_key(
                f.read(),
                backend=default_backend()
            )
        return PublicKey(public_key)

    @staticmethod
    def load_from_string(pem_string):
        public_key = serialization.load_pem_public_key(
            pem_string.encode(),
            backend=default_backend()
        )
        return PublicKey(public_key)


command_handlers = {}


def make_handler(command_name: str):
    def wrapper(func):
        command_handlers[command_name] = func
        return func
    return wrapper


keypair: Keypair | None = None
contacts: dict[str, PublicKey] = {}


@make_handler("generate_keypair")
def handle_generate_keypair(*args):
    global keypair
    keypair = Keypair()
    print("Generated new keypair")


@make_handler("load_keypair")
def handle_load_keypair(*args):
    global keypair
    if len(args) == 1:
        private_key_path = args[0]
    else:
        if not os.path.exists('private_key.pem'):
            print("Usage: load_keypair <private_key_pem_file>")
            return
        private_key_path = 'private_key.pem'
    keypair = Keypair.load_private_key_pem(private_key_path)
    print(f"Loaded keypair from {private_key_path}")


@make_handler("show_keypair")
def handle_show_keypair(*args):
    global keypair
    if keypair is None:
        print("No keypair loaded")
        return
    print("Public Key:")
    print(keypair.serialize_public_key().decode())
    if args and args[0] == '-private':
        print("Private Key:")
        print(keypair.serialize_private_key().decode())


@make_handler("export_keypair")
def handle_export_keypair(*args):
    global keypair
    if keypair is None:
        print("No keypair loaded")
        return
    if len(args) != 2:
        private_key_path = 'private_key.pem'
        public_key_path = 'public_key.pem'
    else:
        private_key_path = args[0]
        public_key_path = args[1]
    keypair.export_private_key_pem(private_key_path)
    keypair.export_public_key_pem(public_key_path)
    print(f"Exported private key to {private_key_path}" +
          f"and public key to {public_key_path}")


@make_handler("load_contacts")
def handle_load_contacts(*args):
    global contacts
    contacts = {}
    if not os.path.exists('contacts'):
        os.mkdir('contacts')
    for filename in os.listdir('contacts'):
        if filename.endswith('.pem'):
            contact_id = filename[:-4]
            filepath = os.path.join('contacts', filename)
            public_key = PublicKey.load_from_file(filepath)
            contacts[contact_id] = public_key
    print(f"Loaded {len(contacts)} contacts from 'contacts' directory")


@make_handler("import_contact")
def handle_import_contact(*args):
    global contacts
    if len(args) == 1:
        public_key_path = args[0]
        if not os.path.exists(public_key_path):
            print(f"File {public_key_path} does not exist")
            return
        public_key = PublicKey.load_from_file(public_key_path)
        contact_id = os.path.splitext(os.path.basename(public_key_path))[0]
        contacts[contact_id] = public_key
        if not os.path.exists('contacts'):
            os.mkdir('contacts')
        filename = os.path.join('contacts', f"{contact_id}.pem")
        public_key.export_public_key_pem(filename)
        print(f"Imported contact {contact_id} from {public_key_path}")
    else:
        contact_id = input("Enter contact ID: ").strip()
        public_key_path = os.path.join('contacts', contact_id + '.pem')

        if os.path.exists(public_key_path):
            print(f"contact {contact_id} already exists.")
            return

        public_key_pem_lines = []
        print("Enter public key PEM (end with an empty line):")
        while line := input():
            public_key_pem_lines.append(line)
        public_key_pem = "\n".join(public_key_pem_lines)

        try:
            public_key = PublicKey.load_from_string(public_key_pem)
        except Exception as e:
            print(f"Failed to load public key: {e}")
            return

        contacts[contact_id] = public_key

        if not os.path.exists('contacts'):
            os.mkdir('contacts')

        public_key.export_public_key_pem(public_key_path)
        print(f"Imported contact {contact_id} and saved to {public_key_path}")  # noqa: E501


@make_handler("list_contacts")
def handle_list_contacts(*args):
    global contacts
    if not contacts:
        print("No contacts loaded")
        return
    print("contacts:")
    for contact_id in contacts:
        print(f" - {contact_id}")


@make_handler("show_contact")
def handle_show_contact(*args):
    global contacts
    if len(args) != 1:
        print("Usage: show_contact <contact_id>")
        return
    contact_id = args[0]
    public_key = contacts.get(contact_id)
    if public_key is None:
        print(f"No contact with ID {contact_id}")
        return
    print(f"Public Key for {contact_id}:")
    print(public_key.serialize_public_key().decode())


@make_handler("encrypt")
def handle_encrypt(*args):
    global keypair, contacts
    if keypair is None:
        print("No keypair loaded")
        return
    if len(args) < 2:
        print("Usage: encrypt <contact_id> <message>")
        return
    contact_id = args[0]
    message = " ".join(args[1:])
    public_key = contacts.get(contact_id)
    if public_key is None:
        print(f"No contact with ID {contact_id}")
        return

    encrypted_message = public_key.encrypt_message(message.encode())

    print("Encrypted message:")
    print(encrypted_message.hex())


@make_handler("decrypt")
def handle_decrypt(*args):
    global keypair
    if keypair is None:
        print("No keypair loaded")
        return
    if len(args) < 1:
        print("Usage: decrypt <encrypted_message>")
        return
    encrypted_message = " ".join(args)
    encrypted_message = bytes.fromhex(encrypted_message)

    try:
        decrypted_message = keypair.decrypt_message(encrypted_message)
    except ValueError:
        print("Failed to decrypt message. Invalid ciphertext or wrong keypair.")  # noqa: E501
        return

    print("Decoded message:")
    print(decrypted_message.decode())


@make_handler("help")
def handle_help(*args):
    print(help_message)


def cli():
    handle_help()
    handle_load_contacts()
    handle_list_contacts()
    handle_load_keypair()

    try:
        while command := input('> '):
            command, *args = command.split()
            if command == 'exit':
                break
            handler = command_handlers.get(command)
            if not handler:
                print(f"Unknown command: {command}")
                continue
            handler(*args)
    except KeyboardInterrupt:
        print()

    print("Bye!")


if __name__ == "__main__":
    cli()
