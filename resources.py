help_message = '''\
CMAX CLI
KEYPAIR COMMANDS:
 - generate_keypair - Generate a new keypair
 - load_keypair <private_key_pem_file> - Load keypair from PEM file
 - show_keypair ['-private']- Show the current keypair
 - export_keypair [private_key_pem_file public_key_pem_file] - Export keypair to PEM files

CA COMMANDS: WIP
 - load_ca <public_key_pem_file> - Add a CA public key from PEM file

CONTACTS COMMANDS:
 - load_contacts - Load all receiver public keys from the 'receivers' directory
 - import_contact [public_key_pem_file] - Import a receiver public key from PEM file or stdin
 - list_contacts - List all loaded receivers
 - show_contact <receiver_id> - Show the public key of a specific receiver

MESSAGE COMMANDS:
 - encrypt <receiver_id> <message> - Encrypt a message for all receivers
 - decrypt <encoded_message> - Decrypt a message using the current keypair
'''
