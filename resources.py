help_message = '''\
   ____ __  __    _    __  __                 _   _                 
  / ___|  \/  |  / \   \ \/ /     _ __  _   _| |_| |__   ___  _ __  
 | |   | |\/| | / _ \   \  /_____| '_ \| | | | __| '_ \ / _ \| '_ \ 
 | |___| |  | |/ ___ \  /  \_____| |_) | |_| | |_| | | | (_) | | | |
  \____|_|  |_/_/   \_\/_/\_\    | .__/ \__, |\__|_| |_|\___/|_| |_|
                                 |_|    |___/                       
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
