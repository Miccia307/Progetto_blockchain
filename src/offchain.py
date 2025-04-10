from web3 import Web3
from web3.contract import Contract
from web3.providers.rpc import HTTPProvider
from solcx import install_solc,set_solc_version
install_solc("0.8.0")
import json
import time
 
import sqlite3
import bcrypt
import re
 
from consolemenu import ConsoleMenu
from consolemenu.items import FunctionItem
import getpass
 
# Configura la versione da utilizzare
set_solc_version("0.8.0")
# install_solc(version='latest')
from solcx import compile_source
import os
 
 
from consolemenu import *
from consolemenu.items import *
from dotenv import load_dotenv
 
load_dotenv()
 
USER_KEY1 = os.getenv('USER_KEY1')
USER_KEY2 = os.getenv('USER_KEY2')
USER_KEY3 = os.getenv('USER_KEY3')
USER_KEY4 = os.getenv('USER_KEY4')
 
indirizzo_contratto_nuovo= None
user_salvato= None
private_key_= None
 
onmanager = None
web3_1 = None
web3_2 = None
web3_3 = None
web3_4 = None
 
 
 
def w3connection():
   
    global web3_1
    global web3_2
    global web3_3
    global web3_4
    web3_1 = Web3(Web3.HTTPProvider('http://127.0.0.1:7545'))
    if web3_1.is_connected():
        print("Connesso al provider Web3")
    else:
        print("Connessione al provider Web3 fallita nella prima porta")
    web3_2 = Web3(Web3.HTTPProvider('http://127.0.0.1:7546'))
   
    if web3_2.is_connected():
        print("Connesso al provider Web3")
    else:
        print("Connessione al provider Web3 fallita nella seconda porta")
    web3_3 = Web3(Web3.HTTPProvider('http://127.0.0.1:7547'))
    if web3_3.is_connected():
        print("Connesso al provider Web3")
    else:
        print("Connessione al provider Web3 fallita nella terza porta")
    web3_4 = Web3(Web3.HTTPProvider('http://127.0.0.1:7548'))
    if web3_4.is_connected():
        print("Connesso al provider Web3")
    else:
        print("Connessione al provider Web3 fallita nella quarta porta")
    return web3_1
 
def getContract(file):
    if os.path.exists(file) :
        filepath = os.path.abspath(file)
        with open(filepath, 'r') as f:
         ctr = f.read()
        return ctr
    else :  input("File non esistente, premi Invio per continuare...")
   
 
 
 
def makeTransaction(w3: Web3, contract: Contract, function_name: str, args: any):
    contract_function = getattr(contract.functions, function_name, None)
    if not contract_function:
        raise ValueError(f"La funzione '{function_name}' non esiste nello smart contract.")
   
    gas = 2000000
    try:
        if w3.provider.endpoint_uri == web3_1.provider.endpoint_uri:            
            private_key = USER_KEY1
        elif w3.provider.endpoint_uri == web3_2.provider.endpoint_uri:
            private_key = USER_KEY2
        elif w3.provider.endpoint_uri == web3_3.provider.endpoint_uri:
            private_key = USER_KEY3
        elif w3.provider.endpoint_uri == web3_4.provider.endpoint_uri:
            private_key = USER_KEY4      
           
        suggested_gas_price = w3.eth.gas_price
       
        transaction = contract_function(*args).build_transaction({
            'gas': gas,          
            'gasPrice': suggested_gas_price,
            'from': w3.eth.accounts[0],
            'nonce': w3.eth.get_transaction_count(w3.eth.accounts[0]),
            'value': 0,
            'chainId': w3.eth.chain_id,
           
        })
       
 
        signed_txn = w3.eth.account.sign_transaction(transaction, private_key)
   
        tx_hash = w3.eth.send_raw_transaction(signed_txn.raw_transaction)
   
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
        return tx_receipt
       
    except Exception as e:
        #raise ValueError(f"Errore durante la transazione: {e}")
        print("errore in maketransaction", e)
        return False
 
 
def getTransactionReceipt(w3: Web3, transactionid : str):  
   
    try:
        return (w3.eth.get_transaction_receipt(transactionid))
    except Exception as e:
        #print("Transazione non registrata...", e)
        return None
 
 
def checkTransactionResult():
    transaction_id = input("Inserisci l'ID della transazione: ")
    web3_connection = [ web3_3, web3_4, web3_1, web3_2]
   
    try:
        for w3_c in web3_connection:
            result = getTransactionReceipt(w3_c,transaction_id)
            if result:  # Se il risultato è valido (non None)
                print("Risultato della transazione trovato :")
               
                for key, value in result.items():
                    print(f"{key}: {value}")
                    #print(result)
            elif w3_c==web3_connection[3]: # è l'ultimo elemento dell'array, se entra qui significa che non ha trovato alcuna transazione
                    print("Transazione non registrata...")
           
    except Exception as e:
        if str(e) == "Transazione non registrata...":
            print("Transazione non trovata.")
        else:
            print("Errore durante la verifica della transazione:", str(e))
    input("Premi Invio per tornare al menù principale...")
       
 
 
def deploy(w3: Web3, contract: Contract, name:str):
   
    if w3.provider.endpoint_uri == web3_1.provider.endpoint_uri:          
        private_key = USER_KEY1
    elif w3.provider.endpoint_uri == web3_2.provider.endpoint_uri:
        private_key = USER_KEY2
    elif w3.provider.endpoint_uri == web3_3.provider.endpoint_uri:
        private_key = USER_KEY3
    elif w3.provider.endpoint_uri == web3_4.provider.endpoint_uri:
        private_key = USER_KEY4
 
    smart_contract = {
        "from": w3.eth.accounts[0],
        #"maxFeePerGas": w3.to_hex(1000000000000),
        "gas": 2000000,
        "gasPrice":w3.to_wei('20', 'gwei'),
        "nonce": w3.eth.get_transaction_count(w3.eth.accounts[0]),
        "data": contract.bytecode,
        'chainId': w3.eth.chain_id
    }
   
    signT = w3.eth.account.sign_transaction(smart_contract, private_key)
    sendT = w3.eth.send_raw_transaction(signT.raw_transaction)
    rec = w3.eth.wait_for_transaction_receipt(sendT)
    contract_add= rec['contractAddress']
    contract = w3.eth.contract(address = rec.contractAddress, abi=contract.abi, bytecode=contract.bytecode)
    return contract_add
 
 
 
def compile_contract(contract_source_code):
    compiled_sol = compile_source(contract_source_code)
    contract_id, contract_interface = compiled_sol.popitem()
    bytecode = contract_interface['bin']
    abi = contract_interface['abi']
    return abi, bytecode
 
 
# Funzione per deploy del contratto
def deployOCM(w_prova: Web3):
    try:
        account = w_prova.eth.accounts[0]
        contract_source_code = getContract("contracts/onchain.sol")
        # Compila il contratto
        abi, bytecode = compile_contract(contract_source_code)
 
        # Crea un'istanza del contratto
        OnChainManager = w_prova.eth.contract(abi=abi, bytecode=bytecode)
        # Imposta i dati di transazione
        transaction = {
            'from': account,
            'gas': 10000000,  # Modifica se necessario
            'gasPrice': w_prova.to_wei('20', 'gwei')
        }
       
        # Deploy del contratto
        tx_hash = OnChainManager.constructor().transact(transaction)
       
        # Attendi che la transazione venga minerata (completata)
        tx_receipt = w_prova.eth.wait_for_transaction_receipt(tx_hash)
 
        # Estrai l'indirizzo del contratto
        contract_address = tx_receipt['contractAddress']
        #print(f"Contratto distribuito con successo all'indirizzo {contract_address}")
 
        return contract_address, abi
   
    except Exception as e:
        print(f"Errore nel deploy del contratto: {e}")
 
 
 
def deployContract():
    global indirizzo_contratto_nuovo
    try:
        while True:
            filename = input("Inserisci il contratto che vuoi caricare: ").strip()
            if filename.endswith(".sol"):
                break
            print("Errore: il file deve avere estensione .sol ed esistere nella cartella src/. Riprova.")
 
        while True:
            name = input("Inserisci il nome con cui vuoi memorizzarlo: ").strip()
            nome_contratto_esistente, trovato = contract.functions.getContracts_byname(name).call()
       
            if not trovato:
                break
            print("Contratto già esistente. Scegli un altro nome.")
 
        comp_sc = compile_source(getContract('src/'+filename), output_values=['abi', 'bin'])
        #print("comp_sc:     ", comp_sc)
        _, cInterface = comp_sc.popitem()
        cBytecode = cInterface['bin']
        cAbi = cInterface['abi']
        next_ad = makeTransaction(web3_1, onmanager, "getNextAddress", [])
        #print("next  \n\n\n ", next_ad)
        logs = onmanager.events.NextAddr().process_receipt(next_ad)
        #print("log   ", logs)
           
        nextAddress = logs[0]['args']['nextAddress']
        web3_new = Web3(HTTPProvider(nextAddress))
        if web3_new.is_connected():
                #print("Connesso a " + nextAddress)
                personal_contract = web3_1.eth.contract(abi=cAbi, bytecode=cBytecode)    
                personal_contract = deploy(web3_new, personal_contract, name)
 
                indirizzo_contratto_nuovo = personal_contract
   
                makeTransaction(web3_1, onmanager, 'aggiungiContratto', [name, nextAddress,  str(cAbi), str(user_salvato)])
                print('Smart Contract caricato con successo')
        else:
                print("Non connessa a  " + nextAddress)
    except Exception as e:
        print(e)
   
    input("Premi Invio per tornare al menù principale...")
 
 
def read(contract: Contract, function_name: str, args: list):
    if len(args) == 0:
        result = contract.functions[function_name]().call()
    elif len(args) == 1:
        result = contract.functions[function_name](args[0]).call()
    elif len(args) == 2:
        result = contract.functions[function_name](args[0], args[1]).call()
    else:
        result = contract.functions[function_name](args[0], args[1], args[2]).call()
    return result
 
 
def parse_abi(abi):
    result = []  # Lista per memorizzare le stringhe formattate
    for function in abi:
        if function['type'] == 'function':  
            name = function['name']
           
            # Estrai gli input
            inputs = ", ".join(inp['internalType'] for inp in function['inputs']) if function['inputs'] else "none"
           
            # Estrai gli output
            outputs = ", ".join(out['internalType'] for out in function['outputs']) if function['outputs'] else "none"
 
            # Aggiungi la stringa formattata alla lista
            result.append(f"Nome: {name} | Input: {inputs} | Output: {outputs}")
   
    return result
 
 
def rimozione_contratto():
    try:
        contratti = contract.functions.getContracts_byOwner(user_salvato).call()
        print("contratti in tuo possesso che puoi eliminare: ")
        print(contratti)
 
        filename = input("Inserisci il nome del contratto che vuoi eliminare: ")
        con, trovato = contract.functions.getContracts_byname(filename).call()
        if not trovato:
            print("Il contratto non esiste")
            input("Premi Invio per tornare al menù principale...")
            return
       
       
        #rimozione = contract.functions.deleteContract_byName(filename).call()
        rimozione_2 = makeTransaction( web3_1, onmanager, "deleteContract_byName" , [filename, user_salvato])
        #print(rimozione_2.status)
       
        if rimozione_2.status:
            input("contratto eliminato con successo, premi per continuare")
        else:
            input("rimozione del contratto non riuscita, premi per continuare")
    except Exception as e:
        print("errore in rimozione contratti", e)
 
 
def trova_contratti_by_prop():
    try:
        contratti = contract.functions.getContracts_byOwner(user_salvato).call()
        print("I tuoi contratti sono:" ,contratti)
        input("premi per continuare ")
    except Exception as e:
        print("errore trova contratti  ", e)
 
 
def use_contract():
    try:
        filename = input("Inserisci il nome del contratto che vuoi usare: ")
        con, trovato = contract.functions.getContracts_byname(filename).call()
 
        if not trovato:
            print("Il contratto non esiste")
            input("Premi Invio per tornare al menù principale...")
            return
 
        abi_json = json.loads(con[3].replace("'", '"'))  # ABI convertito in JSON
       
        contract_instance = web3_2.eth.contract(address=indirizzo_contratto_nuovo, abi=abi_json)
 
        # Analizziamo le funzioni disponibili nel contratto
        risultati_funzioni = parse_abi(abi_json)
 
        if not risultati_funzioni:
            print("Nessuna funzione disponibile nel contratto.")
            input("Premi Invio per tornare al menù principale...")
            return
 
        # Mostra il sottomenu per selezionare le funzioni
        while True:
            print("\n🔹 Funzioni disponibili nel contratto:")
            for idx, func in enumerate(risultati_funzioni, 1):
                print(f"{idx}. {func}")
            print("0. Torna al menù principale")
           
            scelta = input("Seleziona una funzione da eseguire: ")
 
            if scelta == "0":
                break  # Esce dal sottomenu
         
            try:
                scelta_idx = int(scelta) - 1
                if 0 <= scelta_idx < len(risultati_funzioni):
                    funzione_selezionata = risultati_funzioni[scelta_idx].split("|")[0].split(":")[1].strip()
                    print(f"Hai selezionato: {funzione_selezionata}")
 
                    # Recuperiamo la funzione dall'ABI per ottenere gli input richiesti
                    function_abi = next(f for f in abi_json if f['name'] == funzione_selezionata)
                    input_params = function_abi.get("inputs", [])
                    state_mutability = function_abi.get("stateMutability", "nonpayable")
                   
                    # Se la funzione richiede parametri, chiediamoli all'utente
                    args = []
                    for param in input_params:
                        val = input(f"Inserisci il valore per '{param['name']}' ({param['internalType']}): ")
                        args.append(int(val) if "uint" in param['internalType'] else val)
                   
                    contract_function = getattr(contract_instance.functions, funzione_selezionata, None)
                    if contract_function:
                        if state_mutability in ["view", "pure"]:
                            # La funzione è di sola lettura, quindi usiamo call()
                            result = contract_function(*args).call()
                            print(f"Risultato: {result}")
                        else:
                            # La funzione modifica lo stato, quindi usiamo makeTransaction()
                            tx_receipt = makeTransaction(web3_2, contract_instance, funzione_selezionata, args)
                            if tx_receipt.status:
                                input("transazione eseguita con successo, premi per continuare")
                            else:
                                input("Errore durante la transazione, premi per continuare")
                    else:
                        print("Errore: funzione non trovata nell'istanza del contratto.")
                else:
                    print("Errore: funzione non esistente nel menù")
 
            except Exception as e:
                print(f"Errore: {e}")
       
        input("Premi Invio per tornare al menù principale...")
        return con
 
    except Exception as e:
        print("Errore durante l'accesso al contratto.")
        print(e)
        input("Premi Invio per tornare al menù principale...")  
 
 
 
def send_eth():
    try:
        recipient = input("Inserisci l'address del propietario a cui vuoi inviare Ether: ")
        amount_eth = float(input("Inserisci il numero di Ether che vuoi inviare: "))
       
        # Controlla se la connessione è attiva
        if not web3_1.is_connected():
            raise Exception("Connessione alla blockchain fallita")
       
        # Ottieni l'indirizzo del mittente dalla chiave privata
        sender_address = web3_1.eth.account.from_key(private_key_).address
       
        # Controlla se il mittente ha abbastanza saldo
        balance = web3_1.eth.get_balance(sender_address)
        balance_eth = web3_1.from_wei(balance, 'ether')
        #print(balance_eth, balance, recipient, amount_eth , private_key_)
        
        if balance_eth < amount_eth:
            print("bilancio insufficiente: ", balance_eth , " rispetto a quelli richiesti: " ,amount_eth)
            input("Premi per continuare")
            raise Exception("Fondi insufficienti per completare la transazione")
       
        # Ottieni il numero di nonce per evitare doppie transazioni
        nonce = web3_1.eth.get_transaction_count(sender_address)
       
        # Imposta la transazione
        tx = {
            'nonce': nonce,
            'to': recipient,
            'value': web3_1.to_wei(amount_eth, 'ether'),
            'gas': 21000,
            'gasPrice': web3_1.eth.gas_price,
            'chainId': web3_1.eth.chain_id
        }
       
        # Firma la transazione con la chiave privata
        signed_tx = web3_1.eth.account.sign_transaction(tx, private_key_)
       
        # Invia la transazione
        tx_hash = web3_1.eth.send_raw_transaction(signed_tx.raw_transaction)
        tx_receipt = web3_1.eth.wait_for_transaction_receipt(tx_hash)
        if tx_receipt.status:
            input("transazione eseguita con successo, premi per continuare")
        else:
            input("Errore durante la transazione, premi per continuare")
        # Restituisce l'hash della transazione per il tracciamento
        return web3_1.to_hex(tx_hash)
    except Exception as e:
        print("errore nell'invio degli ether", e)
 
 
 
# Crea il menu principale
menu = ConsoleMenu("Menu principale", "Seleziona un'opzione")
w_prova= w3connection()
 
address_onchain, abi_onchain= deployOCM(web3_1)
onmanager=address_onchain
onmanager=w_prova.eth.contract(address=address_onchain, abi=abi_onchain)
makeTransaction(w_prova, onmanager, 'setAddress1', [])
 
 
 
time.sleep(10)
 
makeTransaction(web3_1, onmanager, 'setAddress2', [])
 
time.sleep(10)
 
makeTransaction(web3_1, onmanager, 'setAddress3', [])
 
 
############################################## funziona, metodo per richiamare un contratto
contract_address = address_onchain  # Inserisci l'indirizzo corretto del contratto
contract_abi = abi_onchain
 
# Crea l'oggetto contratto
contract = w_prova.eth.contract(address=contract_address, abi=contract_abi)
 
 
time.sleep(2)
 
 
# Creazione database e tabella utenti (se non esiste)
def initialize_db():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
    cursor.execute("""
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            username TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL,
            public_key TEXT NOT NULL,
            private_key TEXT NOT NULL
        )
    """)
    conn.commit()
    conn.close()
 
 
def is_valid_password(password):
    if (len(password) >= 8 and
        re.search(r"[A-Z]", password) and
        re.search(r"[a-z]", password) and
        re.search(r"\d", password) and
        re.search(r"[-_!@#$%^&*(),.?\":{}|<>]", password)):
        return True
    return False
 
 
# Registrazione di un nuovo utente
def register_user():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
   
    print("=== Registrazione ===")
    while True:
        username = input("Inserisci nuovo username: ")
        # Controllo se l'username esiste già nel database
        cursor.execute("SELECT id FROM users WHERE username = ?", (username,))
        existing_user = cursor.fetchone()
        if existing_user:
            print("Errore: Username già esistente. Scegli un altro username.")
            continue
        break
       
   
    while True:
        password =getpass.getpass("Inserisci nuova password: ")
        if not is_valid_password(password):
            print("La password deve contenere almeno 8 caratteri, una lettera maiuscola, una minuscola, un numero e un carattere speciale.")
            continue
        confirm_password =getpass.getpass("Conferma la password: ")
        if password == confirm_password:
            break
        else:
            print("Le password non coincidono. Riprova.")
   
    public_key = input("Inserisci la tua chiave pubblica: ")
    private_key = input("Inserisci la tua chiave privata: ")
    hashed_password = bcrypt.hashpw(password.encode(), bcrypt.gensalt())
    hashed_private_key = bcrypt.hashpw(private_key.encode(), bcrypt.gensalt())
   
    try:
        cursor.execute("INSERT INTO users (username, password, public_key, private_key) VALUES (?, ?, ?, ?)",
                       (username, hashed_password, public_key, hashed_private_key))
        conn.commit()
        print("Utente registrato con successo!")
    except sqlite3.IntegrityError:
        print("Errore: Username già esistente.")
   
    conn.close()
 
 
 
# Verifica login con il database
def login():
    try:
        global user_salvato
        global private_key_
        conn = sqlite3.connect("users.db")
        cursor = conn.cursor()
 
        print("=== Login ===")
        username = input("Username: ")
        password= getpass.getpass("Password: ")
        private_key = input("Inserisci la tua chiave privata: ")
 
        cursor.execute("SELECT password, private_key FROM users WHERE username = ?", (username,))
        user = cursor.fetchone()
       
        conn.close()
 
        if user and bcrypt.checkpw(password.encode(), user[0]) and bcrypt.checkpw(private_key.encode(), user[1]):
            # print("Login riuscito!\n")
            user_salvato = username
            private_key_= private_key
            input("Login riuscito! Premi invio per continuare...")
            # time.sleep(5)
            return True
        else:
            #print("Credenziali errate. Riprova.\n")
            input("Credenziali errate, premi per continuare...")
            return False
    except Exception as e:
        print("errore login", e)
   
 
def change_password():
    conn = sqlite3.connect("users.db")
    cursor = conn.cursor()
 
    print("=== Cambia Password ===")
    username = user_salvato
   
   
    password = getpass.getpass("Inserisci la tua password attuale: ")
   
    # Verifica che l'utente esista e la password sia corretta
    cursor.execute("SELECT password FROM users WHERE username = ?", (username,))
    user = cursor.fetchone()
   
    if user and bcrypt.checkpw(password.encode(), user[0]):
        print("Password attuale corretta.")
       
        # Chiedi una nuova password
        while True:
            new_password = getpass.getpass("Inserisci una nuova password: ")
            if not is_valid_password(new_password):
                print("La password deve contenere almeno 8 caratteri, una lettera maiuscola, una minuscola, un numero e un carattere speciale.")
                continue
            confirm_new_password = getpass.getpass("Conferma la nuova password: ")
            if new_password == confirm_new_password:
                break
            else:
                print("Le password non coincidono. Riprova.")
 
        # Verifica che la nuova password soddisfi i criteri di sicurezza
        if not is_valid_password(new_password):
            print("La nuova password non soddisfa i criteri di sicurezza.")
            conn.close()
            return
       
        # Aggiorna la password nel database
        hashed_new_password = bcrypt.hashpw(new_password.encode(), bcrypt.gensalt())
        cursor.execute("UPDATE users SET password = ? WHERE username = ?", (hashed_new_password, username))
        conn.commit()
        # Dopo aver cambiato la password, torna al menu principale e richiede nuovamente il login
        conn.close()
        # print("Password aggiornata con successo!")
        # time.sleep(1)
        input("Password aggiornata con successo! Premi invio per continuare...")
        return True  # Segnale che la password è stata cambiata
 
    else:
        #print(" Password errata.")
        input("Password errata. premi per continuare...")
        conn.close()
        return False
 
 
 
def main_menu():
   
    while True:
        menu = ConsoleMenu("Menu Principale")
        function_item = FunctionItem("Caricare uno smart contract", deployContract)
        function_item2 = FunctionItem("Check transazione", checkTransactionResult)
        function_item3 = FunctionItem("Invoca un metodo di un contratto esistente", use_contract)
        function_item4 = FunctionItem("Visualizza i miei contratti", trova_contratti_by_prop)
        function_item5 = FunctionItem("Elimina un contratto esistente", rimozione_contratto)
        function_item6 = FunctionItem("Invia Ether a qualcuno", send_eth)
        function_item7 = FunctionItem("Cambia password", lambda: change_password())
       
 
        menu.append_item(function_item)
        menu.append_item(function_item2)
        menu.append_item(function_item3)
        menu.append_item(function_item4)
        menu.append_item(function_item5)
        menu.append_item(function_item6)
        menu.append_item(function_item7)
       
        menu.show()
        print("Logout effettuato. Torna al menu iniziale...\n")
        break  # Dopo l'uscita, ritorna al menu iniziale
 
 
def start_menu():
    while True:
        print("=== Benvenuto ===")
        print("1. Registrazione")
        print("2. Login")
        print("3. Esci")
        choice = input("Scegli un'opzione: ")
       
        if choice == "1":
            register_user()
        elif choice == "2":
            if login():
                main_menu()
        elif choice == "3":
            print("Uscita...")
            break
        else:
            print("Scelta non valida, riprova.")
 
if __name__ == "__main__":
    initialize_db()  # Assicura che il database sia pronto
    start_menu()
 