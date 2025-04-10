import os

def getContract(file):
    if os.path.exists(file) : 
        filepath = os.path.abspath(file)
        input(os.path.basename(filepath).split('/')[-1])
    else :  input("file non esistente")
    #with open(filepath, 'r') as f:
    #   ctr = f.read()
    
def getContract2(file):
    if os.path.exists(file) : 
        filepath = os.path.abspath(file)
        with open(filepath, 'r') as f:
         ctr = f.read()
        return ctr
    else :  input("File non esistente, premi Invio per continuare...")

def deployOCM():
    ocm = getContract2("onchain.sol")
    try: 
        print(ocm)   
    except Exception as e:
        input("Caricamento non riuscito")

deployOCM()