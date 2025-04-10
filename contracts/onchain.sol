// SPDX-License-Identifier: UNLICENSED
pragma solidity >=0.8.0;
contract OnChainManager {
    
    address public owner; // l'indirizzo del proprietario del contratto
    uint public numContratti; // il numero di contratti presenti
    
    struct Contract {
        uint id;
        string nome;
        string Address;
        string Abi;
        string proprietario;
    }
    
   
    mapping(uint => Contract) public contracts; // mappa che associa l'id del contratto alla sua struttura
    
    event ContrattoAggiunto(uint id, string nome,  string Address, string Abi, string proprietario); // evento generato quando un nuovo contratto viene aggiunto
    event ContrattoRimosso(uint id, string nome, string proprietario); // evento generato quando un contratto viene rimosso
    event NextAddr(string nextAddress, uint8 counter);

    string private blockChain1;
    string private blockChain2;
    string private blockChain3;
    uint8 private count = 0; 

    //cambiato il set degli indirizzi in modo che con solo onchain non possa essere modificato l'indirizzo dello
    //shard su cui fare deploy dei contratti 
    function setAddress1() public{
        blockChain1 = "http://127.0.0.1:7546";
    }

    function setAddress2() public{
        blockChain2 = "http://127.0.0.1:7547";
    }

    function setAddress3() public{
        blockChain3 = "http://127.0.0.1:7548";
    }

    function getAddress1() public view returns (string memory) {
        return blockChain1;
    }

    function getAddress2() public view returns (string memory) {
        return blockChain2;
    }

    function getAddress3() public view returns (string memory) {
        return blockChain3;
    }

    constructor() {
        owner = msg.sender;
        numContratti = 0;
    }
    
   
    function aggiungiContratto(string memory name, string memory address2, string memory abi2, string memory proprietario) public   {
        
        numContratti++;
        
        contracts[numContratti] = Contract(numContratti, name, address2, abi2, proprietario);
        emit ContrattoAggiunto(numContratti, name,  address2, abi2, proprietario);
          
    }    

    function getContracts(uint _id) public view returns (Contract memory) {
        require(contracts[_id].id != 0, "Il contratto non esiste");
        Contract memory c = contracts[_id];
        return c;
    }
    
    function getContracts_byname(string memory name) public view returns (Contract memory, bool) {
        for (uint256 i = 1; i <= numContratti; i++) {
            if (keccak256(bytes(contracts[i].nome)) == keccak256(bytes(name))) {
                return (contracts[i], true);
            }
        }
        return (contracts[0], false); // Restituisce un contratto vuoto e false
    }


    function deleteContract_byName(string memory name, string memory proprietario) public returns (bool) {
        for (uint256 i = 1; i <= numContratti; i++) {
            if (keccak256(bytes(contracts[i].nome)) == keccak256(bytes(name))) {
                // Controllo che solo il proprietario possa eliminare il contratto
                require((keccak256(bytes(proprietario)) == keccak256(bytes(contracts[i].proprietario))), "Solo il proprietario puo eliminare il contratto");
                
                // Sposta l'ultimo elemento nella posizione corrente
                contracts[i] = contracts[numContratti];
                delete contracts[numContratti];
                numContratti--;
                emit ContrattoRimosso(i, contracts[i].nome, contracts[i].proprietario);
                return true; // Indica che il contratto è stato eliminato con successo
            }
        }
        return false; // Nessun contratto trovato con quel nome
    }

    function getContracts_byOwner(string memory proprietario) public view returns (string[] memory) {
        uint256 count_2 = 0;
        
        // Conta quanti contratti appartengono al proprietario
        for (uint256 i = 1; i <= numContratti; i++) {
            if (keccak256(bytes(contracts[i].proprietario)) == keccak256(bytes(proprietario))) {
                count_2++;
            }
        }
        
        // Crea un array per memorizzare i nomi dei contratti
        string[] memory contractNames = new string[](count_2);
        uint256 index = 0;
        
        for (uint256 i = 1; i <= numContratti; i++) {
            if (keccak256(bytes(contracts[i].proprietario)) == keccak256(bytes(proprietario))) {
                contractNames[index] = contracts[i].nome;
                index++;
            }
        }
        
        return contractNames;
    }

   

    function setCounter(uint8 counter) public {
        count = (counter + 1) % 3;
              
    }
    
    function getCounter() public view returns (uint8) {
        return count;
    }
    
    function getNextAddress() public returns (string memory) {
        string memory nextAddrs = "";

        uint8 counter = getCounter();

        if (counter == 0) {
            nextAddrs = blockChain1;
        } else if (counter == 1) {
            nextAddrs = blockChain2;
        } else if (counter == 2) {
            nextAddrs = blockChain3;
        }

        setCounter(counter);

        emit NextAddr(nextAddrs, counter);

        return (nextAddrs);
    }



}