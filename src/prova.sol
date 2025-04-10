// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract SimpleStorage {
    uint256 private storedData=7;

    // Imposta un valore nella variabile storedData
    function set_value(uint256 x) public {
        storedData = x;
    }

    // Ottiene il valore della variabile storedData
    function get_value() public view returns (uint256) {
        return storedData;
    }
}
