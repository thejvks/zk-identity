// SPDX-License-Identifier: MIT
pragma solidity ^0.8.20;

contract MockGroth16Verifier {
    bool private _returnValue;

    constructor(bool returnValue_) {
        _returnValue = returnValue_;
    }

    function verifyProof(
        uint256[2]    calldata,
        uint256[2][2] calldata,
        uint256[2]    calldata,
        uint256[3]    calldata
    ) external view returns (bool) {
        return _returnValue;
    }
}
