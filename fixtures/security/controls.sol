// ARTIFICIAL STATIC FIXTURE - DO NOT EXECUTE, compile, or deploy.
// No addresses, funds, transactions, or attack contract are provided.
pragma solidity ^0.8.20;

contract FixtureAuthorization {
    address private owner;

    function vulnerableGuard() external view {
        // ruleid: localguard.security.solidity-tx-origin-authorization
        require(tx.origin == owner, "fixture guard");
    }

    function vulnerableReverseGuard() external view {
        // ruleid: localguard.security.solidity-tx-origin-authorization
        require(owner == tx.origin, "fixture guard");
    }

    function cleanGuard() external view {
        // ok: localguard.security.solidity-tx-origin-authorization
        require(msg.sender == owner, "fixture guard");
    }

    function cleanObservation() external view returns (address) {
        // ok: localguard.security.solidity-tx-origin-authorization
        return tx.origin;
    }
}
