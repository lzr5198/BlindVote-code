// SPDX-License-Identifier: GPL-3.0

pragma solidity >=0.7.0 <0.9.0;

import "https://github.com/adria0/SolRsaVerify/blob/master/src/RsaVerifyOptimized.sol";
import "https://github.com/Solthodox/solidity-rsa/blob/main/src/RSA.sol";


/** 
 * @title BlindVote
 * @dev Implementation of BlindVote protocol
 */
contract BlindVote {

    // Deployment
    address admin;
    uint256 admin_deposit;
    mapping(uint256 => uint256) tally;
    uint256 f;
    uint256 p;

    uint256 n_options;
    uint256 n_max;
    uint256 t1;
    uint256 t2;
    uint256 t3;
    uint256 t4;
    uint256 t5;
    uint256 t6;

    // Voter Registration
    mapping(address => bool) approved_voters;
    mapping(address => bool) registered_voters;
    uint256 n_voter_registered = 0;

    // Initialization
    bytes N;
    bytes e;

    // Delegation
    mapping(address => bytes32) voter_hashes;

    // Blind Signature
    mapping(address => bytes) voter_signatures;

    // Committment
    uint256 n_commit = 0;
    mapping(bytes => bool) committed_N;
    mapping(bytes => bool) committed_e;
    mapping(bytes => bool) committed_s;
    mapping(bytes => bool) committed_c;

    // Reveal
    uint256 n_reveal = 0;


    // // ***** Main functions *****
    // Step 0: Deployment
    constructor(uint256 n_max_, uint256 f_, uint256 p_, uint256 t1_, uint256 t2_, uint256 t3_, uint256 t4_, uint256 t5_, uint256 t6_, uint256 n_options_, uint256 admin_deposit_) payable {
        require(msg.value == admin_deposit_ * 1 ether, "You should pay the right amount");
        admin_deposit = admin_deposit_ * 1 ether;
        admin = msg.sender;
        n_max = n_max_;
        f = f_ * 1 ether;
        p = p_ * 1 ether;
        t1 = block.timestamp + t1_ * 1 minutes;
        t2 = t1 + t2_ * 1 minutes;
        t3 = t2 + t3_ * 1 minutes;
        t4 = t3 + t4_ * 1 minutes;
        t5 = t4 + t5_ * 1 minutes;
        t6 = t5 + t6_ * 1 minutes;
        n_options = n_options_;

    }

    // Step 1: Voter Registration
    function approve(address a) public{
        require(msg.sender == admin, "Only administrator can approve");
        require(block.timestamp <= t1, "Step 1 has already passed");

        approved_voters[a] = true;
    }

    function register() public payable{
        require(msg.value == f, "You need to pay enough deposit");
        require(msg.sender != admin, "Administrator cannot call this function");
        require(block.timestamp <= t1, "Step 1 has already passed");
        require(n_voter_registered <= n_max, "There are already n_max registered voters");
        n_voter_registered++;
        registered_voters[msg.sender] = true;
    }
    
    bool step1_refuneded = false;
    function step1_refund() public {
        require(msg.sender != admin, "Administrator cannot call this function");
        require(registered_voters[msg.sender] && !approved_voters[msg.sender], "You did not register before or the administrator approved you");
        require(block.timestamp > t1, "This is not the period");
        require(!step1_refuneded, "Reentrancy attack!");    

        step1_refuneded = true;
        (bool sent, bytes memory data) = msg.sender.call{value: f}("");
        step1_refuneded = false;

    }

    // Step 2: Initialization
    function initiate(bytes memory N_, bytes memory e_) public{
        require(msg.sender == admin, "Only administrator can call this function");
        require(block.timestamp > t1 && block.timestamp <= t2, "It's not in step 2");
    
        N = N_;
        e = e_;
    }

    // Step 3: Delegation
    function delegate(bytes32 voterHash) public{
        require(msg.sender != admin, "Administrator cannot call this function");
        require(block.timestamp > t2 && block.timestamp <=t3, "This is not the period");
        require(registered_voters[msg.sender], "You did not register");
        require(voter_hashes[msg.sender] == bytes32(0), "You have submitted a hash before");
        
        voter_hashes[msg.sender] = voterHash;
    }

    // Step 4: Blind Singature
    function blind_sign(address a, bytes memory signature) public {
        require(msg.sender == admin, "Only administrator can call this function");
        require(block.timestamp > t3 && block.timestamp <= t4, "This is not the period");
        require(voter_hashes[a] != bytes32(0), "This node did not delegate before");
        require(RsaVerifyOptimized.pkcs1Sha256(voter_hashes[a], signature, e, N), "This signature is invalid");
        
        voter_signatures[a] = signature;
    }

    // Step 5: Committment
    bool admin_submit_extra_signature = false;
    bool commit_paid = false;
    function commit(bytes memory commit_N, bytes memory commit_e, bytes memory commit_s, bytes memory commit_c, bytes memory commit_sc) public {
        // check whether (commit_N,commit_e) is valid RSA public key
        require(committed_N[commit_N] && committed_e[commit_e] && committed_s[commit_s], "This committment has been submitted before");
        require(RsaVerifyOptimized.pkcs1Sha256Raw(abi.encodePacked(commit_N, commit_e), commit_s, e, N) 
                && RsaVerifyOptimized.pkcs1Sha256Raw(commit_c, commit_sc, commit_e, commit_N), "This signature is invalid");
        require(block.timestamp > t4 && block.timestamp <= t5, "This is not the period");
        require(!commit_paid, "Reentrancy attack!");

        committed_N[commit_N] = true;
        committed_e[commit_e] = true;
        committed_s[commit_s] = true;

        committed_c[commit_c] = true;
        n_commit++;

        commit_paid = true;
        (bool sent, bytes memory data) = msg.sender.call{value: p}("");
        commit_paid = false;
        
        if (n_commit > n_voter_registered)
            admin_submit_extra_signature = true;
    }

    // Step 6: Reveal
    bool reveal_paid = false;
    function reveal(bytes memory reveal_c, uint256 reveal_v, uint256 reveal_x) public {
        require(committed_c[reveal_c], "This committment was not submitted before or it has already been revealed");
        require(sha256(abi.encodePacked(reveal_v, reveal_x)) == bytes32(reveal_c), "The check does not pass");
        require(reveal_v > 0 && reveal_v <= n_options, "This is not a valid vote");
        require(block.timestamp > t5 && block.timestamp <= t6, "This is not the period");
        require(!reveal_paid, "Reentrancy attack!");

        committed_c[reveal_c] = false;
        tally[reveal_v]++;

        n_reveal++;
        reveal_paid = true;
        (bool sent, bytes memory data) = msg.sender.call{value: p}("");
        reveal_paid = false;

    }

    // ***** Report functions *****
    bool admin_not_submit_hash = false;
    function report_refused_signature() public {
        require(block.timestamp > t4, "You can only report after step 4");
        require(voter_hashes[msg.sender] != bytes32(0) && keccak256(voter_signatures[msg.sender]) == keccak256(bytes("")), "You did not submit hash before or the administrator submitted your signature");
        admin_not_submit_hash = true;
    }

    // ***** Refund functions *****
    bool step4_refund_paid = false;
    function step4_refund() public {
        require(block.timestamp > t4, "You can only call this after step 4");
        require(admin_not_submit_hash, "Administrator did not cheat");
        require(!step4_refund_paid, "Reentrancy attack!");
        step4_refund_paid = true;
        (bool sent, bytes memory data) = msg.sender.call{value: f + admin_deposit/n_voter_registered}("");
        step4_refund_paid = false;

    }

    bool step5_refund_paid = false;
    function step5_refund() public {
        require(block.timestamp > t5, "You can only call this after step 5");
        require(admin_submit_extra_signature, "Administrator did not submit extra signature");
        require(!step5_refund_paid, "Reentrancy attack!");
        step5_refund_paid = true;
        (bool sent, bytes memory data) = msg.sender.call{value: f + (admin_deposit - ((n_commit + n_reveal) * p))/n_voter_registered}("");
        step5_refund_paid = false;
    }

    bool admin_refund_paid = false;
    function admin_refund() public {
        require(msg.sender == admin, "Only administrator can call this function");
        require(block.timestamp > t6, "You can only call this after step 6");
        require(!admin_refund_paid, "Reentrancy attack!");
        admin_refund_paid = true;
        (bool sent, bytes memory data) = msg.sender.call{value: admin_deposit}("");
        admin_refund_paid = false;
    }

    bool voter_refund_paid = false;
    function voter_refund() public {
        require(block.timestamp > t6, "You can only call this after step 6");
        require(!voter_refund_paid, "Reentrancy attack!");
        voter_refund_paid = true;
        (bool sent, bytes memory data) = msg.sender.call{value: f - 2 * p}("");
        voter_refund_paid = false;
    }
}
