// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

import "../node_modules/@openzeppelin/contracts-upgradeable/access/OwnableUpgradeable.sol";
import "../node_modules/@openzeppelin/contracts-upgradeable/proxy/utils/Initializable.sol";
import "../node_modules/@openzeppelin/contracts-upgradeable/security/ReentrancyGuardUpgradeable.sol";
import "../node_modules/@openzeppelin/contracts-upgradeable/utils/AddressUpgradeable.sol";

contract UserManagement is Initializable, OwnableUpgradeable, ReentrancyGuardUpgradeable {
    using AddressUpgradeable for address;
    struct User {
        string userId;
        uint registrationTimestamp;
        uint lastLoginTimestamp;
        uint loginCount;
    }

    mapping(address => User) private users;
    mapping(bytes32 => address) private userIdToAddress; // Use bytes32 for key
    uint private totalUserCount;

    event UserRegistered(string indexed userId, address indexed userAddress, uint indexed registrationTimestamp);
    event UserLoggedIn(string indexed userId, address indexed userAddress, uint indexed loginTimestamp);
    event LoginCountUpdated(address indexed userAddress, uint indexed loginCount);


   
    function initialize() public initializer {
        __Ownable_init();
    }

function registerUser(address userAddress, string memory userId) external nonReentrant onlyOwner {
    require(bytes(userId).length > 0, "User ID cannot be empty");
    require(bytes(users[userAddress].userId).length == 0, "User already registered");
    require(!userAddress.isContract(), "Only EOAs allowed");

    uint registrationTimestamp = block.timestamp;
    users[userAddress] = User(userId, registrationTimestamp, 0, 0);
    userIdToAddress[keccak256(bytes(userId))] = userAddress;
    totalUserCount++;

    emit UserRegistered(userId, userAddress, registrationTimestamp);
}

    function login(address userAddress, string memory userId) external nonReentrant onlyOwner {
        bytes32 userIdHash = keccak256(bytes(userId));
        address existingUserAddress = userIdToAddress[userIdHash];
        require(existingUserAddress != address(0), "User not registered");
        require(existingUserAddress == userAddress, "Invalid credentials");
        require(!userAddress.isContract(), "Only EOAs allowed");

        uint loginTimestamp = block.timestamp;
        User storage user = users[userAddress];
        user.lastLoginTimestamp = loginTimestamp;
        user.loginCount++;

        emit UserLoggedIn(userId, userAddress, loginTimestamp);
    }


    function isUserRegistered(address userAddress) external view returns (bool) {
    return bytes(users[userAddress].userId).length != 0;
}


    function getUserRegistrationTimestamp(address userAddress) external view returns (uint) {
        return users[userAddress].registrationTimestamp;
    }

    function getUserLastLoginTimestamp(address userAddress) external view returns (uint) {
        return users[userAddress].lastLoginTimestamp;
    }

    function getUserLoginCount(address userAddress) external view returns (uint) {
        return users[userAddress].loginCount;
    }

    function getTotalUserCount() external view returns (uint) {
        return totalUserCount;
    }


function addUser(address userAddress, string memory userId) external nonReentrant onlyOwner {
    require(bytes(userId).length > 0, "User ID cannot be empty");
    require(bytes(users[userAddress].userId).length == 0, "User already registered");

    uint registrationTimestamp = block.timestamp;
    users[userAddress] = User(userId, registrationTimestamp, 0, 0);
    userIdToAddress[keccak256(bytes(userId))] = userAddress;
    totalUserCount++;

    emit UserRegistered(userId, userAddress, registrationTimestamp);
}


    // function updateUserLoginCount(uint newLoginCount) external {
    //     require(users[msg.sender].userId != 0, "User not registered");
    //     User storage user = users[msg.sender];
    //     user.loginCount = newLoginCount;
    //     emit LoginCountUpdated(msg.sender, newLoginCount);
    // }
}



