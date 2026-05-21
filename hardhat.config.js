require("@nomicfoundation/hardhat-toolbox");
require("dotenv").config();

/** @type import('hardhat/config').HardhatUserConfig */
module.exports = {
  solidity: {
    version: "0.8.20",
    settings: {
      optimizer: { enabled: true, runs: 200 },
    },
  },
  networks: {
    hardhat: {},
    polygon_mumbai: {
      url: process.env.RPC_URL_MUMBAI || "https://rpc-mumbai.maticvigil.com",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    polygon: {
      url: process.env.RPC_URL_POLYGON || "https://polygon-rpc.com",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
    zksync_era: {
      url: "https://mainnet.era.zksync.io",
      accounts: process.env.PRIVATE_KEY ? [process.env.PRIVATE_KEY] : [],
    },
  },
  etherscan: {
    apiKey: {
      polygon:       process.env.POLYGONSCAN_API_KEY || "",
      polygonMumbai: process.env.POLYGONSCAN_API_KEY || "",
    },
  },
  paths: {
    sources:   "./contracts",
    tests:     "./test",
    cache:     "./cache",
    artifacts: "./artifacts",
  },
};
