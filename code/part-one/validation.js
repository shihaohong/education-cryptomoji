'use strict';

const { createHash } = require('crypto');
const signing = require('./signing');

/**
 * A simple validation function for transactions. Accepts a transaction
 * and returns true or false. It should reject transactions that:
 *   - have negative amounts
 *   - were improperly signed
 *   - have been modified since signing
 */
const isValidTransaction = transaction => {
  let isValidSignature = signing.verify(
    transaction.source, 
    transaction.source + transaction.recipient + transaction.amount, 
    transaction.signature);

  if (!isValidSignature || transaction.amount < 0) {
    return false;
  }

  return true;
};

/**
 * Validation function for blocks. Accepts a block and returns true or false.
 * It should reject blocks if:
 *   - their hash or any other properties were altered
 *   - they contain any invalid transactions
 */
const isValidBlock = block => {
  let currentHash = createHash('sha256')
    .update(
      block.transactions + 
      block.previousHash + 
      block.nonce
    )
    .digest('hex');

  if (currentHash !== block.hash) {
    return false;
  }

  let { transactions } = block;

  for (let i = 0; i < transactions.length; i++) {
    let transaction = transactions[i];
    if (!isValidTransaction(transaction)) {
      return false;
    }
  }

  return true;
};

/**
 * One more validation function. Accepts a blockchain, and returns true
 * or false. It should reject any blockchain that:
 *   - is a missing genesis block
 *   - has any block besides genesis with a null hash
 *   - has any block besides genesis with a previousHash that does not match
 *     the previous hash
 *   - contains any invalid blocks
 *   - contains any invalid transactions
 */
const isValidChain = blockchain => {
  const { blocks } = blockchain;

  for (let i = 0; i < blocks.length; i++) {
    const block = blocks[i];

    if (!isValidBlock(block)) {
      return false;
    }

    const { transactions, previousHash } = block;

    if (i === 0) {
      if (transactions.length !== 0 || previousHash !== null) {
        return false;
      }
    } else {
      const previousBlock = blocks[i - 1];
      const actualPreviousHash = previousBlock.hash;

      if (previousHash === null || previousHash !== actualPreviousHash) {
        return false;
      }
    }
  }

  return true;
};

/**
 * This last one is just for fun. Become a hacker and tamper with the passed in
 * blockchain, mutating it for your own nefarious purposes. This should
 * (in theory) make the blockchain fail later validation checks;
 */
const breakChain = blockchain => {
  // Your code here

};

module.exports = {
  isValidTransaction,
  isValidBlock,
  isValidChain,
  breakChain
};
