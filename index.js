const Crypto = require("./crypto");
const {
  AmountCommitment,
  MaskedAmountCommitment,
} = require("./crypto/commitment");
const Network = require("./network");
const Staker = require("./staker");

Crypto.Init().then(() => {
  console.log("Initialised");

  let c = new AmountCommitment(10);

  let network = new Network();
  network.LockAmountCommitment(c);

  let staker = new Staker(network);
  let proof = staker.Stake(c);

  console.log(proof);

  proof.proof.Verify(network.lockedAmountCommitments, proof.keyBases);
});
