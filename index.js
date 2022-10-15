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
  let c2 = new AmountCommitment(1);
  let c3 = new AmountCommitment(15);
  let c4 = new AmountCommitment(20);
  let c5 = new AmountCommitment(25);

  let network = new Network();
  //network.LockAmountCommitment(c);
  network.LockAmountCommitment(c2);
  //network.LockAmountCommitment(c3);
  //network.LockAmountCommitment(c4);
  //network.LockAmountCommitment(c5);

  let staker = new Staker(network);
  let proof = staker.Stake(c2);

  //console.log(proof);

  proof.proof.Verify(network.lockedAmountCommitments, proof.keyBases);
});
