const mcl = require("@aguycalled/mcl-wasm");
const { Transcript } = require("../crypto/operations");
const {
  AmountCommitment,
  AmountCommitmentKeyImage,
} = require("../crypto/commitment");
const SetMembershipProof = require("../proofs/setmembership");

class Staker {
  constructor(network) {
    this.network = network;
  }

  Stake(commitment) {
    const keyBases = this.network.GetBasesKeyImage();

    return {
      proof: new SetMembershipProof(
        commitment,
        this.network.lockedAmountCommitments,
        keyBases
      ),
      keyBases: keyBases,
      height: this.network.height,
      lockedAmountCommitments: this.network.lockedAmountCommitments,
    };
  }
}

module.exports = Staker;
