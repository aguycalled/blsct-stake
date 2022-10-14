const mcl = require("@aguycalled/mcl-wasm");
const { bytesArray, Transcript } = require("./operations");
const { H, G, G2 } = require("./index");

class AmountCommitment {
  constructor(amount) {
    this.amount = new mcl.Fr();
    this.amount.setBigEndianMod(bytesArray(amount));
    this.mask = new mcl.Fr();
    this.mask.setByCSPRNG();
    this.commitment = mcl.add(
      mcl.mul(H(), this.amount),
      mcl.mul(G(), this.mask)
    );
  }

  GetMaskedAmountCommitment() {
    return new MaskedAmountCommitment(this);
  }
}

class MaskedAmountCommitment {
  constructor(commitment) {
    if (!(commitment instanceof AmountCommitment))
      throw new Error(`Argument 0 must be AmountCommitment`);
    this.commitment = commitment;
    this.mask = new mcl.Fr();
    this.mask.setByCSPRNG();
    this.masked_commitment = mcl.add(
      this.commitment.commitment,
      mcl.mul(G2(), this.mask)
    );
  }
}

class AmountCommitmentKeyImage {
  constructor(masked_commitment, g_base, h_base) {
    if (!(masked_commitment instanceof MaskedAmountCommitment))
      throw new Error(`Argument 0 must be MaskedAmountCommitment`);

    this.keyImage = mcl.add(
      mcl.mul(h_base, masked_commitment.commitment.amount),
      mcl.mul(g_base, masked_commitment.commitment.mask)
    );

    const transcript = new Transcript();
    transcript.add(masked_commitment.masked_commitment.serialize());
    transcript.add(g_base.serialize());
    transcript.add(h_base.serialize());
    transcript.add(this.keyImage.serialize());

    this.x = new mcl.Fr();
    this.x.setBigEndianMod(transcript.getHash());

    let r = new mcl.Fr();
    r.setByCSPRNG();
  }
}

module.exports.AmountCommitment = AmountCommitment;
module.exports.MaskedAmountCommitment = MaskedAmountCommitment;
module.exports.AmountCommitmentKeyImage = AmountCommitmentKeyImage;
