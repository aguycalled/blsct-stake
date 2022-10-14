const { AmountCommitment } = require("../crypto/commitment");
const { GetBaseG1Element } = require("../crypto");

class Network {
  constructor() {
    this.lockedAmountCommitments = [];
    this.height = 0;
  }

  LockAmountCommitment(commitment) {
    if (!(commitment instanceof AmountCommitment))
      throw new Error(
        `Argument must be AmountCommitment, got ${typeof commitment}`
      );

    if (this.lockedAmountCommitments.indexOf(commitment) > -1)
      throw new Error("This amount commitment has already been locked");

    this.lockedAmountCommitments.push(commitment);
    this.lockedAmountCommitments.sort((a, b) => {
      return a.serializeToHexStr() < b.serializeToHexStr();
    });
  }

  GetBasesKeyImage(height = this.height) {
    return {
      G: GetBaseG1Element("G_key_image_height" + height),
      H: GetBaseG1Element("H_key_image_height" + height),
    };
  }
}

module.exports = Network;
