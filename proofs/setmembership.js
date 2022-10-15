const mcl = require("@aguycalled/mcl-wasm");
const {
  AmountCommitment,
  AmountCommitmentKeyImage,
} = require("../crypto/commitment");
const {
  one,
  VectorCommitment,
  VectorScalar,
  Hadamard,
  InnerProduct,
  Transcript,
  VectorSubtract,
  VectorPowers,
  twoN,
  VectorAdd,
  VectorAddSingle,
  VectorSlice,
  HadamardFold,
  CrossVectorExponent,
  oneN,
  VectorDup,
} = require("../crypto/operations");
const { G2, Hi, G, H, Gi } = require("../crypto");

class SetMembershipProof {
  constructor(amount_commitment, locked_amount_commitments, bases_key_image) {
    if (!(amount_commitment instanceof AmountCommitment))
      throw new Error(`Argument 0 must be AmountCommitment`);

    if (
      locked_amount_commitments.length === 0 ||
      locked_amount_commitments.filter((a) => !(a instanceof AmountCommitment))
        .length > 0
    )
      throw new Error(
        `Argument 1 must be an array of elements of AmountCommitment type`
      );

    if (
      !(
        bases_key_image.G instanceof mcl.G1 &&
        bases_key_image.H instanceof mcl.G1
      )
    )
      throw new Error(`Argument 2 must have elements G and H of type G1`);

    let amount_commitment_pos =
      locked_amount_commitments.indexOf(amount_commitment);

    if (amount_commitment_pos === -1)
      throw new Error(`amount_commitment is not a locked amount commitment`);

    let n = locked_amount_commitments.length;

    let bL = new Array(n);
    let bR = new Array(n);

    for (let i = 0; i < n; i++) {
      bL[i] = i == amount_commitment_pos ? one() : new mcl.Fr();
      bR[i] = mcl.sub(bL[i], one());
    }

    let masked_commitment = amount_commitment.GetMaskedAmountCommitment();
    this.A1 = masked_commitment.masked_commitment;
    this.U = new AmountCommitmentKeyImage(
      masked_commitment,
      bases_key_image.G,
      bases_key_image.H
    );

    let alpha = masked_commitment.mask;
    let alpha2 = masked_commitment.commitment.mask;
    let beta = new mcl.Fr();
    beta.setByCSPRNG();
    let rho = new mcl.Fr();
    rho.setByCSPRNG();
    let r_alpha1 = new mcl.Fr();
    r_alpha1.setByCSPRNG();
    let r_alpha2 = new mcl.Fr();
    r_alpha2.setByCSPRNG();
    let r_sk = new mcl.Fr();
    r_sk.setByCSPRNG();

    let sL = new Array(n);
    let sR = new Array(n);

    for (let i = 0; i < n; i++) {
      sL[i] = new mcl.Fr();
      sL[i].setByCSPRNG();
      sR[i] = new mcl.Fr();
      sR[i].setByCSPRNG();
    }

    this.A2 = mcl.add(mcl.mul(G2(), beta), InnerProduct(Hi().slice(0, n), bR));
    this.S1 = mcl.add(
      mcl.mul(G2(), r_alpha1),
      mcl.add(mcl.mul(G(), r_alpha2), mcl.mul(H(), r_sk))
    );
    this.S2 = mcl.add(
      mcl.mul(G2(), rho),
      mcl.add(
        InnerProduct(
          locked_amount_commitments.map((el) => el.commitment),
          sL
        ),
        InnerProduct(Hi().slice(0, n), sR)
      )
    );
    this.S3 = mcl.add(
      mcl.mul(bases_key_image.G, r_alpha2),
      mcl.mul(bases_key_image.H, r_sk)
    );

    let { transcript, y, z, w } = this.CalculateYZW(locked_amount_commitments);

    let l0 = VectorSubtract(bL, z);
    let l1 = sL.slice();

    let zs = new Array(n);
    let zsq = mcl.mul(z, z);
    zs.fill(zsq);

    let yN = VectorPowers(y, n);
    let r0 = VectorAdd(
      Hadamard(VectorAddSingle(VectorScalar(bR, w), mcl.mul(w, z)), yN),
      zs
    );

    let r1 = Hadamard(yN, sR);

    let t1 = mcl.add(InnerProduct(l0, r1), InnerProduct(l1, r0));
    let t2 = InnerProduct(l1, r1);

    let tau1 = new mcl.Fr();
    tau1.setByCSPRNG();

    let tau2 = new mcl.Fr();
    tau2.setByCSPRNG();

    this.T1 = mcl.add(mcl.mul(G(), t1), mcl.mul(H(), tau1));
    this.T2 = mcl.add(mcl.mul(G(), t2), mcl.mul(H(), tau2));

    let x = this.CalculateX(transcript, w);

    this.l = VectorAdd(l0, VectorScalar(l1, x));
    this.r = VectorAdd(r0, VectorScalar(r1, x));

    this.taux = mcl.add(mcl.mul(tau1, x), mcl.mul(tau2, mcl.mul(x, x)));
    this.mu = mcl.add(mcl.add(mcl.mul(x, rho), mcl.mul(beta, w)), alpha);
    this.t = InnerProduct(this.l, this.r);
    this.z_alpha1 = mcl.add(r_alpha1, mcl.mul(alpha, x));
    this.z_alpha2 = mcl.add(r_alpha2, mcl.mul(alpha2, x));
    this.z_sk = mcl.add(r_sk, mcl.mul(amount_commitment.amount, x));

    /*transcript.add(x.serialize());
    transcript.add(this.taux.serialize());
    transcript.add(this.mu.serialize());
    transcript.add(this.t.serialize());
    transcript.add(this.z_alpha1.serialize());
    transcript.add(this.z_alpha2.serialize());

    let x_ip = new mcl.Fr();
    x_ip.setBigEndianMod(transcript.getHash());

    if (x_ip.isZero()) throw new Error(`x_ip equals zero`);

    let nprime = n;

    let gprime = [];
    let hprime = [];
    let aprime = [];
    let bprime = [];

    let yinv = mcl.inv(y);

    let yinvpow = [];

    yinvpow[0] = mcl.deserializeHexStrToFr(one().serializeToHexStr());
    yinvpow[1] = mcl.deserializeHexStrToFr(yinv.serializeToHexStr());

    for (var i = 0; i < nprime; i++) {
      gprime[i] = Gi()[i];
      hprime[i] = Hi()[i];

      if (i > 1) yinvpow[i] = mcl.mul(yinvpow[i - 1], yinv);

      aprime[i] = mcl.deserializeHexStrToFr(l[i].serializeToHexStr());
      bprime[i] = mcl.deserializeHexStrToFr(r[i].serializeToHexStr());
    }

    this.L = [];
    this.R = [];

    let round = 0;
    let w = [];

    let scale = yinvpow.slice();

    while (nprime > 1) {
      // PAPER LINE 20
      nprime = parseInt(nprime / 2);

      // PAPER LINES 21-22
      let cL = InnerProduct(
        VectorSlice(aprime, 0, nprime),
        VectorSlice(bprime, nprime, bprime.length)
      );

      let cR = InnerProduct(
        VectorSlice(aprime, nprime, aprime.length),
        VectorSlice(bprime, 0, nprime)
      );

      // PAPER LINES 23-24
      this.L[round] = CrossVectorExponent(
        nprime,
        gprime,
        nprime,
        hprime,
        0,
        aprime,
        0,
        bprime,
        nprime,
        scale,
        H(),
        mcl.mul(cL, x_ip)
      );
      proof.R[round] = CrossVectorExponent(
        nprime,
        gprime,
        0,
        hprime,
        nprime,
        aprime,
        nprime,
        bprime,
        0,
        scale,
        H(),
        mcl.mul(cR, x_ip)
      );

      // PAPER LINES 25-27
      transcript.add(this.L[round].serialize());
      transcript.add(this.R[round].serialize());

      w[round] = new mcl.Fr();
      w[round].setBigEndianMod(transcript.getHash());

      if (w[round].isZero()) continue;

      let winv = mcl.inv(w[round]);

      // PAPER LINES 29-31
      if (nprime > 1) {
        gprime = HadamardFold(gprime, undefined, winv, w[round]);
        hprime = HadamardFold(hprime, scale, w[round], winv);
      }

      // PAPER LINES 33-34
      aprime = VectorAdd(
        VectorScalar(VectorSlice(aprime, 0, nprime), w[round]),
        VectorScalar(VectorSlice(aprime, nprime, aprime.length), winv)
      );

      bprime = VectorAdd(
        VectorScalar(VectorSlice(bprime, 0, nprime), winv),
        VectorScalar(VectorSlice(bprime, nprime, bprime.length), w[round])
      );

      scale = undefined;

      round += 1;
    }

    this.a = aprime[0];
    this.b = bprime[0];*/
  }

  Verify(locked_amount_commitments, bases_key_image) {
    if (!InnerProduct(this.l, this.r).isEqual(this.t))
      throw new Error("InnerProduct failed");

    let { transcript, y, z, w } = this.CalculateYZW(locked_amount_commitments);
    let x = this.CalculateX(transcript, w);

    if (
      !mcl
        .add(
          mcl.mul(G2(), this.z_alpha1),
          mcl.add(mcl.mul(G(), this.z_alpha2), mcl.mul(H(), this.z_sk))
        )
        .isEqual(mcl.add(this.S1, mcl.mul(this.A1, x)))
    )
      throw new Error("SecretKnowledgeProof failed");

    if (
      !mcl
        .add(
          mcl.mul(bases_key_image.G, this.z_alpha2),
          mcl.mul(bases_key_image.H, this.z_sk)
        )
        .isEqual(mcl.add(this.S3, mcl.mul(this.U.keyImage, x)))
    )
      throw new Error("KeyImageProof failed");

    let n = locked_amount_commitments.length;
    let yPowers = VectorPowers(y, n);

    let line10LHS = mcl.add(mcl.mul(G(), this.t), mcl.mul(H(), this.taux));
    let line10RHS = mcl.add(
      mcl.mul(
        G(),
        mcl.sub(
          mcl.add(
            mcl.mul(z, z),
            mcl.mul(
              mcl.mul(w, mcl.sub(z, mcl.mul(z, z))),
              InnerProduct(oneN().slice(0, n), yPowers)
            )
          ),
          mcl.mul(
            mcl.mul(z, mcl.mul(z, z)),
            InnerProduct(oneN().slice(0, n), oneN().slice(0, n))
          )
        )
      ),
      mcl.add(mcl.mul(this.T1, x), mcl.mul(this.T2, mcl.mul(x, x)))
    );

    if (!line10RHS.isEqual(line10LHS)) throw new Error("Line 10 check fails");

    let line11LHS = mcl.add(
      mcl.mul(G2(), this.mu),
      mcl.add(
        InnerProduct(Hi().slice(0, n), this.r),
        InnerProduct(
          locked_amount_commitments.map((el) => el.commitment),
          this.l
        )
      )
    );

    let line11RHS = mcl.add(
      mcl.add(
        mcl.add(mcl.add(this.A1, mcl.mul(this.A2, w)), mcl.mul(this.S2, x)),
        InnerProduct(
          locked_amount_commitments.map((el) => el.commitment),
          VectorDup(mcl.neg(z), n)
        )
      ),
      InnerProduct(
        Hi().slice(0, n),
        VectorAdd(
          VectorScalar(VectorPowers(y, n), mcl.mul(w, z)),
          VectorDup(mcl.mul(z, z), n)
        )
      )
    );

    if (!line11RHS.isEqual(line11LHS)) throw new Error("Line 11 check fails");
  }

  CalculateX(transcript, w) {
    transcript.add(w.serialize());
    transcript.add(this.T1.serialize());
    transcript.add(this.T2.serialize());

    let x = new mcl.Fr();
    x.setBigEndianMod(transcript.getHash());
    return x;
  }

  CalculateYZW(locked_amount_commitments) {
    let y = new mcl.Fr();
    let z = new mcl.Fr();
    let w = new mcl.Fr();

    const transcript = new Transcript();

    for (let ac of locked_amount_commitments) {
      transcript.add(ac.commitment.serialize());
    }

    transcript.add(this.A1.serialize());
    transcript.add(this.A2.serialize());
    transcript.add(this.S1.serialize());
    transcript.add(this.S2.serialize());

    y.setBigEndianMod(transcript.getHash());

    if (y.isZero()) throw new Error(`y equals zero`);

    transcript.add(y.serialize());

    z.setBigEndianMod(transcript.getHash());

    if (z.isZero()) throw new Error(`z equals zero`);

    transcript.add(z.serialize());

    w.setBigEndianMod(transcript.getHash());

    if (w.isZero()) throw new Error(`w equals zero`);
    return { transcript, y, z, w };
  }
}

module.exports = SetMembershipProof;
