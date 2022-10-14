const Hash = require("./hash");
const mcl = require("@aguycalled/mcl-wasm");
const RangeProof = require("../proofs/rangeproof");
const Operations = require("./operations");

let zero, one, two, oneN, twoN, ip12;

module.exports.zero = () => zero;
module.exports.one = () => one;
module.exports.two = () => two;
module.exports.oneN = () => oneN;
module.exports.twoN = () => twoN;
module.exports.ip12 = () => ip12;

const Init = () => {
  zero = new mcl.Fr();
  one = new mcl.Fr();
  two = new mcl.Fr();

  zero.setInt(0);
  one.setInt(1);
  two.setInt(2);

  oneN = Operations.VectorDup(one, RangeProof.maxN);
  twoN = Operations.VectorPowers(two, RangeProof.maxN);
  ip12 = Operations.InnerProduct(oneN, twoN);
};

module.exports.Init = Init;

const VectorDup = (x, n) => {
  let ret = [];

  for (var i = 0; i < n; i++) {
    ret.push(x);
  }

  return ret;
};

module.exports.VectorDup = VectorDup;

const InnerProduct = (a, b) => {
  if (a.length != b.length)
    throw new Error(`InnerProduct: lengths do not match`);

  let res = new mcl.Fr();

  for (var i = 0; i < a.length; ++i) {
    if (i == 0) res = mcl.mul(a[i], b[i]);
    else res = mcl.add(res, mcl.mul(a[i], b[i]));
  }

  return res;
};

module.exports.InnerProduct = InnerProduct;

const VectorPowers = (x, n) => {
  let res = [];

  if (n == 0) return res;

  res[0] = one;

  if (n == 1) return res;

  res[1] = x;

  for (var i = 2; i < n; ++i) {
    res[i] = mcl.mul(res[i - 1], x);
  }

  return res;
};

module.exports.VectorPowers = VectorPowers;

module.exports.VectorPowerSum = (x, n) => {
  let res = VectorPowers(x, n);
  let ret = new mcl.Fr();

  for (var i in res) {
    let it = res[i];
    ret = mcl.add(ret, it);
  }

  return ret;
};

module.exports.VectorCommitment = (a, b) => {
  if (a.length != b.length)
    throw new Error(`VectorCommitment: lengths do not match`);

  let bases = [];
  let exps = [];

  for (var i = 0; i < a.length; ++i) {
    bases.push(Gi[i]);
    bases.push(Hi[i]);
    exps.push(a[i]);
    exps.push(b[i]);
  }

  return mcl.mulVec(bases, exps);
};

module.exports.VectorSubtract = (a, b) => {
  let ret = [];

  for (var i = 0; i < a.length; i++) {
    ret[i] = mcl.sub(a[i], b);
  }

  return ret;
};

module.exports.VectorAdd = (a, b) => {
  if (a.length != b.length)
    throw new Error(`InnerProduct: lengths do not match`);

  let ret = [];

  for (var i = 0; i < a.length; i++) {
    ret[i] = mcl.add(a[i], b[i]);
  }

  return ret;
};

module.exports.VectorAddSingle = (a, b) => {
  let ret = [];

  for (var i = 0; i < a.length; i++) {
    ret[i] = mcl.add(a[i], b);
  }

  return ret;
};

module.exports.VectorScalar = (a, b) => {
  let ret = [];

  for (var i = 0; i < a.length; i++) {
    ret[i] = mcl.mul(a[i], b);
  }

  return ret;
};

module.exports.Hadamard = (a, b) => {
  if (a.length != b.length) throw new Error(`Hadamard: lengths do not match`);

  let ret = [];

  for (var i = 0; i < a.length; i++) {
    ret[i] = mcl.mul(a[i], b[i]);
  }

  return ret;
};

module.exports.VectorSlice = (a, start, stop) => {
  if (!(start <= a.length && stop <= a.length && start >= 0 && stop >= 0))
    throw new Error(`VectorSlice: wrong indexes`);

  let ret = [];

  for (var i = start; i < stop; i++) {
    ret[i - start] = a[i];
  }

  return ret;
};

module.exports.HadamardFold = (vec, scale, a, b) => {
  if ((vec.length & 1) != 0)
    throw new Error(`HadamardFold: Vector lenfth must be multiple of 2`);

  let sz = parseInt(vec.length / 2);
  let out = [];

  for (var n = 0; n < sz; ++n) {
    let c0 = vec[n];
    let c1 = vec[sz + n];
    let sa, sb;
    if (scale) sa = mcl.mul(a, scale[n]);
    else sa = a;
    if (scale) sb = mcl.mul(b, scale[sz + n]);
    else sb = b;
    let l = mcl.mul(c0, sa);
    let r = mcl.mul(c1, sb);
    out[n] = mcl.add(l, r);
  }

  return out;
};

module.exports.CrossVectorExponent = (
  size,
  A,
  Ao,
  B,
  Bo,
  a,
  ao,
  b,
  bo,
  scale,
  extra_point,
  extra_scalar
) => {
  /*assert(size + Ao <= A.length);

  assert(size + Bo <= B.length);

  assert(size + ao <= a.length);

  assert(size + bo <= b.length);

  assert(size <= maxMN);

  assert(!scale || size == parseInt(scale.length / 2));

  assert(!!extra_point == !!extra_scalar);*/

  let bases = [];
  let exps = [];

  for (var i = 0; i < size; ++i) {
    exps[i * 2] = a[ao + i];
    bases[i * 2] = A[Ao + i];
    exps[i * 2 + 1] = b[bo + i];

    if (scale) exps[i * 2 + 1] = mcl.mul(exps[i * 2 + 1], scale[Bo + i]);

    bases[i * 2 + 1] = B[Bo + i];
  }
  if (extra_point) {
    bases.push(extra_point);
    exps.push(extra_scalar);
  }

  return mcl.mulVec(bases, exps);
};

const bytesArray = (n) => {
  let buf = new Buffer(
    (n.toString(16).length % 2 ? "0" : "") + n.toString(16),
    "hex"
  );

  let a = [];

  for (var i = 0; i < buf.length; i++) {
    a.push(buf.readUInt8(i));
  }

  while (a.length != 8) {
    a.unshift(0);
  }

  return new Uint8Array(a);
};

module.exports.bytesArray = bytesArray;

const CombineUint8Array = (arrays) => {
  // sum of individual array lengths
  let totalLength = arrays.reduce((acc, value) => acc + value.length, 0);
  if (!arrays.length) return null;

  let result = new Uint8Array(totalLength);

  // for each array - copy it over result
  // next array is copied right after the previous one
  let length = 0;
  for (let array of arrays) {
    result.set(array, length);
    length += array.length;
  }

  return result;
};

module.exports.CombineUint8Array = CombineUint8Array;

module.exports.HashG1Element = (el, salt) => {
  let elSer = el.serialize();

  let ret = CombineUint8Array([
    new Uint8Array([elSer.length]),
    new Uint8Array(elSer),
    bytesArray(salt).reverse(),
  ]);

  return new Uint8Array(Hash.sha256sha256(new Buffer(ret)).buffer);
};

class Transcript {
  constructor() {
    this.reset();
  }

  reset() {
    this.data = [];
    this.bytes = 0;

    return this;
  }

  add(p, addlength = true) {
    if (!p) return this;
    if (addlength) this.data.push(new Uint8Array([p.length]));
    this.data.push(p);

    this.bytes += p.length + addlength;

    return this;
  }

  finalize() {
    let pad = Buffer.alloc(64);
    pad.writeUInt8(0x80, 0);
    pad = pad.slice(0, 1 + ((119 - (this.bytes % 64)) % 64));

    let size = Buffer.alloc(8);
    size.writeUInt32BE(this.bytes << 3, 4);

    this.add(pad, false);
    this.add(size, false);
  }

  compressData() {
    return ((arrays) => {
      // sum of individual array lengths
      let totalLength = arrays.reduce((acc, value) => acc + value.length, 0);
      if (!arrays.length) return null;

      let result = new Uint8Array(totalLength);

      // for each array - copy it over result
      // next array is copied right after the previous one
      let length = 0;
      for (let array of arrays) {
        result.set(array, length);
        length += array.length;
      }

      return result;
    })(this.data);
  }

  getHash() {
    let compressed = this.compressData();
    let first = Hash.sha256(compressed);

    this.reset();
    this.add(first, false);

    compressed = this.compressData();

    let second = Hash.sha256(compressed);

    this.finalize();

    return new Uint8Array(second.buffer);
  }
}

module.exports.Transcript = Transcript;

const Delta = (yn, z) => {
  const left = mcl.mul(mcl.sub(z, mcl.mul(z, z)), InnerProduct(oneN, yn));
  const right = mcl.mul(mcl.mul(z, mcl.mul(z, z)), ip12);
  const result = mcl.sub(left, right);
  return result;
};

module.exports.Delta = Delta;
