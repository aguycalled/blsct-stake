const mcl = require("@aguycalled/mcl-wasm");
const Operations = require("./operations");

let initialised = false;

let G, G2, H, U, U2;
let Hi = [];
let Gi = [];

module.exports.G = () => G;
module.exports.G2 = () => G2;
module.exports.H = () => H;
module.exports.U = () => U;
module.exports.U2 = () => U2;
module.exports.Hi = () => Hi;
module.exports.Gi = () => Gi;

let GetBaseG1Element = (idx) => {
  if (!module.exports.G()) return;
  let toHash = module.exports.G().serializeToHexStr() + String(idx);

  const transcript = new Operations.Transcript();
  transcript.add(Buffer.from(toHash, "utf8"));

  let hash = transcript.getHash();
  let d = new mcl.Fp();
  d.setLittleEndianMod(hash);
  mcl.setMapToMode(0);
  let g = d.mapToG1();
  mcl.setMapToMode(5);
  return g;
};

module.exports.GetBaseG1Element = GetBaseG1Element;

module.exports.Init = async () => {
  try {
    if (initialised) return;

    await mcl.init(mcl.BLS12_381);

    mcl.setETHserialization(true); // Ethereum serialization

    G = mcl.deserializeHexStrToG1(
      "97f1d3a73197d7942695638c4fa9ac0fc3688c4f9774b905a14e3a3f171bac586c55e83ff97a1aeffb3af00adb22c6bb"
    );

    H = GetBaseG1Element("H");
    G2 = GetBaseG1Element("G2");
    U = GetBaseG1Element("U");
    U2 = GetBaseG1Element("U2");

    Hi = new Array(1024);
    Gi = new Array(1024);

    for (let i = 0; i < 1024; i++) {
      Hi[i] = GetBaseG1Element("H_" + i);
      Gi[i] = GetBaseG1Element("G_" + i);
    }

    Operations.Init();

    initialised = true;
  } catch (e) {
    console.error(e);
  }
};
