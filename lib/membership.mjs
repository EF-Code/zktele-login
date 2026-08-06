import * as snarkjs from 'snarkjs';
import {
  PoseidonUtils,
  resolveArtifacts,
  loadVerificationKey,
} from 'zk-tele-auth/dist/sdk/index.js';

const hash = PoseidonUtils.hash;

const MEMBER_IDS = [1001, 2002, 3003, 4004];
const DEPTH = 12;
const SIZE = 2 ** DEPTH;

function buildTree() {
  const tree = [new Array(SIZE).fill(0n)];
  MEMBER_IDS.forEach((id, i) => {
    tree[0][i] = BigInt(hash([BigInt(id), 1n]));
  });
  for (let level = 1; level <= DEPTH; level++) {
    const prev = tree[level - 1];
    const next = new Array(prev.length / 2);
    for (let j = 0; j < next.length; j++) {
      next[j] = BigInt(hash([prev[2 * j], prev[2 * j + 1]]));
    }
    tree.push(next);
  }
  return tree;
}

const tree = buildTree();
const ROOT = tree[DEPTH][0].toString();
const MEMBER_COUNT = MEMBER_IDS.length;

function pathFor(index) {
  const pathElements = [];
  const pathIndices = [];
  let i = index;
  for (let level = 0; level < DEPTH; level++) {
    pathIndices.push(BigInt(i % 2));
    pathElements.push(tree[level][i % 2 === 0 ? i + 1 : i - 1]);
    i = Math.floor(i / 2);
  }
  return {
    root: ROOT,
    pathElements: pathElements.map(String),
    pathIndices: pathIndices.map(String),
  };
}

export function memberIndex(memberId) {
  return MEMBER_IDS.indexOf(Number(memberId));
}

export function inputFor(memberId) {
  const idx = memberIndex(memberId);
  const isMember = idx !== -1;
  const atIndex = isMember ? idx : SIZE - 1;
  return {
    leaf: BigInt(hash([BigInt(memberId), 1n])).toString(),
    root: ROOT,
    pathElements: pathFor(atIndex).pathElements,
    pathIndices: pathFor(atIndex).pathIndices,
    isMember,
  };
}

export async function generateMembershipProof(memberId) {
  const input = inputFor(memberId);
  const { wasm, zkey } = await resolveArtifacts('membership');
  const { proof, publicSignals } = await snarkjs.groth16.fullProve(
    {
      leaf: input.leaf,
      root: input.root,
      pathElements: input.pathElements,
      pathIndices: input.pathIndices,
    },
    wasm,
    zkey
  );
  return {
    proofPayload: { proof, publicSignals },
    leaf: input.leaf,
    root: input.root,
    isMember: publicSignals[0] === '1',
  };
}

export async function verifyMembershipProof(proofPayload) {
  const fail = (error) => ({ isValid: false, isMember: false, error });
  if (!proofPayload || !proofPayload.proof || !Array.isArray(proofPayload.publicSignals)) {
    return fail('malformed proof payload');
  }
  if (proofPayload.publicSignals.length !== 3) {
    return fail(`expected 3 public signals, got ${proofPayload.publicSignals.length}`);
  }
  const verificationKey = await loadVerificationKey('membership');
  const ok = await snarkjs.groth16.verify(
    verificationKey,
    proofPayload.publicSignals,
    proofPayload.proof
  );
  if (!ok) return fail('groth16 verification failed');
  const [isMember, leaf, root] = proofPayload.publicSignals;
  if (isMember !== '1') return fail('leaf is not on the allowlist (isMember=0)');
  if (root !== ROOT) return fail('proof is for a different allowlist root');
  return { isValid: true, isMember: true, leaf, root };
}

export { ROOT, MEMBER_COUNT, MEMBER_IDS };
