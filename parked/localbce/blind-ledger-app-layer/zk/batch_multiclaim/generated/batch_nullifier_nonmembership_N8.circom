pragma circom 2.2.0;
include "../batch_nullifier_nonmembership.circom";

component main { public [rootBefore, rootAfter, batchNullifierCommitment] } = BatchNullifierNonMembership(32, 8);
