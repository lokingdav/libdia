package io.github.lokingdav.libdia

object LibDia {
    init { System.loadLibrary("dia_jni") } // name of your .so

    // DH
    external fun dhKeygen(): Array<ByteArray> // [sk(Fr), pk(G1)]
    external fun dhComputeSecret(sk: ByteArray, peerPk: ByteArray): ByteArray // secret (G1)

    // VOPRF
    external fun voprfKeygen(): Array<ByteArray>             // [sk, pk]
    external fun voprfBlind(input: ByteArray): Array<ByteArray> // [blinded, blind]
    external fun voprfEvaluate(blinded: ByteArray, sk: ByteArray): ByteArray
    external fun voprfUnblind(element: ByteArray, blind: ByteArray): ByteArray
    external fun voprfVerify(input: ByteArray, Y: ByteArray, pk: ByteArray): Boolean
    external fun voprfVerifyBatch(inputs: Array<ByteArray>, Ys: Array<ByteArray>, pk: ByteArray): Boolean

    // AMF
    external fun amfKeygen(): Array<ByteArray>                       // [sk, pk]
    external fun amfFrank(skSender: ByteArray, pkReceiver: ByteArray, pkJudge: ByteArray, msg: ByteArray): ByteArray
    external fun amfVerify(pkSender: ByteArray, skReceiver: ByteArray, pkJudge: ByteArray, msg: ByteArray, sig: ByteArray): Boolean
    external fun amfJudge(pkSender: ByteArray, pkReceiver: ByteArray, skJudge: ByteArray, msg: ByteArray, sig: ByteArray): Boolean

    // BBS
    external fun bbsKeygen(): Array<ByteArray>                        // [sk, pk]
    external fun bbsSign(msgs: Array<ByteArray>, sk: ByteArray): Array<ByteArray> // [A, e]
    external fun bbsVerify(msgs: Array<ByteArray>, pk: ByteArray, A: ByteArray, e: ByteArray): Boolean
    external fun bbsCreateProof(
        msgs: Array<ByteArray>,
        discloseIdx1b: IntArray?,
        pk: ByteArray,
        A: ByteArray,
        e: ByteArray,
        nonce: ByteArray?
    ): ByteArray
    external fun bbsVerifyProof(
        disclosedIdx1b: IntArray?,
        disclosedMsgs: Array<ByteArray>?,
        pk: ByteArray,
        nonce: ByteArray?,
        proof: ByteArray
    ): Boolean
}
