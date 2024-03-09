package ch.bfh.vcbbs;

import ch.bfh.p2bbs.Types.OctetString;
import ch.bfh.p2bbs.Types.Scalar;
import ch.bfh.p2bbs.key.KeyGen;
import ch.bfh.p2bbs.proof.ProofGen;
import ch.bfh.p2bbs.proof.ProofVerify;
import ch.bfh.p2bbs.signature.Sign;
import ch.bfh.p2bbs.signature.SignVerify;
import ch.openchvote.util.sequence.Vector;
import ch.openchvote.util.set.IntSet;

public class MainTest {
    public static void main(String[] args) {
        OctetString key_material = new OctetString(new byte[256]);
        OctetString key_info = new OctetString(new byte[0]);
        OctetString key_dst = new OctetString(new byte[0]);
        Scalar secretKey = KeyGen.KeyGen(key_material,key_info,key_dst);
        System.out.println("Secret Key:    " + secretKey.toString());
        OctetString publicKey = KeyGen.SkToPk(secretKey);
        System.out.println("Public Key:    " + publicKey); // as hex

        // Generate and validate the Signature
        OctetString msg1 = OctetString.valueOf("Hello");
        OctetString msg2 = OctetString.valueOf("BBS");
        OctetString msg3 = OctetString.valueOf("test");
        Vector<OctetString> messages = Vector.of(msg1);
        Vector<OctetString> empty = Vector.of();


        OctetString header = new OctetString(new byte[0]);
        OctetString ph = new OctetString(new byte[0]);
        OctetString signature = Sign.Sign(secretKey, publicKey, header, messages);
        System.out.println("Signature:   " + signature.toString());
        boolean result = SignVerify.Verify(publicKey, signature, header, messages);
        System.out.println("Signature is:   " + result);

        // Generate and verify the Proof
        var disclosed_indexes_test = IntSet.of(1);
        Vector<OctetString> disclosedMessages = messages.select(disclosed_indexes_test);//Vector.of(msg1, msg3);
        Vector<Integer> disclosed_indexes = Vector.of(1);
        Vector<Integer> disclosed_indexes_empty = Vector.of();
        OctetString proof = ProofGen.ProofGen(publicKey, signature, header, ph, disclosedMessages, disclosed_indexes);
        System.out.println("Proof:   " + proof.toString());
        boolean proofValid = ProofVerify.ProofVerify(publicKey, proof, header, ph, disclosedMessages, disclosed_indexes);
        System.out.println("Proof is:   " + proofValid);
    }
}
