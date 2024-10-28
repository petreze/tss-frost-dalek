use frost_dalek::{
    Parameters,
    Participant,
    DistributedKeyGeneration,
    SignatureAggregator,
    compute_message_hash,
    generate_commitment_share_lists
};

use rand::rngs::OsRng;

const NUM_SHARES: u32 = 3;
const THRESHOLD: u32 = 2;

fn main() {


    let params = Parameters { t: THRESHOLD, n: NUM_SHARES };

    let (alice, alice_coefficients) = Participant::new(&params, 1);
    let (bob, bob_coefficients) = Participant::new(&params, 2);
    let (carol, carol_coefficients) = Participant::new(&params, 3);

    let mut alice_other_participants: Vec<Participant> = vec![bob.clone(), carol.clone()];
    let alice_state = DistributedKeyGeneration::<_>::new(&params, &alice.index, &alice_coefficients,
                                                         &mut alice_other_participants).unwrap();

    let alice_their_secret_shares = alice_state.their_secret_shares().unwrap();

    
    let mut bob_other_participants: Vec<Participant> = vec![alice.clone(), carol.clone()];
    let bob_state = DistributedKeyGeneration::<_>::new(&params, &bob.index, &bob_coefficients,
                                                   &mut bob_other_participants).unwrap();

    let bob_their_secret_shares = bob_state.their_secret_shares().unwrap();

    let mut carol_other_participants: Vec<Participant> = vec![alice.clone(), bob.clone()];
    let carol_state = DistributedKeyGeneration::<_>::new(&params, &carol.index, &carol_coefficients,
                                                     &mut carol_other_participants).unwrap();

    let carol_their_secret_shares = carol_state.their_secret_shares().unwrap();



    let alice_my_secret_shares = vec![bob_their_secret_shares[0].clone(),
                                  carol_their_secret_shares[0].clone()];
    let bob_my_secret_shares = vec![alice_their_secret_shares[0].clone(),
                                carol_their_secret_shares[1].clone()];
    let carol_my_secret_shares = vec![alice_their_secret_shares[1].clone(),
                                  bob_their_secret_shares[1].clone()];


    // ROUND 2
    let alice_state = alice_state.to_round_two(alice_my_secret_shares).unwrap();
    let bob_state = bob_state.to_round_two(bob_my_secret_shares).unwrap();
    let carol_state = carol_state.to_round_two(carol_my_secret_shares).unwrap();


    let (alice_group_key, alice_secret_key) = alice_state
        .finish(alice.public_key().unwrap()).unwrap();
    let (bob_group_key, bob_secret_key) = bob_state
        .finish(bob.public_key().unwrap()).unwrap();
    let (carol_group_key, _carol_secret_key) = carol_state
        .finish(carol.public_key().unwrap()).unwrap();

    // Here we verify that all of the participants yield the same public key for the group
    assert!(alice_group_key == bob_group_key);
    assert!(carol_group_key == bob_group_key);

    let alice_public_key = alice_secret_key.to_public();
    let bob_public_key = bob_secret_key.to_public();
    
    
    let (alice_public_comshares, mut alice_secret_comshares) =
        generate_commitment_share_lists(&mut OsRng, 1, 1);
    let (bob_public_comshares, mut bob_secret_comshares) = 
        generate_commitment_share_lists(&mut OsRng, 2, 1);
    let (_carol_public_comshares, mut _carol_secret_comshares) = 
        generate_commitment_share_lists(&mut OsRng, 3, 1);

    let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
    let message = b"This is a test of the tsunami alert system. This is only a test.";

    let message_hash = compute_message_hash(&context[..], &message[..]);

    let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
    aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
    aggregator.include_signer(2, bob_public_comshares.commitments[0], bob_public_key);

    let signers = aggregator.get_signers();

    // Alice and Bob sign the message with their private keys.
    let alice_partial = alice_secret_key.sign(&message_hash, &alice_group_key,
        &mut alice_secret_comshares, 0, signers).unwrap();
    let bob_partial = bob_secret_key.sign(&message_hash, &bob_group_key,
        &mut bob_secret_comshares, 0, signers).unwrap();

    // Add Alice's and Bob's partial signatures to the aggregator.
    aggregator.include_partial_signature(alice_partial);
    aggregator.include_partial_signature(bob_partial);

    // Build the ThresholdSignature containing the partial signatures of both parties.
    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();

    // Verify that the message is signed with the threshold of this setup. In this scenario, a 2/3 signature is expected.
    let verified = threshold_signature.verify(&alice_group_key, &message_hash).unwrap();



    println!("{:?}", verified);

}
