use frost_dalek::{
    Parameters,
    Participant,
    DistributedKeyGeneration,
    SignatureAggregator,
    compute_message_hash,
    generate_commitment_share_lists
};

use rand::RngCore;

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
    let (carol_group_key, carol_secret_key) = carol_state
        .finish(carol.public_key().unwrap()).unwrap();

    // here we verify that all of the participants yield the same public key for the group
    assert!(alice_group_key == bob_group_key);
    assert!(carol_group_key == bob_group_key);

    let alice_public_key = alice_secret_key.to_public();
    let bob_public_key = bob_secret_key.to_public();
    let carol_public_key = carol_secret_key.to_public();
    
    
    let (alice_public_comshares, mut alice_secret_comshares) =
        generate_commitment_share_lists(&mut RngCore::next_u64(&mut self), 1, 1);
    let (bob_public_comshares, mut bob_secret_comshares) = 
        generate_commitment_share_lists(&mut RngCore::next_u64(&mut self), 2, 1);
    let (carol_public_comshares, mut carol_secret_comshares) = 
        generate_commitment_share_lists(&mut RngCore::next_u64(&mut self), 3, 1);

    let context = b"CONTEXT STRING STOLEN FROM DALEK TEST SUITE";
    let message = b"This is a test of the tsunami alert system. This is only a test.";

    let message_hash = compute_message_hash(&context[..], &message[..]);

    let mut aggregator = SignatureAggregator::new(params, bob_group_key.clone(), &context[..], &message[..]);
    aggregator.include_signer(1, alice_public_comshares.commitments[0], alice_public_key);
    aggregator.include_signer(2, bob_public_comshares.commitments[0], carol_public_key);

    let signers = aggregator.get_signers();

    let alice_partial = alice_secret_key.sign(&message_hash, &alice_group_key,
        &mut alice_secret_comshares, 0, signers).unwrap();
    let carol_partial = carol_secret_key.sign(&message_hash, &carol_group_key,
        &mut carol_secret_comshares, 0, signers).unwrap();

    aggregator.include_partial_signature(alice_partial);
    aggregator.include_partial_signature(carol_partial);


    let aggregator = aggregator.finalize().unwrap();
    let threshold_signature = aggregator.aggregate().unwrap();
    let verified = threshold_signature.verify(&alice_group_key, &message_hash).unwrap();



    /* println!("{:?}", alice_group_key);
    println!("{:?}", bob_group_key);
    println!("{:?}", carol_group_key); */
}
