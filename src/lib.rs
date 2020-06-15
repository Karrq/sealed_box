use blake2::{
    digest::{Update, VariableOutput},
    VarBlake2b,
};
use crypto_box::{
    aead::{self, Aead},
    SalsaBox,
};

//re-export keys
pub use crypto_box::{PublicKey, SecretKey};

const BOX_NONCELENGTH: usize = 24;
const BOX_OVERHEAD: usize = 16;

//32 = PublicKey length
const SEALED_OVERHEAD: usize = 32 + BOX_OVERHEAD;

///generate the nonce for the given public keys
///
/// nonce = Blake2b(ephemeral_pk||target_pk)
/// nonce_length = 24
fn get_nonce(ephemeral_pk: &PublicKey, target_pk: &PublicKey) -> [u8; BOX_NONCELENGTH] {
    let mut hasher = VarBlake2b::new(BOX_NONCELENGTH).unwrap();

    hasher.update(ephemeral_pk.as_bytes());
    hasher.update(target_pk.as_bytes());

    let out = hasher.finalize_boxed();

    let mut array = [0u8; BOX_NONCELENGTH];
    array.copy_from_slice(&out);

    array
}

///encrypts the given buffer for the given public key
///
/// overhead = 48 = (32 ephemeral_pk||16 box_overhead)
pub fn seal(data: &[u8], pk: &PublicKey) -> Vec<u8> {
    let mut out = Vec::with_capacity(SEALED_OVERHEAD + data.len());

    let ep_sk = SecretKey::generate(&mut rand::thread_rng());
    let ep_pk = ep_sk.public_key();
    out.extend_from_slice(ep_pk.as_bytes());

    let nonce = get_nonce(&ep_pk, &pk);
    let nonce = aead::generic_array::GenericArray::from_slice(&nonce);

    let salsabox = SalsaBox::new(&pk, &ep_sk);
    let encrypted = salsabox.encrypt(&nonce, &data[..]).unwrap();

    out.extend_from_slice(&encrypted);
    out
}

///attempt to decrypt the given ciphertext with the given secret key
/// will fail if the secret key doesn't match the public key used to encrypt the payload
pub fn open(ciphertext: &[u8], sk: &SecretKey) -> Option<Vec<u8>> {
    let pk = sk.public_key();

    let ephemeral_pk = {
        let bytes = &ciphertext[..32];
        let mut array = [0u8; 32];
        array.copy_from_slice(&bytes);
        array.into()
    };

    let nonce = get_nonce(&ephemeral_pk, &pk);
    let nonce = aead::generic_array::GenericArray::from_slice(&nonce);

    let encrypted = &ciphertext[32..];
    let salsabox = SalsaBox::new(&ephemeral_pk, &sk);

    salsabox.decrypt(&nonce, &encrypted[..]).ok()
}

#[cfg(test)]
mod tests {
    use super::*;
    use crypto_box::{SalsaBox, SecretKey};

    const TEST_PAYLOAD: &[u8; 15] = b"sealed_box test";

    #[test]
    fn try_nonce() {
        use sodiumoxide::crypto::box_::Nonce;

        //ephemeral
        let alice = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        //target
        let bob = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        let nonce = get_nonce(&alice.0, &bob.0);
        let sodium_nonce = Nonce::from_slice(&nonce).unwrap();

        assert_eq!(&sodium_nonce[..], &nonce[..])
    }

    #[test]
    fn try_box() {
        use sodiumoxide::crypto::box_::{
            seal as bs_seal, Nonce, PublicKey as SodiumPKey, SecretKey as SodiumSKey,
        };

        //ephemeral
        let alice = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        //target
        let bob = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        //generate nonce
        let nonce = get_nonce(&alice.0, &bob.0);
        let sodium_nonce = Nonce::from_slice(&nonce).unwrap();

        //encrypt message with crypto_box
        let salsabox = SalsaBox::new(&bob.0, &alice.1);
        let encrypted = salsabox
            .encrypt(
                &aead::generic_array::GenericArray::from_slice(&nonce),
                &TEST_PAYLOAD[..],
            )
            .unwrap();

        //encrypt message with sodiumoxide::box_
        let sbob_pkey = SodiumPKey::from_slice(bob.0.as_bytes()).unwrap();
        let salice_skey = SodiumSKey::from_slice(&alice.1.to_bytes()).unwrap();
        let sencrypted = bs_seal(&TEST_PAYLOAD[..], &sodium_nonce, &sbob_pkey, &salice_skey);

        assert_eq!(sencrypted, encrypted);
    }

    #[test]
    fn try_full() {
        use sodiumoxide::crypto::box_::{PublicKey as SodiumPKey, SecretKey as SodiumSKey};
        use sodiumoxide::crypto::sealedbox::{open as sopen, seal as sseal};

        let bob = {
            let sk = SecretKey::generate(&mut rand::thread_rng());
            (sk.public_key(), sk)
        };

        let sbob = {
            (
                SodiumPKey::from_slice(bob.0.as_bytes()).unwrap(),
                SodiumSKey::from_slice(&bob.1.to_bytes()).unwrap(),
            )
        };

        //seal and open local
        let encrypted = seal(&TEST_PAYLOAD[..], &bob.0);
        let decrypted = open(&encrypted, &bob.1).unwrap();
        assert_eq!(&decrypted, &TEST_PAYLOAD);

        //sodiumoxide open local seal
        let sopen_rust = sopen(&encrypted, &sbob.0, &sbob.1).unwrap();
        assert_eq!(&sopen_rust, &TEST_PAYLOAD);

        //local open sodiumoxide seal
        let sencrypted = sseal(&TEST_PAYLOAD[..], &sbob.0);
        let open_sodium = open(&sencrypted, &bob.1).unwrap();
        assert_eq!(&open_sodium, &TEST_PAYLOAD);
    }
}
