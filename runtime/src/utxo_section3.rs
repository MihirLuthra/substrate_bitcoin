use super::Aura;
use codec::{Decode, Encode};
use frame_support::{
    decl_event, decl_module, decl_storage,debug,
    dispatch::{DispatchResult, Vec},
    ensure,
};

use sp_core::{H256, H512};
#[cfg(feature = "std")]
use serde::{Deserialize, Serialize};
use sp_core::sr25519::{Public, Signature};
use sp_runtime::traits::{BlakeTwo256, Hash, SaturatedConversion};
use sp_std::collections::btree_map::BTreeMap;
use sp_runtime::transaction_validity::{TransactionLongevity, ValidTransaction};
use frame_system as system;

pub trait Trait: system::Trait {
    type Event: From<Event> + Into<<Self as system::Trait>::Event>;
}

pub type Value = u128;

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct Transaction {
    pub inputs: Vec<TransactionInput>,
    pub outputs: Vec<TransactionOutput>
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionInput {
    pub outpoint: H256,
    pub sigscript: H512,
}

#[cfg_attr(feature = "std", derive(Serialize, Deserialize))]
#[derive(PartialEq, Eq, PartialOrd, Ord, Default, Clone, Encode, Decode, Hash, Debug)]
pub struct TransactionOutput {
    pub value: Value,
    pub pubkey: H256,
}

decl_storage! {
    trait Store for Module<T: Trait> as Utxo {
        UtxoStore build(|config: &GenesisConfig| {
            config.genesis_utxos
                .iter()
                .cloned()
                .map(|u| (BlakeTwo256::hash_of(&u), u))
                .collect::<Vec<_>>()
        }): map hasher(identity) H256 => Option<TransactionOutput>;

        pub RewardTotal get(fn reward_total): Value;
    }

    add_extra_genesis {
        config(genesis_utxos): Vec<TransactionOutput>;
    }
}

decl_module! {
    pub struct Module<T: Trait> for enum Call where origin: T::Origin {
        fn deposit_event() = default;

        #[weight = 0]
        fn spend(_origin, transaction: Transaction) -> DispatchResult {
            // 1. TODO: check that transaction is valid
            let reward = Self::validate_transaction(&transaction)?;
            
            // 2. write to storage
            Self::update_storage(&transaction, reward)?;

            // 3. emit success event
            Self::deposit_event(Event::TransactionSuccess(transaction));
            
            Ok(())
        }

        fn on_finalize() {
            let auth = Aura::authorities().iter().map(|x| {
                let r: &Public = x.as_ref();
                r.0.into()
            }).collect::<Vec<_>>();

            Self::disperse_reward(&auth);
        }
    }
}

decl_event! {
    pub enum Event {
        TransactionSuccess(Transaction),
    }
}

impl<T: Trait> Module<T> {
    // transaction with sigscript removed
    pub fn get_simple_transaction(transaction: &Transaction) -> Vec<u8> {
        let mut trx = transaction.clone();

        for input in trx.inputs.iter_mut() {
            input.sigscript = H512::zero();
        }
        trx.encode()
    }

    fn validate_transaction(transaction: &Transaction) -> Result<Value, &'static str> {
        ensure!(!transaction.inputs.is_empty(), "No inputs");
        ensure!(!transaction.outputs.is_empty(), "No outputs");

        {
            let input_set: BTreeMap<_, ()> = transaction.inputs.iter().map(|input| (input, ())).collect();
            debug::print!("input_set.len = {}, transaction.inputs.len = {}", input_set.len(), transaction.inputs.len());
            ensure!(input_set.len() == transaction.inputs.len(), "Error: duplicate inputs");
        }

        {
            let output_set: BTreeMap<_, ()> = transaction.outputs.iter().map(|output| (output, ())).collect();
            ensure!(output_set.len() == transaction.outputs.len(), "Error: duplicate outputs");
        }

        let simple_trx = Self::get_simple_transaction(transaction);

        let mut total_input: Value = 0;
        let mut total_output: Value = 0;

        for input in transaction.inputs.iter() {
            if let Some(input_utxo) = UtxoStore::get(&input.outpoint) {
                ensure!( sp_io::crypto::sr25519_verify(
                    &Signature::from_raw(*input.sigscript.as_fixed_bytes()),
                    &simple_trx,
                    &Public::from_h256(input_utxo.pubkey)
                ),"Invalid signature");
                total_input = total_input.checked_add(input_utxo.value).ok_or("total input overflowed")?;
            } else {
                //TODO: hanlde race condition
            }
        }

        let mut output_index: u64 = 0;
        for output in transaction.outputs.iter() {
            ensure!(output.value > 0, "Output value should be nonzero");
            let hash = BlakeTwo256::hash_of(&(&transaction.encode(), output_index));
            output_index = output_index.checked_add(1).ok_or("Output index overflowed")?;
            ensure!(!UtxoStore::contains_key(hash), "Output already exists");
            total_output = total_output.checked_add(output.value).ok_or("total output overflowed")?;
        }

        ensure!(total_input >= total_output, "Output value exceeded input");

        let reward = total_input - total_output;

        Ok(reward)
    }

    fn update_storage(transaction: &Transaction, reward: Value) -> DispatchResult {
        let new_reward_total = RewardTotal::get()
            .checked_add(reward)
            .ok_or("Reward overflow")?;
        RewardTotal::put(new_reward_total);

        for input in &transaction.inputs {
            <UtxoStore>::remove(input.outpoint);
        }

        let mut index: u64 = 0;
        for output in &transaction.outputs {
            let hash = BlakeTwo256::hash_of( &(&transaction.encode(), index) );
            index += 1;
            UtxoStore::insert(hash, output);
        }

        Ok(())
    }

    fn disperse_reward(authorities: &[H256]) {
        let reward = RewardTotal::take();
        let share_value: Value = reward
            .checked_div(authorities.len() as Value)
            .ok_or("No authorities")
            .unwrap();

        if share_value == 0 {return}

        let remainder = reward
            .checked_sub(share_value * authorities.len() as Value)
            .ok_or("Sub underflow")
            .unwrap();

        RewardTotal::put(remainder);

        for authority in authorities {
            let utxo = TransactionOutput {
                value: share_value,
                pubkey: *authority,
            };

            let hash = BlakeTwo256::hash_of( 
                &(
                    &utxo,
                    system::Module::<T>::block_number().saturated_into::<u64>()
                )
            );

            if !UtxoStore::contains_key(hash) {
                UtxoStore::insert(hash, utxo);
                sp_runtime::print("Transaction reward sent to");
                sp_runtime::print(hash.as_fixed_bytes() as &[u8]);
            } else {
                sp_runtime::print("Transaction reward wasted due to hash collision");
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    use frame_support::{assert_ok, assert_err, impl_outer_origin, parameter_types, weights::Weight};
    //use primitive_types::H256;
    use sp_runtime::{testing::Header, traits::IdentityLookup, Perbill};
    use sp_core::testing::{KeyStore, SR25519};
    use sp_core::traits::KeystoreExt;

    impl_outer_origin! {
        pub enum Origin for Test {}
    }

    #[derive(Clone, Eq, PartialEq)]
    pub struct Test;
    parameter_types! {
        pub const BlockHashCount: u64 = 250;
        pub const MaximumBlockWeight: Weight = 1024;
        pub const MaximumBlockLength: u32 = 2 * 1024;
        pub const AvailableBlockRatio: Perbill = Perbill::from_percent(75);
    }

    impl system::Trait for Test {
        type Origin = Origin;
        type Call = ();
        type Index = u64;
        type BlockNumber = u64;
        type Hash = H256;
        type Hashing = BlakeTwo256;
        type AccountId = u64;
        type Lookup = IdentityLookup<Self::AccountId>;
        type Header = Header;
        type Event = ();
        type BlockHashCount = BlockHashCount;
        type MaximumBlockWeight = MaximumBlockWeight;
        type MaximumBlockLength = MaximumBlockLength;
        type AvailableBlockRatio = AvailableBlockRatio;
        type Version = ();
        //type ModuleToIndex = ();
        type BaseCallFilter = ();
        type DbWeight = ();
        type BlockExecutionWeight = ();
        type ExtrinsicBaseWeight = ();
        type MaximumExtrinsicWeight = ();
        type PalletInfo = ();
        type AccountData = ();
        type OnNewAccount = ();
        type OnKilledAccount = ();
        type SystemWeightInfo = ();
    }

    impl Trait for Test {
        type Event = ();
    }

    type Utxo = Module<Test>;

    use hex_literal::hex;

    const ALICE_PHRASE: &str = "news slush supreme milk chapter athlete soap sausage put clutch what kitten";
    const GENESIS_UTXO: [u8; 32] = hex!("79eabcbd5ef6e958c6a7851b36da07691c19bda1835a08f875aa286911800999");

    fn new_test_ext() -> sp_io::TestExternalities {
        let keystore = KeyStore::new();
        let alice_pub_key = keystore.write().sr25519_generate_new(SR25519, Some(ALICE_PHRASE)).unwrap();

        let mut t = system::GenesisConfig::default()
            .build_storage::<Test>()
            .unwrap();

        t.top.extend(
            GenesisConfig {
                genesis_utxos: vec![
                    TransactionOutput {
                        value: 100,
                        pubkey: H256::from(alice_pub_key),
                    },
                ],
                ..Default::default()
            }
            .build_storage()
            .unwrap()
            .top
        );

        let mut ext = sp_io::TestExternalities::from(t);
        ext.register_extension(KeystoreExt(keystore));
        ext
    }

    #[test]
    fn test_simple_transaction() {
        new_test_ext().execute_with(|| {
            let alice_pubkey = sp_io::crypto::sr25519_public_keys(SR25519)[0];
            let mut transaction = Transaction {
                inputs: vec![TransactionInput {
                    outpoint: H256::from(GENESIS_UTXO),
                    sigscript: H512::zero(),
                }],
                outputs: vec![TransactionOutput {
                    value: 50,
                    pubkey: H256::from(alice_pubkey),
                }],
            };

            let alice_signature 
                = sp_io::crypto::sr25519_sign(SR25519, &alice_pubkey, &transaction.encode()).unwrap();
            transaction.inputs[0].sigscript = H512::from(alice_signature);

            let new_utxo_hash = BlakeTwo256::hash_of(&(&transaction.encode(), 0 as u64));

            // 1. spend will be Ok
            assert_ok!(Utxo::spend(Origin::signed(0), transaction));

            // 2. old utxo is gone
            assert!(! UtxoStore::contains_key(H256::from(GENESIS_UTXO)));

            // 3. new utxo will exist, value == 50
            assert!(UtxoStore::contains_key(new_utxo_hash));
            assert_eq!(UtxoStore::get(new_utxo_hash).unwrap().value, 50);
        });
    }
}
