use super::Aura;
use codec::{Decode, Encode};
use frame_support::{
    decl_event, decl_module, decl_storage,
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
            
            // 2. write to storage
            let reward: Value = 0;
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
