use std::collections::BTreeMap;

use proptest::{collection::btree_map, prelude::*};
use tokio::{runtime::Runtime, sync::RwLock};

use crate::{
    mock::MockTreeStore,
    restore::{JellyfishMerkleRestore, StateSnapshotReceiver},
    storage::TreeReader,
    tests::helper::init_mock_db,
    JellyfishMerkleTree, KeyHash, OwnedValue, RootHash, Version, WriteOverlay,
};

#[derive(Clone, Debug, Eq, PartialEq, Ord, PartialOrd)]
enum Action {
    Put { key: KeyHash, value: OwnedValue },
    Get { key: KeyHash },
    Commit,
}

#[derive(Clone, Debug, Default)]
struct MockKvStore {
    store: BTreeMap<KeyHash, OwnedValue>,
}

impl Action {
    async fn run(
        &self,
        overlay: &mut WriteOverlay<MockTreeStore>,
        mock_tree_store: MockTreeStore,
        mock_kv: &mut MockKvStore,
    ) -> anyhow::Result<()> {
        match self {
            Action::Put { key, value } => {
                overlay.put(*key, value.clone());
                mock_kv.store.insert(*key, value.clone());
            }
            Action::Get { key } => {
                let overlay_value = overlay.get(*key).await?;
                let mock_kv_value = mock_kv.store.get(key);
                assert_eq!(
                    overlay_value.as_ref(),
                    mock_kv_value,
                    "`get` returned different values"
                );
            }
            Action::Commit => {
                overlay.commit(mock_tree_store).await?;
            }
        }

        Ok(())
    }
}

proptest! {
    #[test]
    fn overlay_implements_kv(
        actions in
            proptest::collection::vec(any::<KeyHash>(), 1..5)
                .prop_flat_map(|used|
                    proptest::collection::vec(
                        proptest::prop_oneof![
                            // Just commit the state
                            proptest::prelude::Just(Action::Commit),
                            // Get an arbitrary key, not necessarily one that was ever used
                            any::<KeyHash>().prop_map(|key| Action::Get { key }),
                            // Get a key that was in the set of to-be-used keys
                            proptest::sample::select(used.clone()).prop_map(|key| Action::Get { key }),
                            // Set a key to either be deleted or to be set to some arbitrary value
                            (proptest::sample::select(used), any::<OwnedValue>()).prop_map(|(key, value)| {
                                Action::Put { key, value }
                            }),
                        ],
                        1..=5
                    )
                )
    ) {
        let rt = Runtime::new().unwrap();

        let mock_tree_store = MockTreeStore::default();
        let mut mock_kv = MockKvStore::default();
        let mut overlay = WriteOverlay::new(mock_tree_store.clone(), 0);

        rt.block_on(async move {
            for action in actions {
                action.run(&mut overlay, mock_tree_store.clone(), &mut mock_kv).await.unwrap();
            }
        })
    }
}
