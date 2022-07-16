use crate::LOG_TARGET;
use futures::FutureExt;
use parking_lot::Mutex;
use sc_client_api::HeaderBackend;
use sp_api::ProvideRuntimeApi;
use sp_core::traits::SpawnNamed;
use sp_executor::{BundleEquivocationProof, ExecutorApi, FraudProof, InvalidTransactionProof};
use sp_runtime::generic::BlockId;
use sp_runtime::traits::Block as BlockT;
use std::collections::VecDeque;
use std::sync::atomic::AtomicBool;
use std::sync::Arc;
use tokio::sync::mpsc;
use tokio::sync::mpsc::Sender;

const MAX_CAPACITY: usize = 256;

#[derive(Debug)]
enum UnsignedMessage {
    FraudProof(FraudProof),
    BundleEquivocationProof(BundleEquivocationProof),
    InvalidTransactionProof(InvalidTransactionProof),
}

/// Submits various executor-specific unsigned extrinsic to the primary node.
struct UnsignedSubmitter {
    spawner: Box<dyn SpawnNamed + Send + Sync>,
    sender: Sender<UnsignedMessage>,
    buffer: Arc<Mutex<VecDeque<UnsignedMessage>>>,
}

impl UnsignedSubmitter {
    pub fn new<Block, PBlock, PClient>(
        primary_chain_client: PClient,
        spawner: Box<dyn SpawnNamed + Send + Sync>,
    ) -> Self
    where
        Block: BlockT,
        PBlock: BlockT,
        PClient: HeaderBackend<PBlock> + ProvideRuntimeApi<PBlock> + Send + Sync + 'static,
        PClient::Api: ExecutorApi<PBlock, Block::Hash>,
    {
        let buffer = Arc::new(Mutex::new(VecDeque::with_capacity(MAX_CAPACITY)));

        let (sender, mut receiver) = mpsc::channel(128);

        spawner.spawn_blocking("cirrus-submit-unsigned-extrinsic", None, {
            let buffer = buffer.clone();
            async move {
                let runtime_api = primary_chain_client.runtime_api();

                while let Some(msg) = receiver.recv().await {
                    let at = BlockId::Hash(primary_chain_client.info().best_hash);
                    match msg {
                        UnsignedMessage::FraudProof(fraud_proof) => {
                            if let Err(error) =
                                runtime_api.submit_fraud_proof_unsigned(&at, fraud_proof)
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "Failed to submit fraud proof"
                                );
                            }
                        }
                        UnsignedMessage::BundleEquivocationProof(bundle_equivocation_proof) => {
                            if let Err(error) = runtime_api
                                .submit_bundle_equivocation_proof_unsigned(
                                    &at,
                                    bundle_equivocation_proof,
                                )
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "Failed to submit bundle equivocation proof"
                                );
                            }
                        }
                        UnsignedMessage::InvalidTransactionProof(invalid_transaction_proof) => {
                            if let Err(error) = runtime_api
                                .submit_invalid_transaction_proof_unsigned(
                                    &at,
                                    invalid_transaction_proof,
                                )
                            {
                                tracing::error!(
                                    target: LOG_TARGET,
                                    ?error,
                                    "Failed to submit invalid transaction proof"
                                );
                            }
                        }
                    }
                }
            }
            .boxed()
        });

        Self {
            spawner,
            sender,
            buffer,
        }
    }

    pub fn submit_fraud_proof(&self, fraud_proof: FraudProof) {
        let sender = self.sender.clone();
        self.spawner.spawn(
            "send-message",
            None,
            async move {
                if let Err(e) = sender.send(UnsignedMessage::FraudProof(fraud_proof)).await {
                    tracing::error!(target: LOG_TARGET, error =?e, "Failed to send FraudProof message");
                }
            }
            .boxed(),
        );
    }

    pub fn submit_bundle_equivocation_proof(
        &self,
        bundle_equivocation_proof: BundleEquivocationProof,
    ) {
        let sender = self.sender.clone();
        self.spawner.spawn(
            "send-message",
            None,
            async move {
                if let Err(e) = sender
                    .send(UnsignedMessage::BundleEquivocationProof(
                        bundle_equivocation_proof,
                    ))
                    .await
                {
                    tracing::error!(target: LOG_TARGET, error =?e, "Failed to send BundleEquivocationProof message");
                }
            }
            .boxed(),
        );
    }

    pub fn submit_invalid_transaction_proof(
        &self,
        invalid_transaction_proof: InvalidTransactionProof,
    ) {
        let sender = self.sender.clone();
        self.spawner.spawn(
            "send-message",
            None,
            async move {
                if let Err(e) = sender
                    .send(UnsignedMessage::InvalidTransactionProof(
                        invalid_transaction_proof,
                    ))
                    .await
                {
                    tracing::error!(target: LOG_TARGET, error =?e, "Failed to send InvalidTransactionProof message");
                }
            }
            .boxed(),
        );
    }
}
