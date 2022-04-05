// Copyright 2017-2020 Parity Technologies (UK) Ltd.
// This file is part of Polkadot.

// Polkadot is free software: you can redistribute it and/or modify
// it under the terms of the GNU General Public License as published by
// the Free Software Foundation, either version 3 of the License, or
// (at your option) any later version.

// Polkadot is distributed in the hope that it will be useful,
// but WITHOUT ANY WARRANTY; without even the implied warranty of
// MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
// GNU General Public License for more details.

// You should have received a copy of the GNU General Public License
// along with Polkadot.  If not, see <http://www.gnu.org/licenses/>.

//! Utility module for subsystems
//!
//! Many subsystems have common interests such as canceling a bunch of spawned jobs,
//! or determining what their validator ID is. These common interests are factored into
//! this module.
//!
//! This crate also reexports Prometheus metric types which are expected to be implemented by subsystems.

#![warn(missing_docs)]
#![deny(unused_crate_dependencies)]

use polkadot_node_subsystem::{
	errors::{RuntimeApiError, SubsystemError},
	messages::{
		AllMessages, BoundToRelayParent, RuntimeApiMessage, RuntimeApiRequest, RuntimeApiSender,
	},
	overseer, ActiveLeavesUpdate, FromOverseer, OverseerSignal, SpawnedSubsystem, SubsystemContext,
	SubsystemSender,
};

pub use overseer::{
	gen::{OverseerError, Timeout},
	Subsystem, TimeoutExt,
};

use futures::{
	channel::{mpsc, oneshot},
	prelude::*,
	select,
	stream::{SelectAll, Stream},
};
use pin_project::pin_project;
use sp_core::traits::SpawnNamed;
use sp_executor::OpaqueBundle;
use sp_runtime::OpaqueExtrinsic;
use std::{
	borrow::Cow,
	collections::{hash_map::Entry, HashMap},
	convert::TryFrom,
	fmt,
	marker::Unpin,
	pin::Pin,
	task::{Context, Poll},
	time::Duration,
};
use subspace_core_primitives::Randomness;
use subspace_runtime_primitives::{opaque::Header, Hash};
use thiserror::Error;

/// These reexports are required so that external crates can use the `delegated_subsystem` macro properly.
pub mod reexports {
	pub use polkadot_overseer::gen::{SpawnNamed, SpawnedSubsystem, Subsystem, SubsystemContext};
}

/// Duration a job will wait after sending a stop signal before hard-aborting.
pub const JOB_GRACEFUL_STOP_DURATION: Duration = Duration::from_secs(1);
/// Capacity of channels to and from individual jobs
pub const JOB_CHANNEL_CAPACITY: usize = 64;

/// Utility errors
#[derive(Debug, Error)]
pub enum Error {
	/// Attempted to send on a MPSC channel which has been canceled
	#[error(transparent)]
	Mpsc(#[from] mpsc::SendError),
	/// A subsystem error
	#[error(transparent)]
	Subsystem(#[from] SubsystemError),
	/// An error in the Runtime API.
	#[error(transparent)]
	RuntimeApi(#[from] RuntimeApiError),
}

impl From<OverseerError> for Error {
	fn from(e: OverseerError) -> Self {
		Self::from(SubsystemError::from(e))
	}
}

/// A type alias for Runtime API receivers.
pub type RuntimeApiReceiver<T> = oneshot::Receiver<Result<T, RuntimeApiError>>;

/// Request some data from the `RuntimeApi`.
pub async fn request_from_runtime<RequestBuilder, Response, Sender>(
	parent: Hash,
	sender: &mut Sender,
	request_builder: RequestBuilder,
) -> RuntimeApiReceiver<Response>
where
	RequestBuilder: FnOnce(RuntimeApiSender<Response>) -> RuntimeApiRequest,
	Sender: SubsystemSender,
{
	let (tx, rx) = oneshot::channel();

	sender
		.send_message(RuntimeApiMessage::Request(parent, request_builder(tx)).into())
		.await;

	rx
}

/// Request `ExtractBundles` from the runtime
pub async fn request_extract_bundles(
	parent: Hash,
	extrinsics: Vec<OpaqueExtrinsic>,
	sender: &mut impl SubsystemSender,
) -> RuntimeApiReceiver<Vec<OpaqueBundle>> {
	request_from_runtime(parent, sender, |tx| RuntimeApiRequest::ExtractBundles(extrinsics, tx))
		.await
}
/// Request `ExtrinsicsShufflingSeed "` from the runtime
pub async fn request_extrinsics_shuffling_seed(
	parent: Hash,
	header: Header,
	sender: &mut impl SubsystemSender,
) -> RuntimeApiReceiver<Randomness> {
	request_from_runtime(parent, sender, |tx| {
		RuntimeApiRequest::ExtrinsicsShufflingSeed(header, tx)
	})
	.await
}
/// Rquest `ExecutionWasmBundle` from the runtime
pub async fn request_execution_wasm_bundle(
	parent: Hash,
	sender: &mut impl SubsystemSender,
) -> RuntimeApiReceiver<Cow<'static, [u8]>> {
	request_from_runtime(parent, sender, RuntimeApiRequest::ExecutionWasmBundle).await
}

struct AbortOnDrop(future::AbortHandle);

impl Drop for AbortOnDrop {
	fn drop(&mut self) {
		self.0.abort();
	}
}

/// A `JobHandle` manages a particular job for a subsystem.
struct JobHandle<ToJob> {
	_abort_handle: AbortOnDrop,
	to_job: mpsc::Sender<ToJob>,
}

impl<ToJob> JobHandle<ToJob> {
	/// Send a message to the job.
	async fn send_msg(&mut self, msg: ToJob) -> Result<(), Error> {
		self.to_job.send(msg).await.map_err(Into::into)
	}
}

/// Commands from a job to the broader subsystem.
pub enum FromJobCommand {
	/// Spawn a child task on the executor.
	Spawn(&'static str, Pin<Box<dyn Future<Output = ()> + Send>>),
}

/// A sender for messages from jobs, as well as commands to the overseer.
pub struct JobSender<S: SubsystemSender> {
	sender: S,
	from_job: mpsc::Sender<FromJobCommand>,
}

// A custom clone impl, since M does not need to impl `Clone`
// which `#[derive(Clone)]` requires.
impl<S: SubsystemSender> Clone for JobSender<S> {
	fn clone(&self) -> Self {
		Self { sender: self.sender.clone(), from_job: self.from_job.clone() }
	}
}

impl<S: SubsystemSender> JobSender<S> {
	/// Get access to the underlying subsystem sender.
	pub fn subsystem_sender(&mut self) -> &mut S {
		&mut self.sender
	}

	/// Send a direct message to some other `Subsystem`, routed based on message type.
	pub async fn send_message(&mut self, msg: impl Into<AllMessages>) {
		self.sender.send_message(msg.into()).await
	}

	/// Send multiple direct messages to other `Subsystem`s, routed based on message type.
	pub async fn send_messages<T, M>(&mut self, msgs: T)
	where
		T: IntoIterator<Item = M> + Send,
		T::IntoIter: Send,
		M: Into<AllMessages>,
	{
		self.sender.send_messages(msgs.into_iter().map(|m| m.into())).await
	}

	/// Send a message onto the unbounded queue of some other `Subsystem`, routed based on message
	/// type.
	///
	/// This function should be used only when there is some other bounding factor on the messages
	/// sent with it. Otherwise, it risks a memory leak.
	pub fn send_unbounded_message(&mut self, msg: impl Into<AllMessages>) {
		self.sender.send_unbounded_message(msg.into())
	}
}

#[async_trait::async_trait]
impl<S, M> overseer::SubsystemSender<M> for JobSender<S>
where
	M: Send + 'static + Into<AllMessages>,
	S: SubsystemSender + Clone,
{
	async fn send_message(&mut self, msg: M) {
		self.sender.send_message(msg.into()).await
	}

	async fn send_messages<T>(&mut self, msgs: T)
	where
		T: IntoIterator<Item = M> + Send,
		T::IntoIter: Send,
	{
		self.sender.send_messages(msgs.into_iter().map(|m| m.into())).await
	}

	fn send_unbounded_message(&mut self, msg: M) {
		self.sender.send_unbounded_message(msg.into())
	}
}

impl fmt::Debug for FromJobCommand {
	fn fmt(&self, fmt: &mut fmt::Formatter) -> fmt::Result {
		match self {
			Self::Spawn(name, _) => write!(fmt, "FromJobCommand::Spawn({})", name),
		}
	}
}

/// This trait governs jobs.
///
/// Jobs are instantiated and killed automatically on appropriate overseer messages.
/// Other messages are passed along to and from the job via the overseer to other subsystems.
pub trait JobTrait: Unpin + Sized {
	/// Message type used to send messages to the job.
	type ToJob: 'static + BoundToRelayParent + Send;
	/// Job runtime error.
	type Error: 'static + std::error::Error + Send;
	/// Extra arguments this job needs to run properly.
	///
	/// If no extra information is needed, it is perfectly acceptable to set it to `()`.
	type RunArgs: 'static + Send;

	/// Name of the job, i.e. `candidate-backing-job`
	const NAME: &'static str;

	/// Run a job for the given relay `parent`.
	///
	/// The job should be ended when `receiver` returns `None`.
	fn run<S: SubsystemSender>(
		parent: Hash,
		run_args: Self::RunArgs,
		receiver: mpsc::Receiver<Self::ToJob>,
		sender: JobSender<S>,
	) -> Pin<Box<dyn Future<Output = Result<(), Self::Error>> + Send>>;
}

/// Jobs manager for a subsystem
///
/// - Spawns new jobs for a given relay-parent on demand.
/// - Closes old jobs for a given relay-parent on demand.
/// - Dispatches messages to the appropriate job for a given relay-parent.
/// - When dropped, aborts all remaining jobs.
/// - implements `Stream<Item=FromJobCommand>`, collecting all messages from subordinate jobs.
#[pin_project]
struct Jobs<Spawner, ToJob> {
	spawner: Spawner,
	running: HashMap<Hash, JobHandle<ToJob>>,
	outgoing_msgs: SelectAll<mpsc::Receiver<FromJobCommand>>,
}

impl<Spawner, ToJob> Jobs<Spawner, ToJob>
where
	Spawner: SpawnNamed,
	ToJob: Send + 'static,
{
	/// Create a new Jobs manager which handles spawning appropriate jobs.
	pub fn new(spawner: Spawner) -> Self {
		Self { spawner, running: HashMap::new(), outgoing_msgs: SelectAll::new() }
	}

	/// Spawn a new job for this `parent_hash`, with whatever args are appropriate.
	fn spawn_job<Job, Sender>(&mut self, parent_hash: Hash, run_args: Job::RunArgs, sender: Sender)
	where
		Job: JobTrait<ToJob = ToJob>,
		Sender: SubsystemSender,
	{
		let (to_job_tx, to_job_rx) = mpsc::channel(JOB_CHANNEL_CAPACITY);
		let (from_job_tx, from_job_rx) = mpsc::channel(JOB_CHANNEL_CAPACITY);

		let (future, abort_handle) = future::abortable(async move {
			if let Err(e) = Job::run(
				parent_hash,
				run_args,
				to_job_rx,
				JobSender { sender, from_job: from_job_tx },
			)
			.await
			{
				tracing::error!(
					job = Job::NAME,
					parent_hash = %parent_hash,
					err = ?e,
					"job finished with an error",
				);

				return Err(e)
			}

			Ok(())
		});

		self.spawner.spawn(
			Job::NAME,
			Some(Job::NAME.strip_suffix("-job").unwrap_or(Job::NAME)),
			future.map(drop).boxed(),
		);
		self.outgoing_msgs.push(from_job_rx);

		let handle = JobHandle { _abort_handle: AbortOnDrop(abort_handle), to_job: to_job_tx };

		self.running.insert(parent_hash, handle);
	}

	/// Stop the job associated with this `parent_hash`.
	pub async fn stop_job(&mut self, parent_hash: Hash) {
		self.running.remove(&parent_hash);
	}

	/// Send a message to the appropriate job for this `parent_hash`.
	async fn send_msg(&mut self, parent_hash: Hash, msg: ToJob) {
		if let Entry::Occupied(mut job) = self.running.entry(parent_hash) {
			if job.get_mut().send_msg(msg).await.is_err() {
				job.remove();
			}
		}
	}
}

impl<Spawner, ToJob> Stream for Jobs<Spawner, ToJob>
where
	Spawner: SpawnNamed,
{
	type Item = FromJobCommand;

	fn poll_next(mut self: Pin<&mut Self>, cx: &mut Context) -> Poll<Option<Self::Item>> {
		match futures::ready!(Pin::new(&mut self.outgoing_msgs).poll_next(cx)) {
			Some(msg) => Poll::Ready(Some(msg)),
			// Don't end if there are no jobs running
			None => Poll::Pending,
		}
	}
}

impl<Spawner, ToJob> stream::FusedStream for Jobs<Spawner, ToJob>
where
	Spawner: SpawnNamed,
{
	fn is_terminated(&self) -> bool {
		false
	}
}

/// Parameters to a job subsystem.
pub struct JobSubsystemParams<Spawner, RunArgs> {
	/// A spawner for sub-tasks.
	spawner: Spawner,
	/// Arguments to each job.
	run_args: RunArgs,
}

/// A subsystem which wraps jobs.
///
/// Conceptually, this is very simple: it just loops forever.
///
/// - On incoming overseer messages, it starts or stops jobs as appropriate.
/// - On other incoming messages, if they can be converted into `Job::ToJob` and
///   include a hash, then they're forwarded to the appropriate individual job.
/// - On outgoing messages from the jobs, it forwards them to the overseer.
pub struct JobSubsystem<Job: JobTrait, Spawner> {
	#[allow(missing_docs)]
	pub params: JobSubsystemParams<Spawner, Job::RunArgs>,
	_marker: std::marker::PhantomData<Job>,
}

impl<Job: JobTrait, Spawner> JobSubsystem<Job, Spawner> {
	/// Create a new `JobSubsystem`.
	pub fn new(spawner: Spawner, run_args: Job::RunArgs) -> Self {
		JobSubsystem {
			params: JobSubsystemParams { spawner, run_args },
			_marker: std::marker::PhantomData,
		}
	}

	/// Run the subsystem to completion.
	pub async fn run<Context>(self, mut ctx: Context)
	where
		Spawner: SpawnNamed + Send + Clone + Unpin + 'static,
		Context: SubsystemContext<Message = <Job as JobTrait>::ToJob, Signal = OverseerSignal>,
		<Context as SubsystemContext>::Sender: SubsystemSender,
		Job: 'static + JobTrait + Send,
		<Job as JobTrait>::RunArgs: Clone + Sync,
		<Job as JobTrait>::ToJob:
			Sync + From<<Context as polkadot_overseer::SubsystemContext>::Message>,
	{
		let JobSubsystem { params: JobSubsystemParams { spawner, run_args }, .. } = self;

		let mut jobs = Jobs::<Spawner, Job::ToJob>::new(spawner);

		loop {
			select! {
				incoming = ctx.recv().fuse() => {
					match incoming {
						Ok(FromOverseer::Signal(OverseerSignal::ActiveLeaves(ActiveLeavesUpdate {
							activated,
							deactivated,
						}))) => {
							if let Some(activated) = activated {
								let sender = ctx.sender().clone();
								jobs.spawn_job::<Job, _>(
									activated.hash,
									run_args.clone(),
									sender,
								)
							}

							for hash in deactivated {
								jobs.stop_job(hash).await;
							}
						}
						Ok(FromOverseer::Signal(OverseerSignal::Conclude)) => {
							jobs.running.clear();
							break;
						}
						Ok(FromOverseer::Signal(OverseerSignal::NewSlot(..))) => {}
						Ok(FromOverseer::Communication { msg }) => {
							if let Ok(to_job) = <<Context as SubsystemContext>::Message>::try_from(msg) {
								jobs.send_msg(to_job.relay_parent(), to_job).await;
							}
						}
						Err(err) => {
							tracing::error!(
								job = Job::NAME,
								err = ?err,
								"error receiving message from subsystem context for job",
							);
							break;
						}
					}
				}
				outgoing = jobs.next() => {
					// TODO verify the introduced .await here is not a problem
					// TODO it should only wait for the spawn to complete
					// TODO but not for anything beyond that
					let res = match outgoing.expect("the Jobs stream never ends; qed") {
						FromJobCommand::Spawn(name, task) => ctx.spawn(name, task),
					};

					if let Err(e) = res {
						tracing::warn!(err = ?e, "failed to handle command from job");
					}
				}
				complete => break,
			}
		}
	}
}

impl<Context, Job, Spawner> Subsystem<Context, SubsystemError> for JobSubsystem<Job, Spawner>
where
	Spawner: SpawnNamed + Send + Clone + Unpin + 'static,
	Context: SubsystemContext<Message = Job::ToJob, Signal = OverseerSignal>,
	Job: 'static + JobTrait + Send,
	Job::RunArgs: Clone + Sync,
	<Job as JobTrait>::ToJob:
		Sync + From<<Context as polkadot_overseer::SubsystemContext>::Message>,
{
	fn start(self, ctx: Context) -> SpawnedSubsystem {
		let future = Box::pin(async move {
			self.run(ctx).await;
			Ok(())
		});

		SpawnedSubsystem { name: Job::NAME.strip_suffix("-job").unwrap_or(Job::NAME), future }
	}
}
