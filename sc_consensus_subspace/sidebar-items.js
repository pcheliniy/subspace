initSidebarItems({"enum":[["Error","Errors encountered by the Subspace authorship task."]],"fn":[["block_import","Produce a Subspace block-import object to be used later on in the construction of an import-queue."],["find_pre_digest","Extract the Subspace pre digest from the given header. Pre-runtime digests are mandatory, the function will return `Err` if none is found."],["import_queue","Start an import queue for the Subspace consensus algorithm."],["start_subspace","Start the Subspace worker."],["start_subspace_archiver","Start an archiver that will listen for imported blocks and archive blocks at `K` depth, producing pieces and root blocks (root blocks are then added back to the blockchain as `store_root_block` extrinsic)."]],"mod":[["aux_schema","Schema for Subspace block weight in the aux-db."],["notification","Utility module for handling Subspace client notifications."]],"struct":[["ArchivedSegment","Archived segment as a combination of root block hash, segment index and corresponding pieces"],["BlockSigningNotification","Notification with block header hash that needs to be signed and sender for signature."],["Config","A slot duration."],["NewSlotInfo","Information about new slot that just arrived"],["NewSlotNotification","New slot notification with slot information and sender for solution for the slot."],["SubspaceBlockImport","A block-import handler for Subspace."],["SubspaceLink","State that must be shared between the import queue and the authoring logic."],["SubspaceParams","Parameters for Subspace."],["SubspaceVerifier","A verifier for Subspace blocks."],["SubspaceWorker","Worker for Subspace which implements `Future<Output=()>`. This must be polled."]]});