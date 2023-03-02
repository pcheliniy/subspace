(function() {var implementors = {
"domain_client_executor":[["impl&lt;Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E&gt; GossipMessageHandler&lt;PBlock, Block&gt; for <a class=\"struct\" href=\"domain_client_executor/struct.CoreGossipMessageValidator.html\" title=\"struct domain_client_executor::CoreGossipMessageValidator\">CoreGossipMessageValidator</a>&lt;Block, SBlock, PBlock, Client, SClient, PClient, TransactionPool, Backend, E&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Block: BlockT,<br>&nbsp;&nbsp;&nbsp;&nbsp;SBlock: BlockT,<br>&nbsp;&nbsp;&nbsp;&nbsp;PBlock: BlockT,<br>&nbsp;&nbsp;&nbsp;&nbsp;Client: HeaderBackend&lt;Block&gt; + BlockBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt; + AuxStore + ProofProvider&lt;Block&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;Client::Api: BlockBuilder&lt;Block&gt; + ApiExt&lt;Block, StateBackend = StateBackendFor&lt;Backend, Block&gt;&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;SClient: HeaderBackend&lt;SBlock&gt; + ProvideRuntimeApi&lt;SBlock&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;SClient::Api: SystemDomainApi&lt;SBlock, NumberFor&lt;PBlock&gt;, PBlock::Hash&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;PClient: HeaderBackend&lt;PBlock&gt; + ProvideRuntimeApi&lt;PBlock&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;PClient::Api: ExecutorApi&lt;PBlock, Block::Hash&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;Backend: Backend&lt;Block&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;Backend as Backend&lt;Block&gt;&gt;::State as StateBackend&lt;HashFor&lt;Block&gt;&gt;&gt;::Transaction: HashDBT&lt;HashFor&lt;Block&gt;, DBValue&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;TransactionPool: TransactionPool&lt;Block = Block&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;E: CodeExecutor,</span>"],["impl&lt;Block, PBlock, Client, PClient, TransactionPool, Backend, E&gt; GossipMessageHandler&lt;PBlock, Block&gt; for <a class=\"struct\" href=\"domain_client_executor/struct.SystemGossipMessageValidator.html\" title=\"struct domain_client_executor::SystemGossipMessageValidator\">SystemGossipMessageValidator</a>&lt;Block, PBlock, Client, PClient, TransactionPool, Backend, E&gt;<span class=\"where fmt-newline\">where<br>&nbsp;&nbsp;&nbsp;&nbsp;Block: BlockT,<br>&nbsp;&nbsp;&nbsp;&nbsp;PBlock: BlockT,<br>&nbsp;&nbsp;&nbsp;&nbsp;Client: HeaderBackend&lt;Block&gt; + BlockBackend&lt;Block&gt; + ProvideRuntimeApi&lt;Block&gt; + AuxStore + ProofProvider&lt;Block&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;Client::Api: SystemDomainApi&lt;Block, NumberFor&lt;PBlock&gt;, PBlock::Hash&gt; + BlockBuilder&lt;Block&gt; + ApiExt&lt;Block, StateBackend = StateBackendFor&lt;Backend, Block&gt;&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;PClient: HeaderBackend&lt;PBlock&gt; + ProvideRuntimeApi&lt;PBlock&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;PClient::Api: ExecutorApi&lt;PBlock, Block::Hash&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;Backend: Backend&lt;Block&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;&lt;&lt;Backend as Backend&lt;Block&gt;&gt;::State as StateBackend&lt;HashFor&lt;Block&gt;&gt;&gt;::Transaction: HashDBT&lt;HashFor&lt;Block&gt;, DBValue&gt;,<br>&nbsp;&nbsp;&nbsp;&nbsp;TransactionPool: TransactionPool&lt;Block = Block&gt; + 'static,<br>&nbsp;&nbsp;&nbsp;&nbsp;E: CodeExecutor,</span>"]]
};if (window.register_implementors) {window.register_implementors(implementors);} else {window.pending_implementors = implementors;}})()