##! PereKV - Persistent Replicated Key Value Store
##!
##! About
##! =====
##!
##! A best-effort cluster-aware persistent and replicated `table[string] of string`
##! implementation for Zeek 8.0 or later using Zeek's SQLite storage backend and
##! explicit Cluster::publish() calls for state propagation.
##!
##! API
##! ===
##!
##!     PereKV::new_store(): Store
##!     PereKV::insert(s: Store, key: string, value: string): Storage::OperationResult
##!     PereKV::contains(s: Store, key: string): bool
##!     PereKV::lookup(s: Store, key: string): Storage::OperationResult
##!
##! The offered API only supports string keys and values. If you need to store
##! complex keys or values, encode and decode them with to_json() and from_json(),
##! or write your own serializiation logic. This is no different than working with
##! Redis or Memchached in any other language. For simple types, use cat() and
##! to_count(), to_addr(), etc. etc. Keeping the schema consistent is up to you.
##!
##! There's no deletion. This package is for persisting state with expiration.
##!
##! Every Zeek node (process) owns a SQLite database on disk per store instance.
##! The location on disk for the database is leveraging the existing
##! :zeek:see`Cluster::default_store_dir` variable from Zeek's cluster framework.
##! It creates a "PereKV" subdirectory within it followed by per-node directories
##! under it. Like so:
##!
##!     Cluster::default_store_dir / "PereKV" / Cluster::node / "{store name}.sqlite"
##!
##! If you see the mkdir() operations failing, either the paretn directory doesn't
##! exist, or the permissions are wrong. An empty :zeek:see:`Cluster::node` value
##! will use "zeek".
##!
##! In a Zeekctl setup, the databases will end up in "<PREFIX>/spool/stores/PereKV/..".
##! Filesystem usage and database sizes can be monitored with standard Unix utilities
##! like ``du``, ``ls`` and also the ``sqlite3``  command. Depending on the churn
##! and growth of the database, you may want to checkout SQLite's VACUUM command
##! and determine whether running it on the databases keeps their sizes bounded.
##!
##! Behavior
##! ========
##!
##! Calling PereKV::insert() on any node will store the given key-value pair
##! persistently in the node's SQLite database specific for the Store instance.
##! Additionally, the node will broadcast the insert to all nodes in a cluster
##! that have created a store instance with the same name. Receiver nodes will
##! insert and potentially overwrite any existing key they had inserted previously,
##! therby updating their local expire time. There is always a delay between a
##! PereKV::insert() on the originating node and a receiver nodes. Do not expect
##! atomic behavior. Particularly during cluster restart operations. Generally,
##! the inserts should propagate relatively quickly. When two node's insert the
##! same key at approximately the same time, it's undefined which value will win.
##! Indeed, they might even differ between nodes. Design your application to
##! deal with this. If you use PereKV as as a set (i.e. not providing a value
##! to PreKV::insert(), or using a fixed value - the default is actually the
##! string "1"), the value will be consistent, obviously.
##!
##! Cluster Optimization
##! ====================
##!
##! Publishing of key-value insert operations to other nodes is queued for a
##! configurable interval (see ``batch_period``, 10msec by default) on the
##! originating node in order send multiple key-value insert operations with
##! a single remote event / Cluster::publish() invocation instead of using an
##! individual remote event per key-value insert. This reduces pressure on the
##! cluster backend by coalescing multiple operations. As mentioned above, there's
##! always some delay propagating the insert operations from one node to another
##! node. This optimization exploits this by purposely increasing the delay to
##! increase throughput and reduce CPU usage on cluster nodes.
##!
##! Some Failure Modes
##! ==================
##!
##! After a PereKV::insert():
##!
##! 1) The node may terminate or crash. The node's local SQLite database
##!    will contain the key-value pair, but no other cluster node will
##!    learn about the new key-value pair. When the node restarts, it will
##!    not broadcast this key-value insert operation. The result is that
##!    all other nodes will not have the key in question and likely insert and
##!    broadcast when observing it. If this succeeds and all nodes receive the
##!    second insert, the state is consistent.
##!
##! 2) The publish operation to distribute key-value pairs to other nodes
##!    is discarded due to cluster overload. This can happen if there's
##!    too many remote events published. In order to prevent unbounded memory
##!    growth, Zeek's cluster backends may discard events in overload situations.
##!    This includes the key-value insert oeprations.
##!    The result is the same as for case 1), but with a different root cause.
##!    You should monitor Broker or ZeroMQ specific metrics that indicating
##!    dropped events and determine why they happen. For ZeroMQ, the following
##!    metrics are available:
##!
##!      zeek_cluster_zeromq_onloop_drops_total
##!      zeek_cluster_zeromq_xpub_drops_total
##!
##!    It can also be reasonable to tweak ZeroMQs high-water-mark values, but
##!    make sure to monitor CPU and memory usage of the Zeek processes after
##!    such changes.
##!
##! 3) Deletion of the SQLite database. If the SQLite database of any node
##!    is deleted (or a new node is added to an existing cluster), this node
##!    will not learn about existing key-value pairs.
##!    Instead, it likely will re-insert one key-value pair after the other
##!    and distribute them to other nodes. Other nodes will overwrite the
##!    entry in their local database and update the expiration time accordingly.
##!    You can copy the SQLite database of any other node for bootstrapping
##!    purposes to prevent this. There is not automatism, however.

@load base/frameworks/cluster
@load base/frameworks/storage/sync
@load policy/frameworks/storage/backend/sqlite

module PereKV;

export {
	## The topic to use for KeyValueInsertOps distribution to other nodes.
	## This will have the name appended.
	const base_topic = "perekv.string_table" &redef;

	## The store instance.
	type Store: record {
		name: string;
		database_file: string;
		topic: string;
		create_expire: interval;
		cache_expire: interval;
		cache: table[string] of string;  # this has a &create_expire
		batch_period: interval;
		batch_max_size: count;
		overwrite: bool;
		storage_backend: opaque of Storage::BackendHandle &optional;
		remote_insert_active: bool &default=F; # To prevent re-publish of inserts received via remote event.
	};

	## Tuning.
	const default_cache_expire = 3.0sec;

	## How long to delay the Cluster::publish() operation after a
	## PereKV::insert() for batching.
	const default_batch_period: interval = 10msec;

	## How many KeyValueInsertOps to accumulate before forcefully
	## flushing them.
	const default_batch_max_size = 100;

	## The default overwrite behavior.
	##
	## By default, PereKV::insert() will overwrite an existing entry
	## and broadcast it to all other processes. These in turn will
	## also overwrite any existing value in their store.
	##
	## This default behavior ensures that the expiration time for
	## individual entries in the the store converge. E.g., when
	## one process misses an insert for a given key and at a later
	## point in time inserts the key itself, it'll broadcast the insert
	## operation to all other nodes. Each of the receiving nodes will
	## then re-insert the entry and update their own expire time. This
	## results in individual processes to have similar expiration times.
	const default_overwrite = T;

	## Whether to run PRAGMA integrity_check on the underlying database
	## when creating a new store. For large databases on slow disks, this
	## can block cluster startup for multiple seconds. Note also that every
	## Zeek proecess owns its own database that it checks.
	const default_run_integrity_check = F;

	## Creates a new perstistent string store.
	##
	## name: A unqiue identifier for this table.
	##
	## create_expire: Interval for the expiration used by the storage framework.
	##
	## cache_expire: How many seconds to keep entries in the local cache
	##               after an insert or successful lookup. Caching is useful
	##               when the same entry is requested multiple times as it
	##               avoids the call to the storage framework.
	##
	##               XXX: This is not functional and will always use
	##                    default_cache_expire (3.0 sec by default).
	##                    See also PereKV::new_store().
	##
	## batch_period: Allows overriding default_batch_period..
	##
	## batch_max_size: Allows overriding default_batch_max_size.
	##
	## overwrite: Allows overriding default_overwrite.
	##
	## run_integrity_check: Whether to run PRAGMA integrity_check when openin
	##                      the SQLite database. For large databases, this can
	##                      result in significant startup delay.
	##
	## Returns: A new Store instance with an opened storage handle,
	##          or a Store instance with an empty name and unset
	##          storage_backend field.
	##
	## If the returned Store instance does not have storage_backend set,
	## an error happened during creation.
	global new_store: function(
		name: string,
		create_expire: interval,
		cache_expire: interval &default=default_cache_expire,
		batch_period: interval &default=default_batch_period,
		batch_max_size: count &default=default_batch_max_size,
		overwrite: bool &default=default_overwrite,
		run_integrity_check: bool &default=default_run_integrity_check
	): Store;

	## Insert a key-value pair into the store ``s``, overwriting any
	## existing local entry and publishing the inserted value on the
	## store specific topic.
	##
	## To prevent from spurious publishes when the local database contains
	## the key, check for the key with PereKV::contains().
	global insert: function(s: Store, key: string, value: string &default="1"): Storage::OperationResult;

	## Returns: ``T`` if the local database contains key ``key``, else ``F``.
	global contains: function(s: Store, key: string): bool;

	## Lookup the value of a key in the local database.
	##
	## This first uses the cache, then delegates to the
	## storage backend. You can asssume that if $value is
	## set, it'll be a string.
	global lookup: function(s: Store, key: string): Storage::OperationResult;
}

## A key-value pair insert operation.
type KeyValueInsertOp: record {
	key: string;
	value: string;
};

## A vector of key-value pair insert operations for more
## efficient cluster implementation.
type KeyValueInsertOps: vector of KeyValueInsertOp;

# Keeping track of the publish queue for a store.
type Queue: record {
	s: Store;
	last_publish_at: time &default=double_to_time(0.0);
	timer_scheduled: bool &default=F;
	entries: KeyValueInsertOps;
};

# Stores registered during new_store().
global stores: table[string] of Store;

# Publish queus  for KeyValueInsertOps per store.
global queues : table[string] of Queue;

# Just an error store.
global error_store = Store(
	$name="",
	$database_file="",
	$topic="",
	$create_expire=-1.0sec,
	$cache_expire=-1.0sec,
	$batch_period=-1.0sec,
	$batch_max_size=0,
	$overwrite=T,
);

# The new_store() implementation.
function new_store(
	name: string,
	create_expire: interval,
	cache_expire: interval &default=default_cache_expire,
	batch_period: interval &default=default_batch_period,
	batch_max_size: count &default=default_batch_max_size,
	overwrite: bool &default=default_overwrite,
	run_integrity_check: bool &default=default_run_integrity_check
): Store
	{
	if ( name in stores )
		{
		Reporter::warning(fmt("Attempted recreation of existing store: %s", name));
		return stores[name];
		}

	if ( /[-_:a-zA-Z0-9]/ !in name )
		{
		Reporter::error(fmt("Invalid store name '%s'", name));
		return error_store;
		}

	# When running standalone, use "zeek" as node name. I thought
	# that's the default, anyhow.
	local node = |Cluster::node| == 0 ? "zeek" : Cluster::node;
	local database_root_dir = Cluster::default_store_dir + "PereKV";
	local database_node_dir = database_root_dir + "/" + node;
	local database_file = database_node_dir + "/" + name + ".sqlite";
	local topic = base_topic + "." + name + ".";

	# XXX: Using the function argument here for &create_expire
	#      behaves like 0.0sec in 8.2.0 development, so use the
	#      module default for now, but it would be nice if that
	#      would actually work in the future.
	# local cache: table[string] of string = table() &create_expire=cache_expire;

	local cache: table[string] of string = table() &create_expire=default_cache_expire;

	local s = Store(
		$name=name,
		$database_file=database_file,
		$topic=topic,
		$create_expire=create_expire,
		$cache_expire=default_cache_expire,
		$cache=cache,
		$batch_period=batch_period,
		$batch_max_size=batch_max_size,
		$overwrite=overwrite,
	);


	if ( ! mkdir(database_root_dir) )
		{
		Reporter::error(fmt("Failed to create directory: %s", database_root_dir));
		return error_store;
		}

	if ( ! mkdir(database_node_dir) )
		{
		Reporter::error(fmt("Failed to create directory: %s", database_node_dir));
		return error_store;
		}

	local sqlite_opts = Storage::Backend::SQLite::Options(
		$database_path=database_file,
		$table_name="string_table",
	);

	if ( ! run_integrity_check )
		delete sqlite_opts$pragma_commands["integrity_check"];
	else if ( "integrity_check" !in sqlite_opts$pragma_commands )
		sqlite_opts$pragma_commands["integrity_check"] = "";

	local store_options = Storage::BackendOptions($sqlite=sqlite_opts);

	local res = Storage::Sync::open_backend(Storage::STORAGE_BACKEND_SQLITE, store_options, string, string);

	if ( res$code != Storage::SUCCESS )
		{
		Reporter::error(fmt("PereKV: Failed to open backend for store %s (%s): %s",
		                    name, database_file, res$error_str));
		return error_store;
		}

	# Finish up initialization.
	Cluster::subscribe(s$topic);
	s$storage_backend = res$value;
	queues[s$name] = Queue($s=s);
	stores[name] = s;

	Reporter::info(fmt("PereKV: Created store %s file=%s topic=%s", s$name, s$database_file, s$topic));
	return s;
	}

## Internal event for propagating KeyValueInsertOp to other nodes.
event insert_key_value_ops__internal(store_name: string, key_value_insert_ops: KeyValueInsertOps)
	{
	if ( store_name !in stores )
		{
		Reporter::error(fmt("Unexpected insert_key_value_ops__internal for unknown store '%s'", store_name));
		return;
		}

	local s = stores[store_name];

	# Protect from endless re-publishes.
	s$remote_insert_active = T;

	for ( _, kvop in key_value_insert_ops )
		PereKV::insert(s, kvop$key, kvop$value);

	s$remote_insert_active = F;

	# A manager in a Broker cluster redistributes to the workers,
	# unconditionally.
	if ( Cluster::local_node_type() == Cluster::MANAGER )
		if ( Cluster::backend == Cluster::CLUSTER_BACKEND_BROKER )
			Cluster::publish(Cluster::worker_topic,
			                 insert_key_value_ops__internal,
			                 store_name,
			                 key_value_insert_ops);
	}

function flush_queue(q: Queue)
	{
	Cluster::publish(q$s$topic, insert_key_value_ops__internal, q$s$name, q$entries);
	q$entries = vector();
	q$last_publish_at = network_time();
	}

event flush_queue_timer(q: Queue)
	{
	q$timer_scheduled = F;

	if ( |q$entries| > 0 )
		flush_queue(q);
	}

function queue_insert_op(s: Store, key: string, value: string)
	{

	local q = queues[s$name];

	q$entries += KeyValueInsertOp($key=key, $value=value);

	# This is the same logic as in the notice suppression package.
	#
	# We should probably have Cluster::publish_batched() or some such.
	if ( s$batch_max_size == 0 || s$batch_period == 0.0sec ||
		(|q$entries| == 1 && (network_time() - q$last_publish_at) > s$batch_period) )
		{
		flush_queue(q);
		}
	else if ( |q$entries| == s$batch_max_size )
		{
		flush_queue(q);
		}
	else if ( ! q$timer_scheduled )
		{
		schedule s$batch_period { flush_queue_timer(q) };
		q$timer_scheduled = T;
		}
	}

function insert(s: Store, key: string, value: string): Storage::OperationResult
	{
	# We do not check the cache: Always overwrite the entry. Users are
	## supposed to check with PereKV::contains() first.
	local put_args = Storage::PutArgs(
		$key=key,
		$value=value,
		$overwrite=s$overwrite,
		$expire_time=s$create_expire
	);

	local res = Storage::Sync::put(s$storage_backend, put_args);

	if ( res$code == Storage::SUCCESS )
		{
		# Queue this insert as an KeyValueInsertOp about this element, unless
		# this is currently processing a remote insert.
		if ( ! s$remote_insert_active )
			queue_insert_op(s, key, value);

		s$cache[key] = value;
		}
	else if ( res$code == Storage::KEY_EXISTS )
		{
		# Hmm, hmm. Nothing to do here. We could populate the
		# cache, but KEY_EXISTS anyhow happens only with overwrite=F
		}
	else
		{
		Reporter::error(fmt("PereKV::insert() failed for %s %s %s: %s",
		                    s$name, key, value, res));
		}

	return res;
	}

function contains(s: Store, key: string): bool
	{
	if ( key in s$cache )
		return T;

	local res = Storage::Sync::get(s$storage_backend, key);

	if ( res$code == Storage::SUCCESS )
		{
		s$cache[key] = res$value;
		return T;
		}
	else if ( res$code != Storage::KEY_NOT_FOUND )
		{
		Reporter::error(fmt("PereKV::contains() error for %s %s: %s",
		                    s$name, key, res));
		}

	return F;
	}

function lookup(s: Store, key: string): Storage::OperationResult
	{
	if ( key in s$cache )
		return Storage::OperationResult($code=Storage::SUCCESS, $value=s$cache[key]);

	local res = Storage::Sync::get(s$storage_backend, key);

	if ( res$code == Storage::SUCCESS )
		{
		s$cache[key] = res$value;
		return res$value;
		}
	else if ( res$code != Storage::KEY_NOT_FOUND )
		{
		Reporter::error(fmt("PereKV::lookup() error for %s %s: %s",
		                    s$name, key, res));
		}

	return res;
	}
