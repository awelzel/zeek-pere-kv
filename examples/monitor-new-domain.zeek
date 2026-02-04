##! Example using dns_request() and creating a New_Domain_Resolved
##! notice if the original_query has not yet been observed. Uses
##! the pere-kv package for persisten storage of the query.

@load base/frameworks/notice
@load packages/pere-kv

module NewDomain::Demo;

export {
	redef enum Notice::Type += {
		New_Domain_Resolved,
	};

	# Holds patters for original_query values to ignore.
	# e.g., inserting  .*\.google\.com$ would ignore any
	# queries for google.com subdomains.
	const ignore_query_patterns: set[pattern] = {
		# ... patterns ....
	} &redef;

	# Expiration time for domains.
	const query_expiration = 7days &redef;
}

# This should be handled by PereKV::contains() below. Otherwise
# it's okay to have duplciated notices.
redef Notice::not_suppressed_types += {
	New_Domain_Resolved,
};

global query_store: PereKV::Store;

event zeek_init()
	{
	query_store = PereKV::new_store("new_domain_demo", query_expiration);
	}

event dns_request(c: connection, msg: dns_msg, query: string,
                  qtype: count, qclass: count, original_query: string)
	{
	if ( original_query in ignore_query_patterns )
		return;


	if ( PereKV::contains(query_store, original_query) )
		return;


	NOTICE(Notice::Info(
		$note=New_Domain_Resolved,
		$msg=fmt("Query %s (%s, %s) observed for the first time",
			 original_query, DNS::query_types[qtype],
			 DNS::classes[qclass]),
		$conn=c,
	));

	PereKV::insert(query_store, original_query);
	}
