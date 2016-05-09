This is the full function version of the Domain service.  It consists of two services.

The Program Key Domain Service receives attestations from CP programs and signs ProgramKeys.
Before signing Program keys the service:
	(1) Checks the program identity against the domain program database;
	(2) Checks that the endorsement cert valid and that neither the endorsement key
	    or its signer key has been revoked;
	(3) Retrieves machine characteristics based on endorsement cert;
	(4) Checks that the security characteristics for the machine meets domain
	    policy;
	(5) Retrieves the validity period for the domain;
	(6) Adds policy characteristics based on the machine and location to the Program cert.

The Revocation Service returns information about revoked certificates previously issued by
the Program Key Domain Service.

Both services implement logs of all requests and responses.

