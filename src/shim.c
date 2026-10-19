/* Reads the issuer from the pg_hba.conf line that matched this connection.
 * pgrx does not bind Port/HbaLine, so this tiny shim does it in C. */
#include "postgres.h"

#include "libpq/hba.h"
#include "libpq/libpq-be.h"
#include "miscadmin.h"

const char *
pg_oauth_rs_hba_issuer(void)
{
	if (MyProcPort == NULL || MyProcPort->hba == NULL)
		return NULL;
	return MyProcPort->hba->oauth_issuer;
}
