-- Demo roles. They log in with OAuth only (see pg_hba.conf), so they have no password.
CREATE ROLE alice LOGIN;
-- bob's email is bob@other.example, which pg_ident.conf does not map: his logins are refused.
CREATE ROLE bob LOGIN;
