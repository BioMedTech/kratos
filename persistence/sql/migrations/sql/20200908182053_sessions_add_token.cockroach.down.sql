ALTER TABLE "session" DROP COLUMN "id_token";COMMIT TRANSACTION;BEGIN TRANSACTION;
ALTER TABLE "session" DROP COLUMN "access_token";COMMIT TRANSACTION;BEGIN TRANSACTION;
ALTER TABLE "session" DROP COLUMN "refresh_token";COMMIT TRANSACTION;BEGIN TRANSACTION;
ALTER TABLE "session" DROP COLUMN "oidc_provider";COMMIT TRANSACTION;BEGIN TRANSACTION;
