ALTER TABLE "sessions" ADD COLUMN "id_token" VARCHAR (255);
ALTER TABLE "sessions" ADD COLUMN "access_token" VARCHAR (255);
ALTER TABLE "sessions" ADD COLUMN "refresh_token" VARCHAR (255);
ALTER TABLE "sessions" ADD COLUMN "oidc_provider" VARCHAR (255);
