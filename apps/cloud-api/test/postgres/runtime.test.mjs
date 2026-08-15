import assert from "node:assert/strict";
import test from "node:test";
import { loadPostgresConfig } from "../../src/postgres/runtime.mjs";

test("requires authenticated PostgreSQL TLS and bounded pool settings", () => {
  const base={
    AGENTPASS_DATABASE_URL:"postgresql://agentpass_app:secret@db.example.test/agentpass?sslmode=verify-full",
    AGENTPASS_MIGRATION_DATABASE_URL:"postgresql://agentpass_migrator:secret@db.example.test/agentpass?sslmode=verify-full",
    AGENTPASS_SIGNER_DATABASE_URL:"postgresql://agentpass_signer:secret@db.example.test/agentpass?sslmode=verify-full"
  };
  const config=loadPostgresConfig({...base,AGENTPASS_DATABASE_MAX_CONNECTIONS:"12",AGENTPASS_SIGNER_DATABASE_MAX_CONNECTIONS:"6"});
  assert.equal(config.maxConnections,12); assert.equal(config.signerMaxConnections,6); assert.equal(config.statementTimeoutMs,8000); assert.equal(Object.isFrozen(config),true);
  for(const value of ["postgresql://db.example.test/agentpass?sslmode=verify-full","postgresql://agent:secret@db.example.test/agentpass?sslmode=require","http://agent:secret@db.example.test/agentpass?sslmode=verify-full","postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full&application_name=x","postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full&sslmode=no-verify"]){
    assert.throws(()=>loadPostgresConfig({...base,AGENTPASS_DATABASE_URL:value}),TypeError);
  }
  assert.throws(()=>loadPostgresConfig({...base,AGENTPASS_MIGRATION_DATABASE_URL:undefined}),/AGENTPASS_MIGRATION_DATABASE_URL/u);
  assert.throws(()=>loadPostgresConfig({...base,AGENTPASS_SIGNER_DATABASE_URL:base.AGENTPASS_DATABASE_URL}),/must be distinct/u);
  assert.throws(()=>loadPostgresConfig({...base,AGENTPASS_SIGNER_DATABASE_URL:"postgresql://agentpass_signer:secret@other.example.test/agentpass?sslmode=verify-full"}),/same authority database/u);
});
