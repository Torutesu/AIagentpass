import assert from "node:assert/strict";
import test from "node:test";
import { loadPostgresConfig } from "../../src/postgres/runtime.mjs";

test("requires authenticated PostgreSQL TLS and bounded pool settings", () => {
  const config=loadPostgresConfig({AGENTPASS_DATABASE_URL:"postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full",AGENTPASS_DATABASE_MAX_CONNECTIONS:"12"});
  assert.equal(config.maxConnections,12); assert.equal(config.statementTimeoutMs,8000); assert.equal(Object.isFrozen(config),true);
  for(const value of ["postgresql://db.example.test/agentpass?sslmode=verify-full","postgresql://agent:secret@db.example.test/agentpass?sslmode=require","http://agent:secret@db.example.test/agentpass?sslmode=verify-full","postgresql://agent:secret@db.example.test/agentpass?sslmode=verify-full&application_name=x"]){
    assert.throws(()=>loadPostgresConfig({AGENTPASS_DATABASE_URL:value}),TypeError);
  }
});
