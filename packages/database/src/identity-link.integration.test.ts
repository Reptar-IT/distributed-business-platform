import { randomUUID } from "node:crypto";
import { Pool } from "pg";
import { afterAll, beforeAll, describe, expect, it } from "vitest";

const databaseUrl=process.env.DBP_AUDIT_TEST_DATABASE_URL;
const suite=databaseUrl?describe:describe.skip;
if (databaseUrl && !/^\/dbp_audit_test(?:_[a-z0-9]+)?$/.test(new URL(databaseUrl).pathname)) {
  throw new Error("DBP_AUDIT_TEST_DATABASE_URL must point to a dedicated disposable dbp_audit_test database");
}

suite("verified OIDC identity-link PostgreSQL integration",()=>{
  const admin=new Pool({connectionString:databaseUrl,max:8});
  let operatorUrl="";
  let callbackUrl="";
  let runtimeUrl="";
  async function loginRole(role:string,parent:string):Promise<string>{
    await admin.query(`DO $$ BEGIN IF NOT EXISTS(SELECT 1 FROM pg_roles WHERE rolname='${role}') THEN CREATE ROLE ${role} LOGIN; END IF; END $$`);
    await admin.query(`GRANT ${parent} TO ${role}`);
    const url=new URL(databaseUrl!);url.username=role;url.password="";return url.toString();
  }
  async function createUser(status="ACTIVE"):Promise<string>{
    const id=randomUUID();
    await admin.query(`INSERT INTO public.platform_users(id,"displayName",status,"createdAt","updatedAt") VALUES($1,$2,$3,CURRENT_TIMESTAMP,CURRENT_TIMESTAMP)`,[id,`Test user ${id}`,status]);
    return id;
  }
  async function begin(userId:string,issuer="https://issuer.example.test/realm"):Promise<string>{
    const operator=new Pool({connectionString:operatorUrl,max:1});
    try{return (await operator.query<{id:string}>("SELECT public.begin_platform_identity_link($1::uuid,$2) AS id",[userId,issuer])).rows[0]!.id;}
    finally{await operator.end();}
  }
  async function complete(challengeId:string,platformUserId:string,subject:string,issuer="https://issuer.example.test/realm",verifiedAt=new Date()):Promise<string>{
    const callback=new Pool({connectionString:callbackUrl,max:1});
    try{return (await callback.query<{outcome:string}>("SELECT public.complete_platform_identity_link($1::uuid,$2::uuid,$3,$4,$5) AS outcome",[challengeId,platformUserId,issuer,subject,verifiedAt])).rows[0]!.outcome;}
    finally{await callback.end();}
  }

  beforeAll(async()=>{
    operatorUrl=await loginRole("dbp_identity_link_operator_test","dbp_identity_link_operator");
    callbackUrl=await loginRole("dbp_identity_link_callback_test","dbp_identity_link_callback");
    runtimeUrl=await loginRole("dbp_identity_link_runtime_test","dbp_runtime");
  });
  afterAll(async()=>{await admin.end();});

  it("binds a fresh exact issuer/subject proof to an existing active user and rejects replay",async()=>{
    const userId=await createUser();
    const challengeId=await begin(userId);
    expect(await complete(challengeId,userId,"subject-success")).toBe("LINKED");
    expect(await complete(challengeId,userId,"subject-success")).toBe("REJECTED");
    const replayAudit=await admin.query<{count:string}>(
      `SELECT count(*)::text AS count FROM public.authorization_audit_events
        WHERE "eventType"='platform-identity-link-rejected' AND "correlationId"=$1`,[challengeId],
    );
    expect(replayAudit.rows[0]!.count).toBe("1");
    const mapped=await admin.query<{user_id:string;email:string|null;email_verified:boolean;verified:boolean;operator:string;issuer:string;subject:string}>(
      `SELECT ui."userId" AS user_id,ui.email,ui."emailVerified" AS email_verified,(ver.id IS NOT NULL) AS verified,
              ver."initiatingOperator" AS operator,ver.issuer,ver.subject
         FROM public.user_identities ui JOIN public.user_identity_verifications ver ON ver."userIdentityId"=ui.id
        WHERE ui.issuer=$1 AND ui.subject=$2`,["https://issuer.example.test/realm","subject-success"],
    );
    expect(mapped.rows[0]).toMatchObject({user_id:userId,email:null,email_verified:false,verified:true,operator:"dbp_identity_link_operator_test",issuer:"https://issuer.example.test/realm",subject:"subject-success"});
    const audit=await admin.query<{actor_id:string;outcome:string}>(
      `SELECT "actorId" AS actor_id,"outcome" FROM public.authorization_audit_events
        WHERE "eventType"='platform-identity-link-challenge-issued' AND "correlationId"=$1`,[challengeId],
    );
    expect(audit.rows[0]).toEqual({actor_id:"dbp_identity_link_operator_test",outcome:"challenge_issued"});
  });

  it("rejects mismatched issuer, stale authentication, and inactive users",async()=>{
    const userId=await createUser();
    const wrongIssuer=await begin(userId);
    expect(await complete(wrongIssuer,userId,"issuer-mismatch","https://other.example.test/realm")).toBe("REJECTED");
    const stale=await begin(userId);
    expect(await complete(stale,userId,"stale-proof",undefined,new Date(Date.now()-10*60_000))).toBe("REJECTED");
    const inactive=await createUser();
    const inactiveChallenge=await begin(inactive);
    await admin.query(`UPDATE public.platform_users SET status='SUSPENDED' WHERE id=$1`,[inactive]);
    expect(await complete(inactiveChallenge,inactive,"inactive-user")).toBe("REJECTED");
    const count=await admin.query<{count:string}>(`SELECT count(*)::text AS count FROM public.user_identities WHERE subject IN ('issuer-mismatch','stale-proof','inactive-user')`);
    expect(count.rows[0]!.count).toBe("0");
  });

  it("prevents identity reassignment and serializes concurrent claims for one subject",async()=>{
    const firstUser=await createUser();
    const secondUser=await createUser();
    const firstChallenge=await begin(firstUser);
    const secondChallenge=await begin(secondUser);
    const results=await Promise.all([
      complete(firstChallenge,firstUser,"contended-subject"),
      complete(secondChallenge,secondUser,"contended-subject"),
    ]);
    expect(results.sort()).toEqual(["LINKED","REJECTED"]);
    const mapping=await admin.query<{user_id:string;count:string}>(
      `SELECT ui."userId" AS user_id,count(ver.id)::text AS count FROM public.user_identities ui
       LEFT JOIN public.user_identity_verifications ver ON ver."userIdentityId"=ui.id
       WHERE ui.issuer=$1 AND ui.subject=$2 GROUP BY ui."userId"`,["https://issuer.example.test/realm","contended-subject"],
    );
    expect(mapping.rows).toHaveLength(1);
    expect([firstUser,secondUser]).toContain(mapping.rows[0]!.user_id);
    expect(mapping.rows[0]!.count).toBe("1");
  });

  it("binds holder confirmation to the database-selected PlatformUser and denies operator access to callback lookup",async()=>{
    const selected=await createUser();
    const attackerSelected=await createUser();
    const challengeId=await begin(selected);
    const callback=new Pool({connectionString:callbackUrl,max:1});
    const operator=new Pool({connectionString:operatorUrl,max:1});
    try{
      const target=await callback.query<{platform_user_id:string}>("SELECT * FROM public.get_platform_identity_link_confirmation($1::uuid)",[challengeId]);
      expect(target.rows[0]!.platform_user_id).toBe(selected);
      const substituted=await callback.query<{complete_platform_identity_link:string}>(
        "SELECT public.complete_platform_identity_link($1::uuid,$2::uuid,$3,$4,$5) AS complete_platform_identity_link",
        [challengeId,attackerSelected,"https://issuer.example.test/realm","confirmation-substitution",new Date()],
      );
      expect(substituted.rows[0]!.complete_platform_identity_link).toBe("REJECTED");
      await expect(operator.query("SELECT * FROM public.get_platform_identity_link_confirmation($1::uuid)",[challengeId])).rejects.toThrow();
      const mapping=await admin.query("SELECT 1 FROM public.user_identities WHERE issuer=$1 AND subject=$2",["https://issuer.example.test/realm","confirmation-substitution"]);
      expect(mapping.rowCount).toBe(0);
    }finally{await Promise.all([callback.end(),operator.end()]);}
  });

  it("denies ordinary runtime writes and callback use of operator-only initiation",async()=>{
    const unprivilegedUrl=await loginRole("dbp_identity_link_unprivileged_test","dbp_runtime");
    const unprivileged=new Pool({connectionString:unprivilegedUrl,max:1});
    try{
      const privileges=await admin.query<{operator_member:boolean;callback_member:boolean;begin_execute:boolean;issue_owner_execute:boolean}>(
        `SELECT pg_has_role('dbp_identity_link_unprivileged_test','dbp_identity_link_operator','member') AS operator_member,
                pg_has_role('dbp_identity_link_unprivileged_test','dbp_identity_link_callback','member') AS callback_member,
                has_function_privilege('dbp_identity_link_unprivileged_test','public.begin_platform_identity_link(uuid,text)','EXECUTE') AS begin_execute,
                has_function_privilege('dbp_identity_link_unprivileged_test','public.issue_platform_owner_bootstrap_credential(uuid,uuid,text,text,bytea)','EXECUTE') AS issue_owner_execute`,
      );
      expect(privileges.rows[0]).toEqual({operator_member:false,callback_member:false,begin_execute:false,issue_owner_execute:false});
      await expect(unprivileged.query("SELECT public.begin_platform_identity_link($1::uuid,$2)",[randomUUID(),"https://issuer.example.test/realm"])).rejects.toThrow();
    }finally{await unprivileged.end();}
    const runtime=new Pool({connectionString:runtimeUrl,max:1});
    try{
      await expect(runtime.query("SELECT public.begin_platform_identity_link($1::uuid,$2)",[randomUUID(),"https://issuer.example.test/realm"])).rejects.toThrow();
      await expect(runtime.query("INSERT INTO public.user_identity_verifications(id) VALUES($1)",[randomUUID()])).rejects.toThrow();
    }finally{await runtime.end();}
    const callback=new Pool({connectionString:callbackUrl,max:1});
    try{
      await expect(callback.query("SELECT public.begin_platform_identity_link($1::uuid,$2)",[randomUUID(),"https://issuer.example.test/realm"])).rejects.toThrow();
    }finally{await callback.end();}
    const operator=new Pool({connectionString:operatorUrl,max:1});
    try{
      const privileges=await admin.query<{operator_login:boolean;operator_admin_option:boolean;operator_can_insert_user:boolean;operator_can_update_identity:boolean;operator_can_issue_owner:boolean}>(
        `SELECT (SELECT rolcanlogin FROM pg_roles WHERE rolname='dbp_identity_link_operator') AS operator_login,
                (SELECT m.admin_option FROM pg_auth_members m WHERE m.roleid='dbp_identity_link_operator'::regrole AND m.member='dbp_identity_link_operator_test'::regrole) AS operator_admin_option,
                has_table_privilege('dbp_identity_link_operator_test','public.platform_users','INSERT') AS operator_can_insert_user,
                has_table_privilege('dbp_identity_link_operator_test','public.user_identities','UPDATE') AS operator_can_update_identity,
                has_function_privilege('dbp_identity_link_operator_test','public.issue_platform_owner_bootstrap_credential(uuid,uuid,text,text,bytea)','EXECUTE') AS operator_can_issue_owner`,
      );
      expect(privileges.rows[0]).toEqual({operator_login:false,operator_admin_option:false,operator_can_insert_user:false,operator_can_update_identity:false,operator_can_issue_owner:false});
      await expect(operator.query(`INSERT INTO public.platform_users(id,"displayName") VALUES($1,'forbidden')`,[randomUUID()])).rejects.toThrow();
    }finally{await operator.end();}
  });

  it("rolls back the mapping and challenge if its audit append fails",async()=>{
    const userId=await createUser();
    const challengeId=await begin(userId);
    await admin.query(`CREATE FUNCTION public.identity_link_test_fail_audit() RETURNS trigger LANGUAGE plpgsql AS $$
      BEGIN IF NEW."eventType"='platform-identity-link-verified' THEN RAISE EXCEPTION 'injected identity audit failure'; END IF; RETURN NEW; END $$`);
    await admin.query(`CREATE TRIGGER identity_link_test_fail_audit BEFORE INSERT ON public.authorization_audit_events FOR EACH ROW EXECUTE FUNCTION public.identity_link_test_fail_audit()`);
    try{
      const callback=new Pool({connectionString:callbackUrl,max:1});
      try{await expect(callback.query("SELECT public.complete_platform_identity_link($1::uuid,$2::uuid,$3,$4,$5)",[challengeId,userId,"https://issuer.example.test/realm","audit-rollback",new Date()])).rejects.toThrow(/injected identity audit failure/);}
      finally{await callback.end();}
    }finally{
      await admin.query("DROP TRIGGER identity_link_test_fail_audit ON public.authorization_audit_events");
      await admin.query("DROP FUNCTION public.identity_link_test_fail_audit()");
    }
    const state=await admin.query<{status:string;identity_count:string}>(
      `SELECT c.status,(SELECT count(*)::text FROM public.user_identities WHERE subject='audit-rollback') AS identity_count
       FROM public.identity_link_challenges c WHERE c.id=$1`,[challengeId],
    );
    expect(state.rows[0]).toEqual({status:"PENDING",identity_count:"0"});
  });
});
