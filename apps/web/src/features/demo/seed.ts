import {
  aeadEncrypt, b64url, DEFAULT_KDF, encryptFolderName, encryptNewRecord, generateKeyPair, randomBytes, RECORD_TYPE_DEFS, serverRecordType, wrapKey,
  type AccountMaterial, type CustomField, type RecordBody, type UnlockedKeys,
} from "@clane-vault/crypto";
import { forOrg, type OrgApi } from "@/lib/api";
import { myMembershipKey, sealFolderKeyTo, syncMembershipKeys } from "@/lib/orgKeys";
import { startUpload, subscribeUploads, uploadsSnapshot } from "@/features/attachments/uploader";
import { AGREEMENT_PDF_NAME, agreementPdf, NORTHWIND_FOLDERS, PERSONAL_RECORDS, type NorthwindPermission, type NorthwindRecord } from "./northwind";

/**
 * Fills a new demo sandbox (docs/demo.md) with the Northwind sample data, in the browser and encrypted exactly like
 * anything a person adds: the same folder, record, sharing and upload code paths and endpoints as the app. Nothing
 * here is sent in plaintext.
 */

/** A record as the editor would save it: labels from northwind.ts mapped onto the type's template. Throws on a typo. */
export function toRecordBody(r: NorthwindRecord): RecordBody {
  const def = Object.values(RECORD_TYPE_DEFS).find((d) => d.label === r.type);
  if (!def) throw new Error(`unknown record type "${r.type}"`);
  const body: RecordBody = { v: 2, type: def.id, title: r.title, ...(r.notes ? { notes: r.notes } : {}) };
  const data: Record<string, string> = {};
  const set = (label: string, value: string) => {
    const f = def.fields.find((x) => x.label === label);
    if (!f) throw new Error(`"${label}" isn't a field of ${def.label}`);
    if (f.core) (body as unknown as Record<string, string>)[f.key] = value; else data[f.key] = value;
  };
  for (const [label, value] of Object.entries(r.fields ?? {})) set(label, value);
  for (const [label, option] of Object.entries(r.options ?? {})) {
    const o = def.fields.find((x) => x.label === label)?.options?.find((x) => x.label === option);
    if (!o) throw new Error(`"${option}" isn't an option of ${def.label} ${label}`);
    set(label, o.value);
  }
  if (Object.keys(data).length) body.data = data;
  const fields: CustomField[] = (r.custom ?? []).map((c, i) => ({ id: `demo-${i + 1}`, label: c.label, kind: c.kind, value: c.value }));
  if (fields.length) body.fields = fields;
  return body;
}

const PERMISSION: Record<NorthwindPermission, "edit" | "view" | "use"> = { "Can edit": "edit", "Can view": "view", "Use only": "use" };

/**
 * A made-up colleague's account material: a real key pair (folder keys are sealed to its public key), wrapped under keys
 * that are thrown away at once. Nobody holds them, so nobody can ever open the account; no KDF run is needed.
 */
export async function colleagueMaterial(): Promise<AccountMaterial> {
  const userKey = randomBytes(32), lost = randomBytes(32);
  const { publicKey, privateKey } = await generateKeyPair();
  const pub = b64url.encode(publicKey);
  const material: AccountMaterial = { kdfSalt: b64url.encode(randomBytes(16)), kdfParams: DEFAULT_KDF,
    wrappedUserKey: await aeadEncrypt(lost, userKey, "user-key"), publicKey: pub, wrappedPrivateKey: await aeadEncrypt(userKey, privateKey, `private-key:${pub}`) };
  userKey.fill(0); lost.fill(0); privateKey.fill(0);
  return material;
}

export interface Colleague { id: string; name: string; publicKey: string }

/** Resolves once an upload started with `startUpload` is done; rejects when it fails or is cancelled. */
function uploaded(key: string): Promise<void> {
  return new Promise((resolve, reject) => {
    const check = () => {
      const u = uploadsSnapshot().find((x) => x.key === key);
      if (!u || u.status === "done") { stop(); resolve(); }
      else if (u.status === "failed" || u.status === "cancelled") { stop(); reject(new Error(u.error ?? "upload failed")); }
    };
    const stop = subscribeUploads(check);
    check();
  });
}

async function batches(http: OrgApi, records: object[]) {
  for (let i = 0; i < records.length; i += 25) await http.post("/records/batch", { records: records.slice(i, i + 25) });
}

/**
 * Seeds the sandbox: the visitor's membership key in the organisation, the shared folders (sealed to the visitor and to
 * the made-up colleagues), their records, one file on the production server, and a few Personal items.
 */
export async function seedDemo(o: { orgId: string; userId: string; keys: UnlockedKeys; colleagues: Colleague[] }): Promise<void> {
  const { orgId, userId, keys } = o;
  const team = forOrg(orgId), personal = forOrg(null);
  // The membership key first (as the app does when it enters an organisation): folder keys are sealed to it.
  await syncMembershipKeys(team, orgId, userId, keys);
  const myKey = await myMembershipKey(team, orgId, userId, keys.userKey);
  const me = { id: userId, publicKey: b64url.encode(keys.publicKey), membershipKey: myKey };
  const byName = new Map(o.colleagues.map((c) => [c.name, c]));
  let server: { id: string; recordKey: Uint8Array } | null = null;
  const toZero: Uint8Array[] = [];
  try {
    await Promise.all(NORTHWIND_FOLDERS.map(async (f) => {
      const folderId = crypto.randomUUID();
      const folderKey = randomBytes(32);
      toZero.push(folderKey);
      const ids = { orgId, folderId };
      await team.post("/folders", { id: folderId, kind: "team", encName: await encryptFolderName(folderId, f.name, folderKey), ...(await sealFolderKeyTo(folderKey, ids, me, me.id)) });
      for (const [person, perm] of f.people) {
        const c = byName.get(person.name);
        if (c) await team.post(`/folders/${folderId}/members`, { userId: c.id, permission: PERMISSION[perm], ...(await sealFolderKeyTo(folderKey, ids, { id: c.id, publicKey: c.publicKey, membershipKey: null }, me.id)) });
      }
      const records = await Promise.all(f.records.map(async (r) => {
        const id = crypto.randomUUID();
        const body = toRecordBody(r);
        const enc = await encryptNewRecord(id, body, keys.userKey);
        const folderWrapped = await wrapKey(enc.recordKey, folderKey, `record-key:${id}`);
        if (r.title === "Production web server") server = { id, recordKey: enc.recordKey }; else enc.recordKey.fill(0);
        return { id, folderId, type: serverRecordType(body), encBody: enc.encBody, wrappedRecordKey: folderWrapped, ownerWrappedRecordKey: enc.wrappedRecordKey };
      }));
      await batches(team, records);
    }));
    const mine = await Promise.all(PERSONAL_RECORDS.map(async (r) => {
      const id = crypto.randomUUID();
      const body = toRecordBody(r);
      const enc = await encryptNewRecord(id, body, keys.userKey);
      enc.recordKey.fill(0);
      return { id, folderId: null, type: serverRecordType(body), encBody: enc.encBody, wrappedRecordKey: enc.wrappedRecordKey };
    }));
    await batches(personal, mine);
    // One file: the maintenance agreement on the production server, through the app's own uploader.
    const s = server as { id: string; recordKey: Uint8Array } | null;
    if (s) {
      toZero.push(s.recordKey);
      const file = Object.assign(new Blob([agreementPdf() as BlobPart], { type: "application/pdf" }), { name: AGREEMENT_PDF_NAME });
      await uploaded(startUpload({ api: team, recordId: s.id, recordKey: s.recordKey, file }));
    }
  } finally {
    for (const k of toZero) k.fill(0);
  }
}
