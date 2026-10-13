// Prints an account and one encrypted login for the extension's Playwright test (e2e/extension): real key material at
// the production KDF cost, so the extension unlocks it exactly as it would a real account.
import { createAccount, encryptNewRecord } from "@clane-vault/crypto";

const password = process.env.FIXTURE_PASSWORD!, url = process.env.FIXTURE_URL!;
const acct = await createAccount(password);
const id = crypto.randomUUID();
const rec = await encryptNewRecord(id, { type: "login", title: "Example login", username: "ana@example.com", password: "hunter2-e2e", url }, acct.keys.userKey);
process.stdout.write(JSON.stringify({ material: acct.material, authKey: acct.authKey, record: { id, encBody: rec.encBody, wrappedRecordKey: rec.wrappedRecordKey } }));
