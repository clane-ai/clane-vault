/** Microsoft 365 delegated sign-in helpers for the email settings (docs/email.md, "Microsoft 365 — delegated sign-in"). */

/** Leaving for Microsoft's sign-in page (a seam for tests). */
export const browser = { go: (url: string) => window.location.assign(url) };

/** What the sign-in callback's `?m365_error=` means (with the AADSTS code when Microsoft gave one). */
export function m365ConnectError(code: string, aadsts: string | null, redirectUri: string | undefined): string {
  const uri = redirectUri ?? "the Redirect URI shown here";
  const tag = aadsts ? ` (AADSTS${aadsts})` : "";
  switch (code) {
    case "consent_required": return `Your organisation requires an administrator to approve this app${tag}. In Microsoft Entra, open the app registration → API permissions → Grant admin consent, then sign in again.`;
    case "redirect_uri_mismatch": return `The redirect URI isn't registered for this app${tag}. In the app registration → Authentication → Web, add exactly: ${uri}`;
    case "app_not_found": return `The application (client) ID wasn't found in this tenant${tag}. Check the client ID and the tenant ID.`;
    case "bad_secret": return `Microsoft rejected the client secret${tag}. Copy the secret's Value (not its Secret ID) into Client secret.`;
    case "secret_expired": return `The client secret has expired${tag}. Create a new one under Certificates & secrets and enter it here.`;
    case "tenant_not_found": return `Microsoft can't find that tenant${tag}. Check the directory (tenant) ID or domain.`;
    case "spa_platform": return `The redirect URI is registered as a single-page application${tag}. Register it under the Web platform instead (the client secret stays on the server).`;
    case "code_expired": return "The sign-in took too long or was used twice. Sign in again.";
    case "access_denied": return `The sign-in was cancelled or consent was declined${tag}.`;
    case "no_refresh_token": return "Microsoft didn't grant offline access (offline_access). Add it to the app's API permissions and sign in again.";
    case "send_scope_missing": return "Microsoft didn't grant Mail.Send. Add the Microsoft Graph Mail.Send delegated permission and sign in again.";
    case "shared_scope_missing": return "Sending from a shared mailbox needs the Microsoft Graph Mail.Send.Shared delegated permission. Add it (and grant consent if your tenant requires it), then sign in again.";
    case "state": return "This sign-in expired or was started in another browser. Sign in again from here.";
    case "forbidden": return "You can no longer change these email settings.";
    case "settings_changed": return "The email settings changed during the sign-in. Sign in again.";
    case "secret_missing": return "The stored client secret can't be read any more. Enter it again, save, then sign in.";
    case "id_token": return "Microsoft's answer didn't match this sign-in request. Sign in again.";
    case "unreachable": return "Couldn't reach Microsoft from the server. Check outbound HTTPS to login.microsoftonline.com and graph.microsoft.com.";
    default: return `Signing in with Microsoft failed${tag}. Try again.`;
  }
}
