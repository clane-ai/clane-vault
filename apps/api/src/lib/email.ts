import type { Mailer } from "./mailer.js";

/** The invite email's subject and plain-text body, named after the product (PRODUCT_NAME). */
export function inviteEmail(productName: string, inviteUrl: string, orgName?: string): { subject: string; text: string } {
  const to = orgName ? `${orgName} on ${productName}` : productName;
  return {
    subject: `You're invited to ${to}`,
    text: `You've been invited to ${to}, the team password manager.\n\nCreate your account (the link works for 7 days):\n${inviteUrl}\n\nIf you weren't expecting this, ignore this email.`,
  };
}

/** Sent when someone uses a recovery kit or an admin recovery link: the owner should know their master password changed. */
export function recoveryUsedEmail(productName: string, via: "kit" | "admin", at: Date): { subject: string; text: string } {
  const how = via === "kit" ? "with your recovery kit" : "through admin account recovery";
  return {
    subject: `Your ${productName} master password was reset`,
    text: `Your ${productName} master password was reset ${how} on ${at.toUTCString()}.

All your other sessions were signed out.${via === "kit" ? " Your old recovery kit no longer works; you were asked to create a new one." : ""}

If this wasn't you, contact your ${productName} admin right away.`,
  };
}

/** Sent when someone asks an admin to reset the master password for this address. */
export function recoveryRequestedEmail(productName: string, orgName: string): { subject: string; text: string } {
  return {
    subject: `Password reset requested for your ${productName} account`,
    text: `Someone asked the admins of ${orgName} in ${productName} to reset the master password for this account.

If it was you, wait for an admin to send you a one-time recovery link. Admins never ask for your password or your 2FA codes.

If it wasn't you, tell your admin; nothing changes unless an admin approves it and the link is used together with your two-step sign-in code.`,
  };
}

/** Sent to the member when an admin opens their escrowed key to approve a reset, and when the link is ready. */
export function recoveryAdminActionEmail(productName: string, what: "escrow_opened" | "approved", adminName: string, orgName: string): { subject: string; text: string } {
  const line = what === "escrow_opened"
    ? `${adminName}, an admin of ${orgName}, opened your escrowed ${orgName} key on their device to approve a master-password reset for your ${productName} account. It gives access to what you hold in ${orgName} only, never your private items or other organisations.`
    : `${adminName}, an admin of ${orgName}, approved a master-password reset for your ${productName} account and was given a one-time link (it works for 24 hours) to send you.`;
  return {
    subject: `${productName}: an admin is resetting your master password`,
    text: `${line}\n\nIf you asked for this, wait for the link and open it yourself. If you didn't, tell another admin right away: nothing changes until the link is used with your two-step sign-in code.`,
  };
}

/** Sent to everyone when an admin turns admin account recovery on. */
export function adminRecoveryOnEmail(productName: string, adminName: string, orgName: string): { subject: string; text: string } {
  return {
    subject: `${productName}: admin account recovery was turned on in ${orgName}`,
    text: `${adminName} turned on admin account recovery for ${orgName} in ${productName}.\n\nWhen you next unlock your vault you'll be asked to confirm. After that, the admins of ${orgName} can help you reset your master password and restore your access to ${orgName}'s shared folders and items. They can't open your private items or other organisations' items: your recovery kit restores those.\n\nIf you have questions, ask your admin.`,
  };
}

/** Sent to a member when an admin resets their two-step sign-in. */
export function twoFactorResetEmail(productName: string, adminName: string, at: Date): { subject: string; text: string } {
  return {
    subject: `${productName}: your two-step sign-in was reset`,
    text: `${adminName} reset the two-step sign-in (authenticator) for your ${productName} account on ${at.toUTCString()}. You were signed out everywhere and will set up a new authenticator the next time you sign in.\n\nIf this wasn't expected, contact another ${productName} admin right away.`,
  };
}

/** Sent to every existing admin when a new admin account becomes active. */
export function adminAddedEmail(productName: string, name: string, email: string, orgName: string): { subject: string; text: string } {
  return {
    subject: `${productName}: new admin ${email} in ${orgName}`,
    text: `${name} (${email}) is now an admin of ${orgName} in ${productName}.\n\nIf you didn't expect this, check People and the event log, and disable the account if needed.`,
  };
}

type Log = { warn: (o: object, m: string) => void };

/** Sends the invite (the inviting org's email settings, else the instance's). False (never throws) when it can't. */
export async function sendInviteEmail(mail: Mailer, productName: string, to: string, inviteUrl: string, log: Log, org: { id: string; name: string }): Promise<boolean> {
  return mail.send(to, inviteEmail(productName, inviteUrl, org.name), log, org.id);
}

/** Sent to someone who already has an account when an organisation invites them: they accept in the app. */
export function orgInvitationEmail(productName: string, orgName: string, inviterName: string, url: string): { subject: string; text: string } {
  return {
    subject: `${inviterName} invited you to ${orgName} on ${productName}`,
    text: `${inviterName} invited you to join ${orgName} on ${productName}.\n\nSign in with your existing account and accept the invitation from the organisation menu at the top left:\n${url}\n\nIf you weren't expecting this, decline it or ignore this email.`,
  };
}

/**
 * Sends one plain-text email (docs/email.md). Security notices never pass `orgId` (they go out with the instance's
 * settings, so an organisation's admins can't silence or read them through their own mail server); invites do: with
 * `orgId`, that organisation's email settings when it has its own,
 * otherwise the instance settings, otherwise RESEND_API_KEY / EMAIL_FROM. False (never throws) when email is not
 * configured or sending fails.
 */
export function sendEmail(mail: Mailer, to: string, msg: { subject: string; text: string }, log: Log, orgId?: string | null): Promise<boolean> {
  return mail.send(to, msg, log, orgId);
}

/**
 * Email domain auto-join (docs/provisioning.md): the link someone asked for with an address in a domain the organisation
 * verified. `existingAccount`: the link is claimed signed in (then accepted from the organisation menu).
 */
export function domainJoinEmail(productName: string, orgName: string, url: string, existingAccount: boolean): { subject: string; text: string } {
  return {
    subject: `Join ${orgName} on ${productName}`,
    text: existingAccount
      ? `You asked to join ${orgName} on ${productName} with this address.\n\nOpen this link, sign in with your existing account, and accept the invitation (the link works for 7 days):\n${url}\n\nIf you didn't ask for this, ignore this email: nothing changes.`
      : `You asked to join ${orgName} on ${productName} with this address.\n\nCreate your account (the link works for 7 days):\n${url}\n\nIf you didn't ask for this, ignore this email: nothing changes.`,
  };
}

/** Sent to an organisation's owners and admins when its email domain auto-join changes (security relevant). */
export function domainJoinChangedEmail(productName: string, orgName: string, actorName: string, enabled: boolean, domains: string[]): { subject: string; text: string } {
  return {
    subject: `${productName}: email domain auto-join ${enabled ? "changed" : "was turned off"} in ${orgName}`,
    text: enabled
      ? `${actorName} changed email domain auto-join of ${orgName} in ${productName}. Anyone with a verified address in ${domains.join(", ") || "its verified domains"} can ask to join as a member.\n\nIf you didn't expect this, check Organisation settings → Single sign-on and the event log.`
      : `${actorName} turned off email domain auto-join of ${orgName} in ${productName}.`,
  };
}

/** HOSTED_MODE sign-up: the 6-digit code that proves the person registering reads the invited address. */
export function signupCodeEmail(productName: string, orgName: string, code: string): { subject: string; text: string } {
  return {
    subject: `${productName} sign-up code: ${code}`,
    text: `Your code to create your ${productName} account (invited by ${orgName}) is:\n\n    ${code}\n\nIt works for 10 minutes. If you didn't ask for it, ignore this email.`,
  };
}

/** Sent to an organisation's owners and admins when its single sign-on settings change (security relevant). */
export function ssoChangedEmail(productName: string, orgName: string, actorName: string, what: string[]): { subject: string; text: string } {
  const labels: Record<string, string> = { created: "single sign-on was set up", removed: "single sign-on was turned off", issuer: "the identity provider (issuer) changed",
    clientId: "the client ID changed", clientSecret: "the client secret changed", requireSso: "\"Require SSO for members\" changed",
    trustIdpMfa: "\"Trust the identity provider's MFA\" changed", autoJoin: "\"Auto-join verified domain users\" changed" };
  return {
    subject: `${productName}: single sign-on settings changed in ${orgName}`,
    text: `${actorName} changed the single sign-on settings of ${orgName} in ${productName}:\n\n${what.map((w) => `- ${labels[w] ?? w}`).join("\n")}\n\nIf you didn't expect this, check Organisation settings → Single sign-on and the event log.`,
  };
}
