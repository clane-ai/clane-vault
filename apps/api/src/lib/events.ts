import type { Prisma, PrismaClient } from "@prisma/client";

/** `meta`: small, non-secret details such as counts or a request id. */
export interface EventInput { orgId?: string; actorId?: string; action: string; recordId?: string; folderId?: string; targetUserId?: string; ip?: string; userAgent?: string; meta?: Prisma.InputJsonValue }

export async function logEvent(prisma: PrismaClient | Prisma.TransactionClient, e: EventInput): Promise<void> {
  await prisma.event.create({ data: e });
}
