import { PrismaClient } from "@prisma/client";
export const createPrisma = (url: string) => new PrismaClient({ datasourceUrl: url });
