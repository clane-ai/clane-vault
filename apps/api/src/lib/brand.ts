import type { PrismaClient } from "@prisma/client";
import { z } from "zod";
import { cleanName } from "./names.js";

export const BRAND_ID = "instance";
export const BRAND_NAME_MAX = 40;

/** A product name or short name set at runtime: cleaned, 1–40 characters, no markup characters. */
export const brandName = z.string().max(200).transform(cleanName)
  .refine((s) => s.length >= 1 && s.length <= BRAND_NAME_MAX, { message: "length" })
  .refine((s) => !/[<>]/.test(s), { message: "markup" });

export interface RuntimeBrand { productName: string | null; shortName: string | null; logoSha256: string | null }

const TTL_MS = 15_000;

/**
 * The instance's runtime branding (docs/branding.md), cached for a few seconds: emails and the authenticator issuer use
 * the stored product name when an instance admin set one, else PRODUCT_NAME. Changes made through this API apply at once
 * (`invalidate`); other API processes pick them up within the TTL.
 */
export class BrandCache {
  private cached: { at: number; value: RuntimeBrand } | null = null;
  constructor(private prisma: PrismaClient, private fallbackName: string) {}

  async get(): Promise<RuntimeBrand> {
    if (this.cached && Date.now() - this.cached.at < TTL_MS) return this.cached.value;
    const row = await this.prisma.instanceBrand.findUnique({ where: { id: BRAND_ID }, select: { productName: true, shortName: true, logoSha256: true } });
    const value = { productName: row?.productName ?? null, shortName: row?.shortName ?? null, logoSha256: row?.logoSha256 ?? null };
    this.cached = { at: Date.now(), value };
    return value;
  }

  /** The product name people see in emails and their authenticator app. */
  async productName(): Promise<string> {
    try { return (await this.get()).productName ?? this.fallbackName; }
    catch { return this.fallbackName; }
  }

  invalidate() { this.cached = null; }
}
