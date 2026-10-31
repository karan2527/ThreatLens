import { describe, expect, it } from "vitest";

import { indicatorSchema, scanRequestSchema } from "./validation";

describe("indicatorSchema", () => {
  it("accepts supported indicator shapes", () => {
    expect(indicatorSchema.safeParse("https://example.com/path").success).toBe(true);
    expect(indicatorSchema.safeParse("203.0.113.10").success).toBe(true);
    expect(indicatorSchema.safeParse("example.com").success).toBe(true);
    expect(indicatorSchema.safeParse("a".repeat(64)).success).toBe(true);
  });

  it("rejects unsafe URLs and whitespace", () => {
    expect(indicatorSchema.safeParse("javascript:alert(1)").success).toBe(false);
    expect(indicatorSchema.safeParse("https://user:pass@example.com").success).toBe(false);
    expect(indicatorSchema.safeParse("example .com").success).toBe(false);
  });
});

describe("scanRequestSchema", () => {
  it("allows an optional explicit indicator type", () => {
    expect(
      scanRequestSchema.safeParse({ indicator: "example.com", type: "domain" }).success,
    ).toBe(true);
    expect(scanRequestSchema.safeParse({ indicator: "example.com", type: "hash" }).success).toBe(
      true,
    );
  });
});
