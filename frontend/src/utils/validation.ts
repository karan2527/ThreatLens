import { z } from "zod";

// UX-only validation. The backend remains the security authority.
const hashPattern = /^[0-9a-f]+$/i;
const domainLabel = /^[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?$/i;

export const indicatorTypeSchema = z.enum(["url", "ip", "domain", "hash"]);
export type IndicatorType = z.infer<typeof indicatorTypeSchema>;

export const indicatorSchema = z
  .string()
  .min(1, "Indicator is required")
  .max(2048, "Indicator is too long")
  .refine(
    (value) => [...value].every((char) => char.charCodeAt(0) > 32 && char.charCodeAt(0) !== 127),
    "Indicator contains whitespace",
  )
  .superRefine((value, context) => {
    if (hashPattern.test(value) && [32, 40, 64].includes(value.length)) return;
    if (value.includes("://")) {
      try {
        const url = new URL(value);
        if (!["http:", "https:"].includes(url.protocol)) {
          context.addIssue({ code: "custom", message: "Only HTTP and HTTPS URLs are supported" });
        }
        if (url.username || url.password) {
          context.addIssue({ code: "custom", message: "URL credentials are not allowed" });
        }
      } catch {
        context.addIssue({ code: "custom", message: "Invalid URL" });
      }
      return;
    }
    if (netIp(value)) return;
    const labels = value.replace(/\.$/, "").split(".");
    if (labels.length < 2 || labels.some((label) => !domainLabel.test(label))) {
      context.addIssue({ code: "custom", message: "Invalid domain or indicator" });
    }
  });

function netIp(value: string): boolean {
  const ipv4 = /^(?:\d{1,3}\.){3}\d{1,3}$/.test(value);
  const ipv6 = value.includes(":");
  return ipv4 || ipv6;
}

export const scanRequestSchema = z.object({
  indicator: indicatorSchema,
  type: indicatorTypeSchema.optional(),
});
