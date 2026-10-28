import { expect, it } from "vitest";

import { createEvidence } from "./evidence.js";
import { createEvidenceBundle } from "./evidenceBundle.js";
import {
  EVIDENCE_SEARCH_FIELDS,
  evidenceSearchInputSchema,
  searchEvidenceBundle,
} from "./evidenceRecordSearch.js";

const record = (
  operation: string,
  result: unknown,
  extra?: {
    readonly path?: string;
    readonly sha256?: string;
    readonly limitations?: readonly string[];
    readonly parameters?: Record<string, unknown>;
  },
) =>
  createEvidence(
    {
      path: extra?.path ?? "/fixtures/native.exe",
      format: "pe",
      sha256: extra?.sha256 ?? "a".repeat(64),
    },
    { id: "provider", name: "Provider", version: "1" },
    {
      operation,
      parameters: extra?.parameters ?? {},
      result,
      ...(extra?.limitations === undefined
        ? {}
        : { limitations: extra.limitations }),
    },
  );

const baseInput = () => evidenceSearchInputSchema.parse({ pattern: "license" });

it("groups hits per record with field locations, counts and snippets", () => {
  const target = record("analyze_function", {
    notice: "license check failed for this module",
    deeper: ["license", "license"],
  });
  const other = record("list_procedures", { items: ["unrelated"] });
  const result = searchEvidenceBundle(
    createEvidenceBundle([target, other]),
    baseInput(),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const value = result.value;
  expect(value.kind).toBe("evidence-search");
  expect(value.total_retained_records).toBe(2);
  expect(value.records_searched).toBe(2);
  expect(value.matching_records).toBe(1);
  expect(value.total_matches).toBe(3);
  expect(value.records).toHaveLength(1);
  const hit = value.records[0]!;
  expect(hit.evidence_id).toBe(target.evidence_id);
  expect(hit.operation).toBe("analyze_function");
  expect(hit.matches).toEqual([
    expect.objectContaining({
      field: "normalized_result",
      match_count: 3,
    }),
  ]);
  expect(hit.matches[0]!.snippet).toContain("license check failed");
});

it("narrows the corpus through exact scope filters", () => {
  const matching = record("analyze_function", { note: "license" });
  const wrongOperation = record("list_procedures", { note: "license" });
  const wrongTarget = record(
    "analyze_function",
    { note: "license" },
    { sha256: "b".repeat(64) },
  );
  const bundle = createEvidenceBundle([matching, wrongOperation, wrongTarget]);
  const scoped = searchEvidenceBundle(
    bundle,
    evidenceSearchInputSchema.parse({
      pattern: "license",
      filters: { operation: "analyze_function", target_sha256: "a".repeat(64) },
    }),
  );
  expect(scoped.ok).toBe(true);
  if (!scoped.ok) return;
  expect(scoped.value.records_searched).toBe(1);
  expect(scoped.value.records.map((r) => r.evidence_id)).toEqual([
    matching.evidence_id,
  ]);
  expect(scoped.value.scope).toEqual({
    operation: "analyze_function",
    target_sha256: "a".repeat(64),
  });
});

it("restricts searched fields like a title-only search", () => {
  const titleHit = record(
    "analyze_function",
    { note: "nothing" },
    { path: "/fixtures/license-server.exe" },
  );
  const bodyOnlyHit = record("analyze_function", { note: "license" });
  const result = searchEvidenceBundle(
    createEvidenceBundle([titleHit, bodyOnlyHit]),
    evidenceSearchInputSchema.parse({
      pattern: "license",
      fields: ["subject.name"],
    }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.searched_fields).toEqual(["subject.name"]);
  expect(result.value.records.map((r) => r.evidence_id)).toEqual([
    titleHit.evidence_id,
  ]);
  expect(result.value.records[0]!.matches).toEqual([
    expect.objectContaining({ field: "subject.name", match_count: 1 }),
  ]);
});

it("searches every field by default including limitations and links", () => {
  const target = record(
    "analyze_function",
    { note: "no hits" },
    { limitations: ["license server unreachable"] },
  );
  const linked = createEvidence(
    undefined,
    { id: "p", name: "P", version: null },
    {
      operation: "get_evidence_bundle",
      parameters: {},
      result: { notice: "license" },
      evidenceLinks: [target.evidence_id],
    },
  );
  const result = searchEvidenceBundle(
    createEvidenceBundle([target, linked]),
    evidenceSearchInputSchema.parse({ pattern: target.evidence_id }),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  expect(result.value.searched_fields).toEqual([...EVIDENCE_SEARCH_FIELDS]);
  const linkedHit = result.value.records.find(
    (r) => r.evidence_id === linked.evidence_id,
  );
  expect(linkedHit?.matches).toEqual([
    expect.objectContaining({ field: "evidence_links", index: 0 }),
  ]);
});

it("rejects an invalid regex as a caller input error", () => {
  const result = searchEvidenceBundle(
    createEvidenceBundle([record("analyze_function", { note: "license" })]),
    evidenceSearchInputSchema.parse({ pattern: "([", mode: "regex" }),
  );
  expect(result.ok).toBe(false);
});

it("matches regex patterns and preserves case sensitivity", () => {
  const target = record("analyze_function", { notice: "LICENSE checksum" });
  const bundle = createEvidenceBundle([target]);
  const regex = searchEvidenceBundle(
    bundle,
    evidenceSearchInputSchema.parse({
      pattern: "li[cs]en[cs]e",
      mode: "regex",
    }),
  );
  expect(regex.ok).toBe(true);
  if (!regex.ok) return;
  expect(regex.value.matching_records).toBe(1);
  const sensitive = searchEvidenceBundle(
    bundle,
    evidenceSearchInputSchema.parse({
      pattern: "license",
      case_sensitive: true,
    }),
  );
  expect(sensitive.ok).toBe(true);
  if (!sensitive.ok) return;
  expect(sensitive.value.matching_records).toBe(0);
});

it("pages matched records in stable bundle order", () => {
  const records = [0, 1, 2, 3].map((i) =>
    record("analyze_function", { note: `license hit ${i}` }),
  );
  const bundle = createEvidenceBundle(records);
  const bundledOrder = bundle.records.map((r) => r.evidence_id);
  const first = searchEvidenceBundle(
    bundle,
    evidenceSearchInputSchema.parse({ pattern: "license", limit: 2 }),
  );
  expect(first.ok).toBe(true);
  if (!first.ok) return;
  expect(first.value.records.map((r) => r.evidence_id)).toEqual(
    bundledOrder.slice(0, 2),
  );
  expect(first.value.next_offset).toBe(2);
  const second = searchEvidenceBundle(
    bundle,
    evidenceSearchInputSchema.parse({
      pattern: "license",
      offset: 2,
      limit: 2,
    }),
  );
  expect(second.ok).toBe(true);
  if (!second.ok) return;
  expect(second.value.records.map((r) => r.evidence_id)).toEqual(
    bundledOrder.slice(2),
  );
  expect(second.value.next_offset).toBeNull();
  expect(second.value.matching_records).toBe(4);
});

it("keeps snippet bounded around the first hit", () => {
  const target = record("analyze_function", {
    blob: `${"x".repeat(300)}license${"y".repeat(300)}`,
  });
  const result = searchEvidenceBundle(
    createEvidenceBundle([target]),
    baseInput(),
  );
  expect(result.ok).toBe(true);
  if (!result.ok) return;
  const snippet = result.value.records[0]!.matches[0]!.snippet;
  expect(snippet.startsWith("…")).toBe(true);
  expect(snippet.endsWith("…")).toBe(true);
  expect(snippet.length).toBeLessThan(200);
  expect(snippet).toContain("license");
});
