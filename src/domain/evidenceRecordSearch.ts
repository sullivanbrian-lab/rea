import { z } from "zod";

import { analysisSearchRegExp } from "./analysisSearch.js";
import { AnalysisInputError } from "./analysisErrorCore.js";
import { digestSchema } from "./digests.js";
import { evidenceSchema, type Evidence } from "./evidence.js";
import type { EvidenceBundle } from "./evidenceBundle.js";
import type { JsonValue } from "./jsonValue.js";
import {
  evidenceRecordFiltersSchema,
  matchesEvidenceRecordFilters,
} from "./evidenceRecordSummary.js";
import { err, ok, type Result } from "./result.js";

const countSchema = z.int().nonnegative();

/** Closed vocabulary of searchable record fields, in stable scan order. */
export const evidenceSearchFieldSchema = z.enum([
  "evidence_id",
  "subject.name",
  "subject.local_path",
  "subject.digest.sha256",
  "provider",
  "operation",
  "predicate_type",
  "parameters",
  "caller_input_path",
  "raw_result",
  "normalized_result",
  "confidence",
  "authority",
  "environment",
  "limitations",
  "relationship_coverage",
  "locations",
  "evidence_links",
]);
export type EvidenceSearchField = z.infer<typeof evidenceSearchFieldSchema>;
export const EVIDENCE_SEARCH_FIELDS = evidenceSearchFieldSchema.options;

/** Scoped full-text query over retained Evidence, bounded like list_unknowns. */
export const evidenceSearchInputSchema = z.strictObject({
  pattern: z
    .string()
    .min(1)
    .describe(
      "Literal text or regex pattern searched across retained Evidence text fields",
    ),
  mode: z.enum(["literal", "regex"]).default("literal"),
  case_sensitive: z
    .boolean()
    .default(false)
    .describe(
      "Whether to match case; case-insensitive literal matching uses Unicode simple case folding",
    ),
  filters: evidenceRecordFiltersSchema
    .optional()
    .describe(
      "Exact scope selection shared with the evidence-bundle summary: omit for every retained record",
    ),
  fields: z
    .array(evidenceSearchFieldSchema)
    .min(1)
    .optional()
    .describe(
      "Restrict the searched record fields, e.g. subject.name for a title-only search; omit for every searchable field",
    ),
  offset: z
    .int()
    .min(0)
    .max(Number.MAX_SAFE_INTEGER)
    .default(0)
    .describe("Zero-based offset in the stable matched-record order."),
  limit: z
    .int()
    .positive()
    .max(1000)
    .optional()
    .describe(
      "Optional maximum number of matched records to return. Omit to return every match from offset.",
    ),
});
export type EvidenceSearchQuery = z.infer<typeof evidenceSearchInputSchema>;

const evidenceSearchMatchSchema = z.strictObject({
  field: evidenceSearchFieldSchema,
  index: z.int().nonnegative().exactOptional(),
  match_count: countSchema,
  snippet: z.string(),
});

const evidenceSearchRecordSchema = z.strictObject({
  evidence_id: evidenceSchema.shape.evidence_id,
  subject: evidenceSchema.shape.subject,
  provider: evidenceSchema.shape.provider,
  operation: evidenceSchema.shape.operation,
  confidence: evidenceSchema.shape.confidence,
  authority: evidenceSchema.shape.authority,
  analysis_profile_digest: digestSchema.nullable(),
  matches: z.array(evidenceSearchMatchSchema),
});

export const evidenceSearchResultSchema = z.strictObject({
  kind: z.literal("evidence-search"),
  query: z.strictObject({
    pattern: z.string(),
    mode: z.enum(["literal", "regex"]),
    case_sensitive: z.boolean(),
  }),
  scope: z.record(z.string(), z.string()),
  searched_fields: z.array(evidenceSearchFieldSchema),
  total_retained_records: countSchema,
  records_searched: countSchema,
  matching_records: countSchema,
  total_matches: countSchema,
  unknown_revisions: countSchema,
  records: z.array(evidenceSearchRecordSchema),
  offset: countSchema,
  next_offset: countSchema.nullable(),
});
export type EvidenceSearchResult = z.infer<typeof evidenceSearchResultSchema>;

const SNIPPET_CONTEXT_CHARACTERS = 80;

interface FieldText {
  readonly field: EvidenceSearchField;
  readonly index?: number;
  readonly text: string;
}

/** Map each searchable record field to the text the index covers. */
const searchableFieldTexts = (evidence: Evidence): readonly FieldText[] => {
  const texts: FieldText[] = [];
  const push = (field: EvidenceSearchField, text: string) =>
    texts.push({ field, text });
  const pushJson = (field: EvidenceSearchField, value: JsonValue) =>
    texts.push({ field, text: JSON.stringify(value) });
  const { subject } = evidence;
  push("evidence_id", evidence.evidence_id);
  if (subject !== null) {
    push("subject.name", subject.name);
    push("subject.local_path", subject.local_path);
    push("subject.digest.sha256", subject.digest.sha256);
  }
  pushJson("provider", evidence.provider);
  push("operation", evidence.operation);
  push("predicate_type", evidence.predicate_type);
  pushJson("parameters", evidence.parameters);
  if (evidence.caller_input_path !== undefined)
    push("caller_input_path", evidence.caller_input_path);
  if (evidence.raw_result !== null) pushJson("raw_result", evidence.raw_result);
  pushJson("normalized_result", evidence.normalized_result);
  push("confidence", evidence.confidence);
  push("authority", evidence.authority);
  if (evidence.environment !== null)
    pushJson("environment", evidence.environment);
  evidence.limitations.forEach((limitation, index) =>
    texts.push({ field: "limitations", index, text: limitation }),
  );
  if (evidence.relationship_coverage !== null)
    pushJson("relationship_coverage", evidence.relationship_coverage);
  pushJson("locations", evidence.locations);
  evidence.evidence_links.forEach((link, index) =>
    texts.push({ field: "evidence_links", index, text: link }),
  );
  return texts;
};

const matchCount = (
  text: string,
  regexp: RegExp,
): { count: number; start: number; end: number } => {
  regexp.lastIndex = 0;
  let count = 0;
  let start = -1;
  let end = -1;
  for (;;) {
    const match = regexp.exec(text);
    if (match === null) break;
    if (start < 0) {
      start = match.index;
      end = match.index + match[0].length;
    }
    count++;
    if (match[0].length === 0) regexp.lastIndex++;
  }
  return { count, start, end };
};

const snippetFor = (text: string, start: number, end: number): string => {
  const from = Math.max(0, start - SNIPPET_CONTEXT_CHARACTERS);
  const to = Math.min(text.length, end + SNIPPET_CONTEXT_CHARACTERS);
  return `${from > 0 ? "…" : ""}${text.slice(from, to)}${
    to < text.length ? "…" : ""
  }`;
};

/**
 * Full-text search over retained Evidence with exact scope selection: hits are
 * grouped per record with their field location, occurrence count and a bounded
 * snippet, like a scoped notebook search over the retained ledger. Records are
 * returned in stable bundle order; filters narrow the searched corpus.
 */
export const searchEvidenceBundle = (
  bundle: EvidenceBundle,
  query: EvidenceSearchQuery,
): Result<EvidenceSearchResult, AnalysisInputError> => {
  let regexp: RegExp;
  try {
    regexp = analysisSearchRegExp(query);
  } catch (cause: unknown) {
    if (cause instanceof AnalysisInputError) return err(cause);
    throw cause;
  }
  const global = new RegExp(
    regexp.source,
    regexp.flags.includes("g") ? regexp.flags : `${regexp.flags}g`,
  );
  const selectedFilters: Record<string, string> = {};
  for (const [field, value] of Object.entries(query.filters ?? {}))
    if (value !== undefined) selectedFilters[field] = value;
  const fieldSet = new Set(query.fields ?? EVIDENCE_SEARCH_FIELDS);
  const searchedFields = EVIDENCE_SEARCH_FIELDS.filter((field) =>
    fieldSet.has(field),
  );
  const filters = query.filters ?? {};
  const matched: EvidenceSearchResult["records"] = [];
  let recordsSearched = 0;
  let totalMatches = 0;
  for (const evidence of bundle.records) {
    if (!matchesEvidenceRecordFilters(evidence, filters)) continue;
    recordsSearched++;
    const matches: z.infer<typeof evidenceSearchMatchSchema>[] = [];
    for (const { field, index, text } of searchableFieldTexts(evidence)) {
      if (!fieldSet.has(field)) continue;
      const match = matchCount(text, global);
      if (match.count === 0) continue;
      matches.push({
        field,
        ...(index === undefined ? {} : { index }),
        match_count: match.count,
        snippet: snippetFor(text, match.start, match.end),
      });
      totalMatches += match.count;
    }
    if (matches.length === 0) continue;
    matched.push({
      evidence_id: evidence.evidence_id,
      subject: evidence.subject,
      provider: evidence.provider,
      operation: evidence.operation,
      confidence: evidence.confidence,
      authority: evidence.authority,
      analysis_profile_digest: evidence.analysis_profile?.digest ?? null,
      matches,
    });
  }
  const start = Math.min(query.offset, matched.length);
  const end =
    query.limit === undefined
      ? matched.length
      : Math.min(matched.length, start + query.limit);
  return ok({
    kind: "evidence-search",
    query: {
      pattern: query.pattern,
      mode: query.mode,
      case_sensitive: query.case_sensitive,
    },
    scope: selectedFilters,
    searched_fields: searchedFields,
    total_retained_records: bundle.records.length,
    records_searched: recordsSearched,
    matching_records: matched.length,
    total_matches: totalMatches,
    unknown_revisions: bundle.unknowns.length,
    records: matched.slice(start, end),
    offset: start,
    next_offset: end < matched.length ? end : null,
  });
};
