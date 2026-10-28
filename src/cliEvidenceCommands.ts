import { withCommandCancellation } from "./cli/commandCancellation.js";
import { safeParseJson } from "./domain/safeJson.js";
import { AnalysisInputError } from "./domain/analysisErrorCore.js";
import { analysisInputErrorFromIssues } from "./domain/inputIssueProjection.js";
import { bundleComparisonInputSchema } from "./domain/bundleComparison.js";
import { Cli, z } from "incur";

import {
  compareEvidenceBundlesCommand,
  exportEvidenceBundleCommand,
  importEvidenceBundleCommand,
  searchEvidenceBundleCommand,
} from "./application/EvidenceBundleCommands.js";
import { logCliCommand } from "./cliLogging.js";
import type { Logger } from "pino";
import { CLI_COMMANDS } from "./cliCommandNames.js";
import { parseCliJsonInput } from "./cliJsonInput.js";
import { evidenceSearchInputSchema } from "./domain/evidenceRecordSearch.js";
import { importEvidenceBundleInputSchema } from "./contracts/sessionToolSchemas.js";
import type { JsonValue } from "./domain/jsonValue.js";
import { projectAnalysisError } from "./domain/analysisErrorProjection.js";
import type { AnalysisError } from "./domain/analysisErrorBase.js";

/** Register caller-path Evidence commands. */
export const registerEvidenceCommands = (
  cli: ReturnType<typeof Cli.create>,
  logger: Logger,
): void => {
  cli.command(CLI_COMMANDS.evidenceImport, {
    description: "Validate and import a bounded local Evidence bundle",
    args: z.object({
      path: z.string().describe("Evidence bundle JSON path"),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "evidence-import", async () => {
          const imported = await importEvidenceBundleCommand(args.path, signal);
          return imported.ok ? imported.value : cliError(imported.error);
        }),
      ),
  });
  cli.command(CLI_COMMANDS.evidenceExport, {
    description: "Validate and atomically export canonical Evidence JSON",
    args: z.object({
      source: z.string().describe("Existing evidence bundle JSON path"),
      output: z.string().describe("Canonical output JSON path"),
    }),
    options: z.object({
      overwrite: z.boolean().default(false).describe("Replace output file"),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "evidence-export", async () => {
          const exported = await exportEvidenceBundleCommand(
            args.source,
            args.output,
            options.overwrite,
            signal,
          );
          return exported.ok ? exported.value : cliError(exported.error);
        }),
      ),
  });
  cli.command(CLI_COMMANDS.compare, {
    description: "Compare two canonical Evidence bundles",
    args: z.object({
      left: z.string().describe("Left Evidence bundle JSON path"),
      right: z.string().describe("Right Evidence bundle JSON path"),
    }),
    options: z.object({
      record_pairs: z
        .string()
        .optional()
        .describe(
          "JSON array of explicit left_evidence_id/right_evidence_id observation pairs",
        ),
    }),
    run: ({ args, options }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, "compare", async () => {
          const decoded =
            options.record_pairs === undefined
              ? { ok: true as const, value: [] }
              : safeParseJson(options.record_pairs);
          if (!decoded.ok)
            return cliError(
              new AnalysisInputError(
                "compare_bundles",
                { cause: decoded.cause },
                [
                  {
                    path: ["record_pairs"],
                    reason: "invalid_format",
                    expected: "JSON array",
                  },
                ],
              ),
            );
          const input = { record_pairs: decoded.value };
          const selected = bundleComparisonInputSchema
            .pick({ record_pairs: true })
            .safeParse(input);
          if (!selected.success)
            return cliError(
              analysisInputErrorFromIssues(
                "compare_bundles",
                selected.error.issues,
                input,
              ),
            );
          const compared = await compareEvidenceBundlesCommand({
            leftPath: args.left,
            rightPath: args.right,
            recordPairs: selected.data.record_pairs,
            signal,
          });
          return compared.ok ? compared.value : cliError(compared.error);
        }),
      ),
  });
  cli.command(CLI_COMMANDS.searchEvidence, {
    description:
      "Search a local Evidence bundle's retained records with a literal or regex pattern and optional exact scope filters",
    args: z.object({
      inputJson: z
        .string()
        .describe(
          "JSON or JSON file with absolute path, search pattern and optional filters, fields, offset and limit",
        ),
    }),
    run: ({ args }) =>
      withCommandCancellation((signal) =>
        logCliCommand(logger, CLI_COMMANDS.searchEvidence, async () => {
          const input = await parseCliJsonInput(
            args.inputJson,
            CLI_COMMANDS.searchEvidence,
            signal,
          );
          if (!input.ok) return input.error;
          const schema = evidenceSearchInputSchema.safeExtend({
            path: importEvidenceBundleInputSchema.shape.path,
          });
          const parsed = schema.safeParse(input.value);
          if (!parsed.success)
            return cliError(
              analysisInputErrorFromIssues(
                CLI_COMMANDS.searchEvidence,
                parsed.error.issues,
                input.value,
              ),
            );
          const result = await searchEvidenceBundleCommand(parsed.data, signal);
          return result.ok ? result.value : cliError(result.error);
        }),
      ),
  });
};

const cliError = (error: AnalysisError): JsonValue => ({
  error: "Analysis failed",
  ...projectAnalysisError(error),
});
