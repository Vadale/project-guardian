/**
 * Guardian gate for the `pi` coding agent (earendil-works/pi).
 *
 * The pi analogue of Guardian's Claude Code PreToolUse hook: it registers on the
 * `tool_call` event (fired *before* a tool runs — "Can block."), maps the pi tool
 * call to a Guardian structured action, asks the deterministic policy via
 * `guardian decide --policy <toml>`, and BLOCKS anything that is not `allow`.
 *
 * Fail-closed: any non-"allow" decision OR any error blocks the tool. The model's
 * prose never decides — only the intercepted structured action does (invariant #2).
 *
 * Load it with:  pi -e ./guardian-pi.ts ...
 * Env:
 *   GUARDIAN_BIN     path to the `guardian` binary (default: "guardian" on PATH)
 *   GUARDIAN_POLICY  policy .toml passed to `guardian decide --policy` (required;
 *                    `decide` ignores the env var, so we pass it as a flag)
 *   GUARDIAN_PI_LOG  append a tab-separated decision log here (optional)
 */
import { execFileSync } from "node:child_process";
import { appendFileSync } from "node:fs";

const BIN = process.env.GUARDIAN_BIN || "guardian";
const POLICY = process.env.GUARDIAN_POLICY;
const LOG = process.env.GUARDIAN_PI_LOG;

// Map a pi tool call to a Guardian action (tool + ActionKind + args/context).
function actionFor(ev: any) {
	const i = ev.input || {};
	switch (ev.toolName) {
		case "bash":
			return { tool: "bash", kind: "Exec", args: { cmd: String(i.command ?? "") }, context: {} };
		case "write":
			return { tool: "write", kind: "FileWrite", args: {}, context: { path: String(i.file_path ?? i.path ?? "") } };
		case "edit":
			return { tool: "edit", kind: "FileWrite", args: {}, context: { path: String(i.file_path ?? i.path ?? "") } };
		case "read":
			return { tool: "read", kind: "FileRead", args: {}, context: { path: String(i.file_path ?? i.path ?? "") } };
		case "ls":
		case "grep":
		case "find":
			return { tool: ev.toolName, kind: "FileRead", args: {}, context: {} };
		default:
			return { tool: String(ev.toolName), kind: "Other", args: i, context: {} };
	}
}

export default function (pi: any) {
	pi.on("tool_call", async (event: any) => {
		const action = actionFor(event);
		let decision = "deny";
		let reason = "";
		try {
			const argv = POLICY ? ["decide", "--policy", POLICY] : ["decide"];
			const out = execFileSync(BIN, argv, { input: JSON.stringify(action), encoding: "utf8" });
			const d = JSON.parse(out);
			decision = d.decision ?? "deny";
			reason = d.reason ?? "";
		} catch (e: any) {
			decision = "deny";
			reason = "Guardian unavailable (fail closed): " + (e?.message ?? String(e));
		}
		if (LOG) {
			const detail = action.args?.cmd || action.context?.path || "";
			try {
				appendFileSync(LOG, `${new Date().toISOString()}\t${event.toolName}\t${decision}\t${detail}\t${reason}\n`);
			} catch {
				/* logging is best-effort */
			}
		}
		if (decision !== "allow") {
			return { block: true, reason: `Guardian ${decision.toUpperCase()}: ${reason}` };
		}
		// allow -> return nothing -> tool proceeds
	});
}
